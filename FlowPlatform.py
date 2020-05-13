import os, random, sqlalchemy, datetime, requests, json, jwt, qrcode, image, contextlib, urllib
from flask import Flask, request, abort, redirect, Response, make_response, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from linebot import (LineBotApi, WebhookHandler)
from linebot.exceptions import (InvalidSignatureError)
from linebot.models import *
from google.cloud import storage
from urllib.parse import urlencode
from urllib.request import urlopen
#
app = Flask(__name__)
app.config['SECRET_KEY'] = '12345'
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "local_gmi.json"
# DB information
# db_user = os.environ.get('CLOUD_SQL_USERNAME')
# db_password = os.environ.get('CLOUD_SQL_PASSWORD')
# db_name = os.environ.get('CLOUD_SQL_DATABASE_NAME')
# db_connection_name = os.environ.get('CLOUD_SQL_CONNECTION_NAME')

# engine_url = 'mysql+pymysql://{}:{}@/{}?unix_socket=/cloudsql/{}'.format(db_user, db_password, db_name, db_connection_name)
engine_url = sqlalchemy.engine.url.URL(
    drivername='mysql+pymysql',
    username='root',
    password='fatsheepgod',
    host='34.80.112.57',
    # host='localhost',
    port=3306,
    database='test'
)
engine = sqlalchemy.create_engine(engine_url, pool_size=0)

# -- function definition --
def page_list(data, page, limit):
    '''
    output the list contains in certain page
    '''
    index_start = limit*(page-1)
    index_max = len(data)

    if index_max - index_start  >= limit:
        index_end = index_start + limit
    else :
        index_end = index_max + 1

    return data[index_start : index_end]

def number():
    '''
    create a number that is no unique in the database
    '''
    with engine.connect() as cnx:
        cnx.execute("INSERT INTO dummy () VALUES ();")
        cursor = cnx.execute("SELECT num FROM dummy ORDER BY num DESC LIMIT 1;")
        num = str(cursor.fetchall()[0][0])
    engine.dispose()
    return num

def token_required(func):
    '''
    A decorator that would check if token is exist or valid
    '''
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token:
            return jsonify({'message' : 'Token is missing!'}), headers

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            custom_id = data['custom_id']
        except:                 
            return jsonify({'message' : 'Token is invalid'}), headers

        return func(custom_id, *args, **kwargs)
    return decorated

def upload_blob(bucket_name, source_file_name, destination_blob_name):
    """Uploads a file to the bucket."""
    # bucket_name = "your-bucket-name"
    # source_file_name = "local/path/to/file"
    # destination_blob_name = "storage-object-name"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    print(
        "File {} uploaded to {}.".format(
            source_file_name, destination_blob_name
        )
    )

def make_blob_public(bucket_name, blob_name):
    """Makes a blob publicly accessible."""
    # bucket_name = "your-bucket-name"
    # blob_name = "your-object-name"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    blob.make_public()

    print(
        "Blob {} is publicly accessible at {}".format(
            blob.name, blob.public_url
        )
    )

def make_short(url):
    url_req = ("http://tinyurl.com/api-create.php?" + urlencode({"url":url}))
    with contextlib.closing(urlopen(url_req)) as response:
        return response.read().decode("utf-8")

# -- variable definition --
headers = {
    'Access-Control-Allow-Origin' : '*',
    'Access-Control-Allow-Headers' : ['Content-Type', 'x-access-token'],
    'Access-Control-Allow-Methods' : '*'
}
#-----------------------------------------#
# Label Feature
#-----------------------------------------#
#-----------------------------------------#
# create new label
#-----------------------------------------#
@app.route("/label_create", methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def label_create(custom_id): 
    if request.method == 'POST':
        data = request.json
        
        with engine.connect() as cnx:
            num = number()
            # 修改標籤名稱
            if data['create_label_period'] == '0':
                name = data['create_label_name'] + '(永久)'
            else:
                name = data['create_label_name'] + '({}天)'.format(data['create_label_period'])
            # 正式修改資料庫
            cnx.execute('INSERT INTO tag_list (label_id, label_name, label_period, label_radio, custom_id) VALUES \
                (\'label_{}\', \'{}\', {}, \'{}\', \'{}\');'.format(num, name, data['create_label_period'], data['create_label_radio'], custom_id))
        
        # 計算標籤人數
        with engine.connect() as cnx:
            query = cnx.execute("select a.label_id, a.label_name, a.label_period, a.label_radio, b.count from tag_list a left join (select label_id, count(*) as count from label_record where custom_id = \'{}\' group by label_id) as b on b.label_id = a.label_id where a.custom_id = \'{}\';".format(custom_id, custom_id)).fetchall()
        
        # 轉換成可代入jsonify的字典
        result = [{"label_id" : x[0], "label_name" : x[1], "label_period": x[2], "label_radio":x[3], "label_people_number":x[4]} for x in query]
        for x in result:
            if x["label_people_number"] == None:
                x["label_people_number"] = 0
            else:
                continue
        
        # filter 
        if data['type'] == 'all':
            pass
        elif data['type'] == 'forever':
            tmp = list()
            for x in result:
                if x['label_radio'] == '永久':
                    tmp.append(x)
            result = tmp
        elif data['type'] == 'temp':
            tmp = list()
            for x in result:
                if x['label_radio'] == '有效天數':
                    tmp.append(x)
            result = tmp
        # shows the data contains in certain page
        filter_result = page_list(result, int(data['page']), int(data['limit']))

        body = {
            "tag_data" : filter_result,
            "total_tag_number" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Label Delete
#-----------------------------------------#
@app.route("/label_delete", methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def label_delete(custom_id):
    if request.method == 'POST':
        data = request.json
        label_id = data['delete_label_id']
        with engine.connect() as cnx:
            cnx.execute("SET SQL_SAFE_UPDATES = 0;")
            # tag_redirect
            cursor = cnx.execute("select action_id, label_list from tag_redirect where label_list like '[%%{}%%]' and custom_id = \'{}\';".format(data['delete_label_id'], custom_id))
            query = cursor.fetchall()
            if query != []:
                dict_value = [json.loads(x[1]) for x in query]
                dict_key = [x[0] for x in query]
                # delete "the" label_id from dict_value
                tmp = [y.remove(data['delete_label_id']) for y in dict_value]
                
                for action_id, label_list in zip(dict_key, dict_value):
                    cnx.execute("UPDATE tag_redirect SET label_list = \'{}\' WHERE action_id = \'{}\' and custom_id = \'{}\';".format(str(label_list).replace("\'",'\"'), action_id, custom_id))
            # tag_postback
            cursor = cnx.execute("select postback_id, label_list from tag_postback where label_list like '[%%{}%%]' and custom_id = \'{}\';".format(data['delete_label_id'], custom_id))
            query = cursor.fetchall()
            if query != []:
                dict_value = [json.loads(x[1]) for x in query]
                dict_key = [x[0] for x in query]
                tmp = [y.remove(data['delete_label_id']) for y in dict_value]
                
                for postback_id, label_list in zip(dict_key, dict_value):
                    cnx.execute("UPDATE tag_postback SET label_list = \'{}\' WHERE postback_id = \'{}\' and custom_id = \'{}\';".format(str(label_list).replace("\'",'\"'), postback_id, custom_id))
            # auto_reply
            cursor = cnx.execute("select reply_id, label_list from auto_reply where label_list like '[%%{}%%]' and custom_id = \'{}\';".format(data['delete_label_id'], custom_id))
            query = cursor.fetchall()
            if query != []:
                dict_value = [json.loads(x[1]) for x in query]
                dict_key = [x[0] for x in query]
                tmp = [y.remove(data['delete_label_id']) for y in dict_value]
                
                for reply_id, label_list in zip(dict_key, dict_value):
                    cnx.execute("UPDATE auto_reply SET label_list = \'{}\' WHERE reply_id = \'{}\' and custom_id = \'{}\';".format(str(label_list).replace("\'",'\"'), reply_id, custom_id))
            
            #
            cnx.execute("DELETE FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\'".format(label_id, custom_id))
            cnx.execute("DELETE FROM tag_list WHERE label_id = \'{}\' and custom_id = \'{}\'".format(label_id, custom_id))

        # 計算標籤人數
        with engine.connect() as cnx:
            query = cnx.execute("select a.label_id, a.label_name, a.label_period, a.label_radio, b.count from tag_list a left join (select label_id, count(*) as count from label_record where custom_id = \'{}\' group by label_id) as b on b.label_id = a.label_id where a.custom_id = \'{}\';".format(custom_id, custom_id)).fetchall()
        
        # 轉換成可代入jsonify的字典
        result = [{"label_id" : x[0], "label_name" : x[1], "label_period": x[2], "label_radio":x[3], "label_people_number":x[4]} for x in query]
        for x in result:
            if x["label_people_number"] == None:
                x["label_people_number"] = 0
            else:
                continue
        
        # filter 
        if data['type'] == 'all':
            pass
        elif data['type'] == 'forever':
            tmp = list()
            for x in result:
                if x['label_radio'] == '永久':
                    tmp.append(x)
            result = tmp
        elif data['type'] == 'temp':
            tmp = list()
            for x in result:
                if x['label_radio'] == '有效天數':
                    tmp.append(x)
            result = tmp
        # shows the data contains in certain page
        filter_result = page_list(result, int(data['page']), int(data['limit']))

        body = {
            "tag_data" : filter_result,
            "total_tag_number" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Label Display
#-----------------------------------------#
@app.route("/label_display", methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def label_display(custom_id):
    if request.method == 'POST':
        data = request.json
        # 修改標籤
        if data['fixed_label_id'] != '':
            label_id = data['fixed_label_id']
            label_name = data['fixed_label_name'].split('(')[0]
            label_period = data['fixed_label_period']
            label_radio = data['fixed_label_radio']
            
            if data['fixed_label_period'] == '0':
                label_name = label_name + '(永久)'
            else:
                label_name = label_name + '({}天)'.format(label_period)
            
            with engine.connect() as cnx:
                cnx.execute("SET SQL_SAFE_UPDATES = 0;")
                cnx.execute("UPDATE tag_list SET label_name = \'{}\', label_period = \'{}\', label_radio = \'{}\' WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label_name, label_period, label_radio, label_id, custom_id))
            
        # 計算標籤人數
        with engine.connect() as cnx:
            query = cnx.execute("select a.label_id, a.label_name, a.label_period, a.label_radio, b.count from tag_list a left join (select label_id, count(*) as count from label_record where custom_id = \'{}\' group by label_id) as b on b.label_id = a.label_id where a.custom_id = \'{}\';".format(custom_id, custom_id)).fetchall()
        
        # 轉換成可代入jsonify的字典
        result = [{"label_id" : x[0], "label_name" : x[1], "label_period": x[2], "label_radio":x[3], "label_people_number":x[4]} for x in query]
        for x in result:
            if x["label_people_number"] == None:
                x["label_people_number"] = 0
            else:
                continue
        
        # filter 
        if data['type'] == 'all':
            pass
        elif data['type'] == 'forever':
            tmp = list()
            for x in result:
                if x['label_radio'] == '永久':
                    tmp.append(x)
            result = tmp
        elif data['type'] == 'temp':
            tmp = list()
            for x in result:
                if x['label_radio'] == '有效天數':
                    tmp.append(x)
            result = tmp

        # filter (keyword)
        if data['search_input'] != "":
            tmp = list()
            for x in result:
                keyword = data['search_input']
                if keyword in x['label_name']:
                    tmp.append(x)
            result = tmp
        
        # filter (number)
        if data['filter_number'] != "":
            if data['filter_type'] == "bigger":
                tmp = list()
                for x in result:
                    if int(x['label_people_number']) >= int(data['filter_number']):
                        tmp.append(x)
            else:
                tmp = list()
                for x in result:
                    if int(x['label_people_number']) <= int(data['filter_number']):
                        tmp.append(x)
            result = tmp

        # shows the data contains in certain page
        filter_result = page_list(result, int(data['page']), int(data['limit']))

        body = {
            "tag_data" : filter_result,
            "total_tag_number" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Message Feature
#-----------------------------------------#
#-----------------------------------------#
# create message
#-----------------------------------------#
# iEAT old version url_redirect
@app.route('/url_redirect/url_id=<url_id>', methods=['GET', 'POST', 'OPTIONS'])
def redirecting(url_id):
    with engine.connect() as cnx:
        url = cnx.execute("SELECT url from url_redirect where url_id = \'{}\' and custom_id = 'cust_ieat';".format(url_id)).fetchall()[0][0]
    return redirect(url)
# new version for flow platform api - url_redirect
@app.route('/reloading/url_id=<url_id>&custom_id=<custom_id>', methods=['GET', 'POST', 'OPTIONS'])
def reloading(custom_id, url_id):
    with engine.connect() as cnx:
        url = cnx.execute("SELECT url from url_redirect where url_id = \'{}\' and custom_id = \'{}\';".format(url_id, custom_id)).fetchall()[0][0]
    return redirect(url)

@app.route('/create_msg', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def create_msg(custom_id):
    if request.method == 'POST':
        with engine.connect() as cnx:
            Client_ID, url_redirect, url_api = cnx.execute("select login_id, url_redirect, url_api from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0]
    
        data = request.json
        msg_id = "msg_{}".format(number())
        action_list = list()
        postback_list = list()
        #
        for msg in data['message']:
            # text can not be labelized
            if msg['type'] == 'text':
                if len(msg['urlList']) != 0:
                    list_url = msg['urlList'][1:len(msg['urlList'])]
                    list_tag = msg['tagList'][1:len(msg['tagList'])]
                    list_NewUrl = list()
                    
                    for url, label_list, num in zip(list_url, list_tag, range(1, len(msg['urlList']))):
                        label_list = str(label_list).replace("\'",'\"')
                        action_id = 'action_{}'.format(number())
                        url_id = 'url_{}'.format(number())
                        # 將此Action應執行的動作存入Action Table
                        with engine.connect() as cnx:
                            cnx.execute("INSERT INTO tag_redirect (action_id, label_list, url, msg_id, custom_id) VALUES (\"{}\", \'{}\', \"{}\", \"{}\", \"{}\");".format(action_id, label_list, url, msg_id, custom_id))
                            new_url = "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid%%20profile&nonce=09876xyz".format(Client_ID, url_redirect, action_id)
                            cnx.execute("INSERT INTO url_redirect (url_id, url, msg_id, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\');".format(url_id, new_url, msg_id, custom_id))
                        short_url = make_short("{}/reloading/url_id={}&custom_id={}".format(url_api, url_id, custom_id))
                        list_NewUrl.append(short_url)
                        msg['text'] = msg['text'].replace("__url__{}__url__".format(str(num)), ' ' + short_url + ' ')
                        action_list.append(action_id)
                    del msg['urlList']
                    del msg['tagList']
                else:
                    pass
            # image can not be labelized
            elif msg['type'] == 'image':
                pass
            elif msg['type'] == 'imagemap':
                for action in msg["actions"]:
                    label_list = str(action['label_id']).replace("\'",'\"')
                    if action['type'] == 'uri':
                        action_id = 'action_{}'.format(number())
                        # 將此Action應執行的動作存入Action Table
                        with engine.connect() as cnx:
                            cnx.execute("INSERT INTO tag_redirect (action_id, label_list, url, msg_id, custom_id) VALUES (\"{}\", \'{}\', \"{}\", \'{}\', \'{}\');".format(action_id, label_list, action['linkUri'], msg_id, custom_id))
                        action['linkUri'] = "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid%%20profile&nonce=09876xyz".format(Client_ID, url_redirect, action_id)
                        action_list.append(action_id)
                    # 拿掉不應存在 Msg 結構中的變數                    
                    del action['label_id']    
            elif msg['type'] == 'flex':
                # 一般的flex msg
                if msg['contents']['type'] == 'bubble':
                    for button in msg['contents']['footer']['contents']:
                        label_list = str(button['action']['label_id']).replace("\'",'\"')
                        if button['action']['type'] == 'uri':
                            action_id = 'action_{}'.format(number())
                            with engine.connect() as cnx:
                                cnx.execute("INSERT INTO tag_redirect (action_id, label_list, url, msg_id, custom_id) VALUES (\"{}\", \'{}\', \"{}\", \'{}\', \'{}\');".format(action_id, label_list, button['action']['uri'], msg_id, custom_id))
                            button['action']['uri'] = "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid%%20profile&nonce=09876xyz".format(Client_ID, url_redirect, action_id)
                            action_list.append(action_id)
                        elif button['action']['type'] == 'postback':
                            postback_id = 'postback_{}'.format(number())
                            with engine.connect() as cnx:
                                cnx.execute("INSERT INTO tag_postback (postback_id, label_list, msg_id, custom_id) VALUES (\"{}\", \'{}\', \'{}\', \'{}\');".format(postback_id, label_list, msg_id, custom_id))
                            postback_list.append(postback_id)
                            button['action']['data'] = postback_id
                        del button['action']['label_id']
                # 輪播flex msg
                elif msg['contents']['type'] == 'carousel':
                    for bubble in msg['contents']['contents']:
                        for button in bubble['footer']['contents']:
                            label_list = str(button['action']['label_id']).replace("\'",'\"')
                            if button['action']['type'] == 'uri':
                                action_id = 'action_{}'.format(number())
                                with engine.connect() as cnx:
                                    cnx.execute("INSERT INTO tag_redirect (action_id, label_list, url, msg_id, custom_id) VALUES (\"{}\", \'{}\', \"{}\", \'{}\', \'{}\');".format(action_id, label_list, button['action']['uri'], msg_id, custom_id))
                                button['action']['uri'] = "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid%%20profile&nonce=09876xyz".format(Client_ID, url_redirect, action_id)
                                action_list.append(action_id)
                            elif button['action']['type'] == 'postback':
                                postback_id = 'postback_{}'.format(number())
                                with engine.connect() as cnx:
                                    cnx.execute("INSERT INTO tag_postback (postback_id, label_list, msg_id, custom_id) VALUES (\"{}\", \'{}\', \'{}\', \'{}\');".format(postback_id, label_list, msg_id, custom_id))
                                postback_list.append(postback_id)
                                button['action']['data'] = postback_id
                            del button['action']['label_id']
        #
        json_msg = str(data['message']).replace("\'",'\"')
        postback_list = str(postback_list).replace("\'",'\"')
        action_list = str(action_list).replace("\'",'\"')
        if 'True' in json_msg:
            json_msg = json_msg.replace('True', 'true')
        with engine.connect() as cnx:
            cnx.execute('INSERT INTO msg_list (msg_id, msg_name, content, action_list, postback_list, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\');'.format(msg_id, data['name'], json_msg, action_list, postback_list, custom_id))
        return 'status code <200>', headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# create backend message
#-----------------------------------------#
@app.route('/create_backend_msg', methods=['GET', 'POST', 'OPTIONS'])
def create_backend_msg():
    if request.method == 'POST':
        data = request.json
        msg_id = "msg_{}".format(number())
        #
        json_msg = str(data['message']).replace("\'",'\"')
        if 'True' in json_msg:
            json_msg = json_msg.replace('True', 'true')
        with engine.connect() as cnx:
            cnx.execute('INSERT INTO backend_message (msg_id, msg_name, content, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\');'.format(msg_id, data['name'], json_msg, data['custom_id']))
        return jsonify({"message" : "upload completed!"}), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Query Messsage List
#-----------------------------------------#
@app.route('/query_msg', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def query_msg(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            # 訊息內容
            cursor = cnx.execute("SELECT msg_id, msg_name, event_time, content FROM msg_list where custom_id = \'{}\' order by event_time desc;".format(custom_id))
            query = cursor.fetchall()
            result = [{"msg_id" : x[0], "name" : x[1], "event_time" : str(x[2]), "content" : json.loads(x[3])} for x in query]        
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total": len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Query Messsage History
#-----------------------------------------#
@app.route('/query_msg_history', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def query_msg_history(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            # push history
            cursor_history = cnx.execute("SELECT serial_no, msg_name, event_time, object, D_union, req_id FROM push_history where custom_id = \'{}\' order by event_time desc;".format(custom_id))
            query_history = cursor_history.fetchall()
            data_history = [{"serial_no" : x[0], "name" : x[1], "event_time" : str(x[2]), "object" : json.loads(x[3]), "union" : x[4], "req_id":x[5]} for x in query_history]
        
        body = {
            "history" : page_list(data_history, data['page'], data['limit']),
            "total": len(data_history)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# advanced push History
#-----------------------------------------#
@app.route('/advanced_history', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def advanced_history(custom_id):
    if request.method == 'POST':
        with engine.connect() as cnx:
            Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
        
        get_headers = {
            "Authorization" : "Bearer {}".format(Channel_Access_Token)
        }
        
        data = request.json
        req_id = data['req_id']
        url = 'https://api.line.me/v2/bot/insight/message/event?requestId=' + req_id
        req_info = requests.get(url, headers = get_headers)
        req_json = json.loads(req_info.text)

        if req_json['overview']['uniqueClick'] == None:
            uniqueClick = 0
        else:
            uniqueClick = req_json['overview']['uniqueClick']

        if req_json['overview']["delivered"] == None:
            delivered = 0
        else:
            delivered = req_json['overview']['delivered']

        if req_json['overview']["uniqueImpression"] == None:
            uniqueImpression = 0
        else:
            uniqueImpression = req_json['overview']['uniqueImpression']

        with engine.connect() as cnx:
            num_aud = cnx.execute("select num_aud from push_history where req_id = \'{}\' and custom_id = \'{}\';".format(req_id, custom_id)).fetchall()[0][0]

        num_sent = delivered/num_aud
        num_click = uniqueClick/num_aud
        num_imp = uniqueImpression/num_aud

        if num_sent == 1:
            num_sent = "100.00"
        else:
            num_sent = str(round(num_sent, 4)*100)

        if num_click == 1:
            num_click = "100.00"
        else:
            num_click = str(round(num_click, 4)*100)

        if num_imp == 1:
            num_imp = "100.00"
        else:
            num_imp = str(round(num_imp, 4)*100)

        body = {
            "click" : uniqueClick,
            "impression" : uniqueImpression,
            "total_target" : num_aud,
            "delivered" : delivered,
            "failed" : num_aud - delivered,
            "rate_delivered" : num_sent,
            "rate_click" : num_click,
            "rate_impression" : num_imp
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Push Message(NEW)
#-----------------------------------------#
@app.route('/push_msg', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def push_msg(custom_id):
    if request.method == 'POST':
        data = request.json        
        # Total User_ID
        with engine.connect() as cnx:
            userList = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(custom_id)).fetchall()} 

        # gender
        in_gender = data['include']['gender']
        ex_gender = data['exclude']['gender']

        list_InGender = list()
        for gender in in_gender:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender = \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                list_InGender.append(tmp)
        
        list_ExGender = list()
        for gender in ex_gender:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender != \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                list_ExGender.append(tmp)

        # label_id
        in_label = data['include']['label_id']
        ex_label = data['exclude']['label_id']

        list_InLabel = list()
        for label in in_label:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                list_InLabel.append(tmp)
        
        list_ExLabel = list()
        for label in ex_label:
            with engine.connect() as cnx:
                tmp = userList - {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                list_ExLabel.append(tmp)

        list_Total = list_InGender + list_ExGender + list_InLabel + list_ExLabel
        #
        if in_gender + ex_gender + in_label + ex_label == []:
            userid_all = userList
        else:
            if list_Total != []:
                userid_all = list_Total[0]
                for query in list_Total:
                    if data['union'] == 'false':
                        userid_all = userid_all & query
                    else:
                        userid_all = userid_all | query
            else:
                userid_all = set()
        
        userid_all = list(userid_all)
        if userid_all != []:
            # push message to target user_id
            with engine.connect() as cnx:
                query = cnx.execute('select content, msg_name from msg_list where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id)).fetchall()[0]
                Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
    
            req_body = {
                "to": userid_all,
                "messages" : json.loads(query[0]),
            }
            
            push_headers = {
                "Content-Type" : "application/json",
                "Authorization" : "Bearer {}".format(Channel_Access_Token)
            }

            url = "https://api.line.me/v2/bot/message/multicast"
            requests.post(url, headers = push_headers, data = json.dumps(req_body))
    
            return jsonify({"message": "messages sent!"}), headers
        else:
            return jsonify({'message': "There is no user satisfied the conditions!"}), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Push Message(calculate people number)
#-----------------------------------------#
@app.route('/people_number', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def people_number(custom_id):
    if request.method == 'POST':
        data = request.json        
        # Total User_ID
        with engine.connect() as cnx:
            userList = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(custom_id)).fetchall()} 

        # gender
        in_gender = data['include']['gender']
        ex_gender = data['exclude']['gender']

        list_InGender = list()
        for gender in in_gender:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender = \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                list_InGender.append(tmp)
        
        list_ExGender = list()
        for gender in ex_gender:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender != \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                list_ExGender.append(tmp)

        # label_id
        in_label = data['include']['label_id']
        ex_label = data['exclude']['label_id']

        list_InLabel = list()
        for label in in_label:
            with engine.connect() as cnx:
                tmp = {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                list_InLabel.append(tmp)
        
        list_ExLabel = list()
        for label in ex_label:
            with engine.connect() as cnx:
                tmp = userList - {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                list_ExLabel.append(tmp)

        list_Total = list_InGender + list_ExGender + list_InLabel + list_ExLabel
        #
        if in_gender + ex_gender + in_label + ex_label == []:
            userid_all = userList
        else:
            if list_Total != []:
                userid_all = list_Total[0]
                for query in list_Total:
                    if data['union'] == 'false':
                        userid_all = userid_all & query
                    else:
                        userid_all = userid_all | query
            else:
                userid_all = set()
        return jsonify({"total":len(userList), "target":len(userid_all)}), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Push Message tag_list
#-----------------------------------------#
@app.route('/push_msg_tag', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def push_msg_tag(custom_id):
    if request.method == 'POST':
        with engine.connect() as cnx:
            cursor = cnx.execute("select label_id, label_name from tag_list where custom_id = \'{}\';".format(custom_id))
            query = cursor.fetchall()

        body = {
            "data" : [{"label_id" : x[0], "label_name" : x[1]} for x in query]
        }
        return jsonify(body), headers
    else:
        return "status code <200>", headers

#-----------------------------------------#
# Delete Message
#-----------------------------------------#
@app.route('/delete_msg', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def delete_msg(custom_id):    
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            cnx.execute('set sql_safe_updates = 0;')
            cnx.execute('delete from msg_list where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from scheduled_msg where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from auto_reply where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from welcome_msg_list where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from tag_redirect where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from tag_postback where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
            cnx.execute('delete from url_redirect where msg_id = \'{}\' and custom_id = \'{}\';'.format(data['msg_id'], custom_id))
        return 'status code <200>', headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Auto Reply Feature
#-----------------------------------------#
#-----------------------------------------#
# Setting Auto Reply
#-----------------------------------------#
@app.route('/auto_reply', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def auto_reply(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            cursor = cnx.execute("select keyword from auto_reply where custom_id = \'{}\';".format(custom_id))
            query = cursor.fetchall()
            list_keyword = [x[0] for x in query]
            if data['keyword'] in list_keyword:
                return jsonify({"message" : "keyword has been exist!"}), headers
            else:
                cnx.execute("INSERT INTO auto_reply (reply_id, keyword, msg_id, label_list, custom_id) VALUES ('reply_{}', \'{}\', \'{}\', \'{}\', \'{}\');".format(number(), data['keyword'], data['msg_id'], str(data['label_list']).replace("\'",'\"'), custom_id))
                return jsonify({"message" : "upload completed"}), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Query Auto Reply
#-----------------------------------------#
@app.route('/query_auto', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def query_auto(custom_id): 
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            dict_label = dict(cnx.execute("SELECT label_id, label_name from tag_list where custom_id = \'{}\';".format(custom_id)).fetchall())
            cursor = cnx.execute("select a.reply_id, a.keyword, a.event_time, b.msg_name, b.content, a.label_list from auto_reply a, msg_list b where a.msg_id = b.msg_id and a.custom_id = \'{}\' and b.custom_id = \'{}\' order by event_time desc;".format(custom_id, custom_id))
            query = cursor.fetchall()
        result = list()
        for x in query:
            tmp = {
                "reply_id" : x[0],
                "keyword" : x[1],
                "event_time" : str(x[2]),
                "msg_name" : x[3],
                "content" : json.loads(x[4]),
                "label_list" : [dict_label[y] for y in json.loads(x[5])]
            }
            result.append(tmp)
            
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Delete Auto Reply
#-----------------------------------------#
@app.route('/delete_auto', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def delete_auto(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            cnx.execute('set sql_safe_updates = 0;')
            cnx.execute('delete from auto_reply where reply_id = \'{}\' and custom_id = \'{}\';'.format(data['reply_id'], custom_id))
        return 'status code <200>', headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# Friend Adding Label Feature
#-----------------------------------------#
#-----------------------------------------#
# Friend Adding Label create
#-----------------------------------------#
@app.route('/line_add_create', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def line_add_create(custom_id):
    if request.method == 'POST':
        with engine.connect() as cnx:
            url_api = cnx.execute("select url_api from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
            
        data = request.json
        url_id = "url_{}".format(number())
        logo = data['logo']
        announce = data['announce']
        postion = data['position']
        activity = data['activity']
        url_friend = "{}/MakeFriend/logo={}&announce={}&position={}&activity={}&url_id={}&custom_id={}".format(url_api, logo, announce, postion, activity, url_id, custom_id)
        # qrcode
        qr = qrcode.QRCode()
        qr.add_data(url_friend)
        qr.make(fit=None)
        img = qr.make_image()  
        file_name = "QR_code_{}.png".format(number())  
        img.save("/tmp/{}".format(file_name))
        upload_blob("ieat-qrcode", "/tmp/{}".format(file_name), file_name)    
        make_blob_public("ieat-qrcode", file_name)
        url_qrcode = "https://storage.googleapis.com/ieat-qrcode/{}".format(file_name)
        #
        with engine.connect() as cnx:
            cnx.execute("INSERT INTO line_add (url_id, logo, announce, position, activity, qrcode, url, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\');".format(url_id, logo, data['announce'], postion, activity, url_qrcode, url_friend, custom_id))
            query = cnx.execute("SELECT url_id, logo, announce, position, activity, qrcode, url, click, event_time from line_add where custom_id = \'{}\';".format(custom_id)).fetchall()
        
        result = [{"url_id":x[0], "logo":x[1], "announce":x[2], "position":x[3], "activity":x[4], "qrcode":x[5], "url":x[6], "click":x[7], "event_time":x[8]} for x in query]
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total" : len(query)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Friend Adding with Label (IEAT)
#-----------------------------------------#
@app.route('/line_add/logo=<var_A>&announce=<var_B>&position=<var_C>&activity=<var_D>&url_id=<var_E>', methods = ['GET', 'POST', 'OPTIONS'])
def line_add(var_A, var_B, var_C, var_D, var_E):
    with engine.connect() as cnx:
        click = int(cnx.execute("SELECT click from line_add where url_id = \'{}\' and custom_id = 'cust_ieat';".format(var_E)).fetchall()[0][0])
        cnx.execute("SET sql_safe_updates = 0;")
        cnx.execute("UPDATE line_add SET click = {} WHERE url_id = \'{}\' and custom_id = 'cust_ieat';".format(str(click+1), var_E))
    return redirect('https://lin.ee/Avpnlx4')
#-----------------------------------------#
# Friend Adding with Label (NEW WITH TOKEN)
#-----------------------------------------#
@app.route('/MakeFriend/logo=<var_A>&announce=<var_B>&position=<var_C>&activity=<var_D>&url_id=<var_E>&custom_id=<custom_id>', methods = ['GET', 'POST', 'OPTIONS'])
def MakeFriend(var_A, var_B, var_C, var_D, var_E, custom_id):
    with engine.connect() as cnx:
        click = int(cnx.execute("SELECT click from line_add where url_id = \'{}\' and custom_id = \'{}\';".format(var_E, custom_id)).fetchall()[0][0])
        cnx.execute("SET sql_safe_updates = 0;")
        cnx.execute("UPDATE line_add SET click = {} WHERE url_id = \'{}\' and custom_id = \'{}\';".format(str(click+1), var_E, custom_id))
        url_MakeFriend = cnx.execute("select url_makefriend from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
    return redirect(url_MakeFriend)
#-----------------------------------------#
# Friend Adding Label delete
#-----------------------------------------#
@app.route('/line_add_delete', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def line_add_delete(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            cnx.execute('set sql_safe_updates = 0;')
            cnx.execute('delete from line_add where url_id = \'{}\' and custom_id = \'{}\';'.format(data['url_id'], custom_id))
            query = cnx.execute("SELECT url_id, logo, announce, position, activity, qrcode, url, click, event_time from line_add where custom_id = \'{}\';".format(custom_id)).fetchall()
            
        
        result = [{"url_id":x[0], "logo":x[1], "announce":x[2], "position":x[3], "activity":x[4], "qrcode":x[5], "url":x[6], "click":x[7], "event_time":x[8]} for x in query]
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total" : len(query)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Friend Adding Label display
#-----------------------------------------#
@app.route('/line_add_display', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def line_add_display(custom_id):
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            query = cnx.execute("SELECT url_id, logo, announce, position, activity, qrcode, url, click, event_time from line_add where custom_id = \'{}\';".format(custom_id)).fetchall()
        
        result = [{"url_id":x[0], "logo":x[1], "announce":x[2], "position":x[3], "activity":x[4], "qrcode":x[5], "url":x[6], "click":x[7], "evet_time":x[8]} for x in query]
        
        # filter (keyword)
        if data['filter_keyword'] != "":
            tmp = list()
            for x in result:
                keyword = data['filter_keyword']
                if keyword in x[data['select_keyword']]:
                    tmp.append(x)
            result = tmp
        
        # filter (number)
        if data['filter_number'] != "":
            if data['filter_type'] == "bigger":
                tmp = list()
                for x in result:
                    if int(x['click']) >= int(data['filter_number']):
                        tmp.append(x)
            else:
                tmp = list()
                for x in result:
                    if int(x['click']) <= int(data['filter_number']):
                        tmp.append(x)
            result = tmp
        
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Cloud Storage Feature
#-----------------------------------------#
#-----------------------------------------#
# Video storage
#-----------------------------------------#
@app.route('/video_link', methods = ['GET', 'POST', 'OPTIONS'])
def video_link():
    if request.method == 'POST':
        data = request.files['file']
        file_name = "video_{}.mp4".format(number()) 
        print("口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口")
        print (data)
        print (file_name)
        try:
            data.save("tmp\\{}".format(file_name))
        except:
            return jsonify({"message":"Some Errors Occured During Writting Video Object"}), headers
        
        upload_blob("ieat-video", "tmp\\{}".format(file_name), file_name)    
        make_blob_public("ieat-video", file_name)
        os.remove("tmp\\{}".format(file_name))
        print("口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口口")
        return jsonify({"message":"Upload Completed!", "video_link":"https://storage.googleapis.com/ieat-video/{}".format(file_name)}), headers
    else:
        return jsonify({"message":"POST Request Required"}), headers
#-----------------------------------------#
# Summary Feature
#-----------------------------------------#
#-----------------------------------------#
# Total sub
#-----------------------------------------#
@app.route('/Total_sub', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def Total_sub(custom_id):
    if request.method == 'POST':
        data = request.json
        if data['type'] == 'Totalsub':
            with engine.connect() as cnx:
                cursor = cnx.execute("SELECT follower, friend_in_7, msg_in_7, touch_in_7, unfriend_in_7 FROM summary where custom_id = \'{}\';".format(custom_id))
                query = cursor.fetchall()

            if query != []:
                num_follower = [format(x[0], ',') for x in query][-1]
                num_friend7 = [format(x[1], ',') for x in query][-1]
                num_msg = [format(x[2], ',') for x in query][-1]
                num_touch7 = [format(x[3], ',')for x in query][-1]
                num_unfriend7 = [format(x[4], ',') for x in query][-1]
            else:
                num_follower = num_friend7 = num_msg = num_touch7 = num_unfriend7 = '0'
            
            body = {
                "follower" : num_follower, #會員總人數
                "friend_in_7" : num_friend7, #會員加入(近七天)
                "multicast" : num_msg, #傳送訊息(近七天)
                "touch_in_7" : num_touch7, #活躍會員(近七天)
                "unfriend_in_7" : num_unfriend7 #會員退訂(近七天)
            }    
            return jsonify(body), headers
        else:
            return "status code <200>", headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Barchart
#-----------------------------------------#
@app.route('/barchart', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def barchart(custom_id):
    if request.method == 'POST':
        data = request.json
        if data['type'] == 'barchart':
            if data['date_type'] == '過去7天':
                condition = 'WHERE custom_id = \'{}\' and cur_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'.format(custom_id) 
            elif data['date_type'] == '過去30天':
                condition = 'WHERE custom_id = \'{}\' and cur_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)'.format(custom_id)
            elif data['date_type'] == '自訂':
                condition = "WHERE custom_id = \'{}\' and cur_date BETWEEN '{}' AND '{}'".format(custom_id, data['date_range'][0], data['date_range'][1])
            
            with engine.connect() as cnx:
                cursor = cnx.execute("SELECT cur_date, auto_reply, push, multicast, broadcast, narrowcast, touch_today, new_sub, de_sub, link FROM summary {};".format(condition))
                query = cursor.fetchall()

            list_curdate = [str(x[0]) for x in query]
            # left chart
            list_autoreply = [x[1] for x in query]
            list_msg = [x[2] + x[3] + x[4] + x[5] for x in query]
            list_touchtoday = [x[6] for x in query]
            # right chart
            list_newsub = [x[7] for x in query] 
            list_desub = [x[8] for x in query]
            list_link = [x[9] for x in query]
            

            body = {
                "cur_date" : list_curdate,
                "autoreply" : list_autoreply,
                "multicast" : list_msg,
                "touch_today" : list_touchtoday,
                "new_sub" : list_newsub,
                "de_sub" : list_desub,
                "link" : list_link
            }
            return jsonify(body), headers
        else:
            return "status code <200>", headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Demographics
#-----------------------------------------#
@app.route('/demographic', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def demographic(custom_id):
    with engine.connect() as cnx:
        Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
    
    get_headers = {
        "Authorization" : "Bearer {}".format(Channel_Access_Token)
    }
    url = 'https://api.line.me/v2/bot/insight/demographic'
    req = requests.get(url, headers=get_headers)
    data = json.loads(req.text)

    data_age = {x['age']:x['percentage'] for x in data['ages']}
    data_gender = {x['gender']:x['percentage'] for x in data['genders']}
    data_area = [{"name" : x['area'][0:2], "value":x['percentage']} for x in data['areas']]

    data_area2 = list()
    yee = 0
    for x in data_area:
        if x['name'] == 'un':
            x['name'] = '不明'
            data_area2.append(x)
        elif x['name'] == '嘉義':
            yee = yee + x['value']
        else:
            data_area2.append(x)
    data_area2.append({"name":"嘉義", "value":yee})

    body = {
        "data_age" : {
            "age" : ["0~14歲", "15~19歲", "20~24歲", "25~29歲", "30~34歲", "35~39歲", "40~44歲", "45~49歲", "50歲以上", "不明"],
            "percentage" : [data_age['from0to14'], data_age['from15to19'], data_age['from20to24'], data_age['from25to29'], data_age['from30to34'], data_age['from35to39'], data_age['from40to44'], data_age['from45to49'], data_age['from50'], data_age['unknown']]
        },
        "data_gender" : [
            {"name" : "男生", "value" : data_gender['male']},
            {"name" : "女生", "value" : data_gender['female']},
            {"name" : "不明", "value" : data_gender['unknown']},
        ],
        "data_area" : data_area2
    }
    return jsonify(body), headers
#-----------------------------------------#
# Filter page
#-----------------------------------------#
@app.route("/filter", methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def filter(custom_id):
    if request.method == 'POST':
        data = request.json
        if data['type'] == 'filter':
            # check if there needs any modification
            mdf = data['data_fixed']
            if mdf['userid'] != '':
                if mdf['name'] != '':
                    with engine.connect() as cnx:
                        cnx.execute("UPDATE member_list SET displayname = '{}' where user_id = '{}' and custom_id = \'{}\';".format(mdf['name'], mdf['userid'], custom_id))
                if mdf['address'] != '':
                    with engine.connect() as cnx:
                        cnx.execute("UPDATE member_list SET address = '{}' where user_id = '{}' and custom_id = \'{}\';".format(mdf['address'], mdf['userid'], custom_id))
                if mdf['phone'] != '':
                    with engine.connect() as cnx:
                        cnx.execute("UPDATE member_list SET phone = '{}' where user_id = '{}' and custom_id = \'{}\';".format(mdf['phone'], mdf['userid'], custom_id))
                if mdf['email'] != '':
                    with engine.connect() as cnx:
                        cnx.execute("UPDATE member_list SET e_mail = '{}' where user_id = '{}' and custom_id = \'{}\';".format(mdf['email'], mdf['userid'], custom_id))

            # collect all the labels from DB query  
            with engine.connect() as cnx:
                query = cnx.execute("SELECT label_id, label_name from tag_list where custom_id = \'{}\';".format(custom_id)).fetchall()
                tags = [{'value': x[0], 'label': x[1]} for x in query]
                total_labels = [x[0] for x in query]
                dict_labels = {x[0] : x[1] for x in query}
            
            # label summary
            with engine.connect() as cnx:
                query = cnx.execute("SELECT user_id FROM member_list WHERE user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(custom_id)).fetchall()
                userList = {x[0] for x in query} 
                LabelSummary = {x[0] : [] for x in query} 

            for label in total_labels:
                with engine.connect() as cnx:
                    list_user = [x[0] for x in cnx.execute("SELECT user_id FROM label_record where label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()]
                for user in list_user:
                    try:
                        LabelSummary[user] = LabelSummary[user] + [dict_labels[label]]
                    except:
                        with engine.connect() as cnx:
                            cnx.execute("INSERT INTO error_log (log_msg, custom_id) VALUES (\'{}\', \'{}\');".format(user, custom_id))
                        continue

            # 性別條件
            cond_gender = list({x['male'] for x in data['gender']})
            list_Gender = list()
            for gender in cond_gender:
                with engine.connect() as cnx:
                    tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender = \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                    list_Gender.append(tmp)
            
            # 標籤條件
            in_label = list()
            ex_label = list()
            for dummy, label_id in zip(data['label_dummy'], data['label_id']):
                if dummy == '是':
                    in_label = in_label + label_id['tag']
                else:
                    ex_label = ex_label + label_id['tag']
            in_label = list(set(in_label))
            ex_label = list(set(ex_label))
        
            list_InLabel = list()
            for label in in_label:
                with engine.connect() as cnx:
                    tmp = {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                    list_InLabel.append(tmp)
            
            list_ExLabel = list()
            for label in ex_label:
                with engine.connect() as cnx:
                    tmp = userList - {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                    list_ExLabel.append(tmp)

            list_Total = list_Gender + list_InLabel + list_ExLabel
            #
            if cond_gender + in_label + ex_label == []:
                userid_all = userList
            else:
                if list_Total != []:
                    userid_all = list_Total[0]
                    for query in list_Total:
                        if data['filter_select'] == '符合所有篩選條件':
                            userid_all = userid_all & query
                        else:
                            userid_all = userid_all | query
                else:
                    userid_all = set()
              
            # 時間條件
            with engine.connect() as cnx:
                if data['radio_time'] == '不限時間':
                    pass
                else:
                    if data['radio_time'] == '過去':
                        userid_time = {x[0] for x in cnx.execute("select user_id from memeber_list where custom_id = \'{}\' and jointime BETWEEN DATE_SUB(NOW(), INTERVAL {} DAY) AND NOW()".format(custom_id, data['time_select'].replace('天', '')))}
                    else: #自訂
                        userid_time = {x[0] for x in cnx.execute("select user_id from memeber_list where custom_id = \'{}\' and jointime BETWEEN '{}' AND '{}'".format(custom_id, data['time_range'][0], data['time_range'][1]))}
                    userid_all = userid_time & userid_all
            
            # 篩選條件
            with engine.connect() as cnx:
                if data['search_input'] != '':
                    if data['select_keyword'] == 'name':
                        userid_filter = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE custom_id = \'{}\' and (displayname like '{}%%' or displayname like '%%{}' or displayname like '%%{}%%');".format(custom_id, data['search_input'], data['search_input'], data['search_input']))}
                    elif data['select_keyword'] == 'phone':
                        userid_filter = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE custom_id = \'{}\' and (phone like '{}%%' or phone like '%%{}' or phone like '%%{}%%');".format(custom_id, data['search_input'], data['search_input'], data['search_input']))}
                    elif data['select_keyword'] == 'email':
                        userid_filter = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE custom_id = \'{}\' and (e_mail like '{}%%' or e_mail like '%%{}' or e_mail like '%%{}%%');".format(custom_id, data['search_input'], data['search_input'], data['search_input']))}
                    elif data['select_keyword'] == 'user_id':
                        userid_filter = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE custom_id = \'{}\' and (user_id like '{}%%' or user_id like '%%{}' or user_id like '%%{}%%');".format(custom_id, data['search_input'], data['search_input'], data['search_input']))}
                    userid_all = userid_filter & userid_all
                else:
                    pass
                
            # Result
            # 頁碼條件
            if userid_all != set():
                page = data['page']
                limit = data['limit']
                lim_1 = (page-1)*limit
                total = len(userid_all)
                #
                cond_userid = str(userid_all).replace("{", "(").replace("}", ")")
                with engine.connect() as cnx:
                    query = cnx.execute('SELECT displayname, gender, user_id, jointime, picture, e_mail, phone, address, username, D_member, birth from member_list where user_id in {} and custom_id = \'{}\' limit {}, {};'.format(cond_userid, custom_id, str(lim_1), str(limit))).fetchall()
            else:
                total = 0
                query = []

            result = []
            for x in query:
                tmp = {
                    "name" : x[0],
                    "gender" : x[1],
                    "user_id" : x[2],
                    "jointime" : x[3],
                    "label_id" : LabelSummary[x[2]],
                    
                    "picture" : x[4],
                    "email" : x[5],
                    "phone" : x[6],
                    "address": x[7],
                    "username" : x[8],
                    "D_member" : x[9],
                    "birth" : x[10]
                }
                result.append(tmp)

            body = {
                "total" : total,
                "member_data" : result,
                "tags" : tags
            }
            return jsonify(body), headers
        else:
            return 'hello python', headers
    else:
        return 'hello python', headers
#-----------------------------------------#
# Cron setting Feature
#-----------------------------------------#
#-----------------------------------------#
# auto summary
#-----------------------------------------#
@app.route("/auto_summary", methods=['get'])
def auto_summary():
    # front page information    
    with engine.connect() as cnx:
        query = cnx.execute('SELECT DATE_SUB(CURDATE(), interval 1 day);').fetchall()[0][0]
        year = str(query.year)
        #yesterday
        if query.month < 10:
            month = str('0')+str(query.month)
        else:
            month  = str(query.month)
        

        if query.day < 10:
            day = str('0')+str(query.day)
        else:
            day  = str(query.day)
        cond_yesterday = year+month+day
        date_yesterday = datetime.date(int(year), int(month), int(day))

        #today
        query = cnx.execute('SELECT CURDATE();').fetchall()[0][0]
        year = str(query.year)

        if query.month < 10:
            month = str('0')+str(query.month)
        else:
            month  = str(query.month)
        
        if query.day < 10:
            day = str('0')+str(query.day)
        else:
            day  = str(query.day)
        cond_today = year+'-'+month+'-'+day+'%%'
        date_today = datetime.date(int(year), int(month), int(day))

    with engine.connect() as cnx:
        CustomIDList = [x[0] for x in cnx.execute("SELECT custom_id from user_list;").fetchall()]
    
    for custom_id in CustomIDList:
        with engine.connect() as cnx:
            Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
        
        get_headers = {
            "Authorization" : "Bearer {}".format(Channel_Access_Token)
        }
        
        url_delivery = "https://api.line.me/v2/bot/insight/message/delivery?date="
        req_delivery = requests.get(url_delivery + cond_yesterday, headers = get_headers)
        json_req = json.loads(req_delivery.text)

        apiResult = {
            "apiReply" : 0,
            "apiPush": 0,
            "apiMulticast" : 0,
            "apiBroadcast" : 0,
            "apiNarrowcast" : 0
        }

        for key in json_req.keys():
            apiResult[key] = json_req[key]
        
        with engine.connect() as cnx:
            num_follower = cnx.execute('select count(*) from member_list where user_id not in (select user_id from unfriend_list) and custom_id = \'{}\';'.format(custom_id)).fetchall()[0][0]
            num_friend = cnx.execute('select count(*) from member_list where jointime >= date_sub(curdate(), interval 7 day) and custom_id = \'{}\';'.format(custom_id)).fetchall()[0][0]
            num_unfriend = cnx.execute('select count(*) from unfriend_list where event_time >= date_sub(curdate(), interval 7 day) and custom_id = \'{}\';'.format(custom_id)).fetchall()[0][0]
            num_touch = cnx.execute('select count(*) from (select user_id, max(timestamp) as timestamp from label_record where custom_id = \'{}\' group by user_id) as tmp where tmp.timestamp >= date_sub(curdate(), interval 7 day);'.format(custom_id)).fetchall()[0][0]
            num_msg = cnx.execute('select sum(push)+sum(multicast)+sum(broadcast)+sum(narrowcast) from summary where cur_date >= date_sub(curdate(), interval 7 day) and custom_id = \'{}\';'.format(custom_id)).fetchall()[0][0]
            num_newsub = cnx.execute('select count(*) from member_list where jointime like \'{}\' and custom_id = \'{}\';'.format(cond_today, custom_id)).fetchall()[0][0]
            num_desub = cnx.execute('select count(*) from unfriend_list where event_time like \'{}\' and custom_id = \'{}\';'.format(cond_today, custom_id)).fetchall()[0][0]
            num_touchtoday = cnx.execute('select count(*) from (select user_id, max(timestamp) as timestamp from label_record where custom_id = \'{}\' group by user_id) as tmp where tmp.timestamp like \'{}\';'.format(custom_id, cond_today)).fetchall()[0][0]
            num_link = cnx.execute("select count(*) from member_list where event_time like \'{}\' and custom_id = \'{}\' and D_member = 1;".format(cond_today, custom_id)).fetchall()[0][0]

        if num_msg == None:
            num_msg = 0

        with engine.connect() as cnx:        
            # renew summary table
            cnx.execute("set sql_safe_updates = 0;")
            cnx.execute("delete from summary where cur_date = \'{}\' and custom_id = \'{}\';".format(str(date_today), custom_id))
            cnx.execute("INSERT INTO summary (cur_date, follower, friend_in_7, unfriend_in_7, touch_in_7, msg_in_7, new_sub, de_sub, touch_today, link, custom_id) \
                values (\'{}\', {}, {}, {}, {}, {}, {}, {}, {}, {}, \'{}\');".format(date_today, num_follower, num_friend, num_unfriend, num_touch, num_msg, num_newsub, num_desub, num_touchtoday, num_link, custom_id))
            cnx.execute("UPDATE summary set auto_reply = {}, push = {}, multicast = {}, broadcast = {}, narrowcast = {} \
                where cur_date = \'{}\' and custom_id = \'{}\';".format(apiResult['apiReply'], apiResult['apiPush'], apiResult['apiMulticast'], apiResult['apiBroadcast'], apiResult['apiNarrowcast'], date_yesterday, custom_id))
    return "status code <200>", headers
#-----------------------------------------#
# auto renew label record
#-----------------------------------------#
@app.route('/renew_label_record')
def renew_label_record():
    with engine.connect() as cnx:
        CustomIDList = [x[0] for x in cnx.execute("SELECT custom_id from user_list;").fetchall()]
    
    for custom_id in CustomIDList:
        # renew label record
        with engine.connect() as cnx:
            # 選取非永久之標籤
            query = cnx.execute("SELECT label_id, label_period FROM tag_list WHERE label_period != 0 and custom_id = \'{}\';".format(custom_id)).fetchall()
            now = str(cnx.execute("select NOW();").fetchall()[0][0])
            # 將非永久之標籤，如果非在有效期限內，標籤紀錄歸零
        with engine.connect() as cnx:    
            cnx.execute("SET SQL_SAFE_UPDATES = 0;")
            for x in query:
                date = str(cnx.execute("select date_sub(\'{}\', interval {} day);".format(now, x[1])).fetchall()[0][0])
                cnx.execute("delete from label_record where label_id = \'{}\' and timestamp <= \'{}\' and custom_id = \'{}\';".format(x[0], date, custom_id))
    return "status code <200>", headers
#-----------------------------------------#
# Execute Scheduled Task
#-----------------------------------------#
@app.route('/run_task')
def run_task():
    with engine.connect() as cnx:
        CustomIDList = [x[0] for x in cnx.execute("SELECT custom_id from user_list;").fetchall()]
    
    for custom_id in CustomIDList:
        with engine.connect() as cnx:
            do_list = cnx.execute("select task_id, include, exclude, D_union from audience where timing <= NOW() and custom_id = \'{}\';".format(custom_id)).fetchall()
            body_list = [{"task_id":x[0], "include":json.loads(x[1]), "exclude":json.loads(x[2]), "union":x[3]} for x in do_list]

        # create audience
        for data in body_list:     
            # Total User_ID
            with engine.connect() as cnx:
                userList = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(custom_id)).fetchall()} 

            # gender
            in_gender = data['include']['gender']
            ex_gender = data['exclude']['gender']

            list_InGender = list()
            for gender in in_gender:
                with engine.connect() as cnx:
                    tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender = \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                    list_InGender.append(tmp)
            
            list_ExGender = list()
            for gender in ex_gender:
                with engine.connect() as cnx:
                    tmp = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE gender != \'{}\' and user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(gender, custom_id)).fetchall()}
                    list_ExGender.append(tmp)

            # label_id
            in_label = data['include']['label_id']
            ex_label = data['exclude']['label_id']

            list_InLabel = list()
            for label in in_label:
                with engine.connect() as cnx:
                    tmp = {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                    list_InLabel.append(tmp)
            
            list_ExLabel = list()
            for label in ex_label:
                with engine.connect() as cnx:
                    tmp = userList - {x[0] for x in cnx.execute("SELECT user_id FROM label_record WHERE label_id = \'{}\' and custom_id = \'{}\';".format(label, custom_id)).fetchall()}
                    list_ExLabel.append(tmp)

            list_Total = list_InGender + list_ExGender + list_InLabel + list_ExLabel
            #
            if in_gender + ex_gender + in_label + ex_label == []:
                userid_all = userList
            else:
                if list_Total != []:
                    userid_all = list_Total[0]
                    for query in list_Total:
                        if data['union'] == 'false':
                            userid_all = userid_all & query
                        else:
                            userid_all = userid_all | query
                else:
                    userid_all = set()
            
            userid_all = list(userid_all)
            #
            with engine.connect() as cnx:
                num_aud = len(userid_all)
                cnx.execute("SET sql_safe_updates = 0;")
                cnx.execute("UPDATE scheduled_msg SET num_aud = {} WHERE task_id = \'{}\' and custom_id = \'{}\';".format(str(num_aud), data['task_id'], custom_id))
                
            if userid_all != []:
                with engine.connect() as cnx:
                    Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
                url_addaud = 'https://api.line.me/v2/bot/audienceGroup/upload'

                list_AudId = list()
                page = 1
                while page_list(userid_all, page, 10000) != []:
                    body_addaud = {
                        "description": "audience_{}".format(number()),
                        "isIfaAudience": "false",
                        "audiences":[{"id" : x} for x in page_list(userid_all, page, 10000)],
                        "audiences[].id":"user id"
                    }

                    push_headers = {
                        "Content-Type" : "application/json",
                        "Authorization" : "Bearer {}".format(Channel_Access_Token)
                    }

                    req_addaud = requests.post(url_addaud, headers = push_headers, data = json.dumps(body_addaud))

                    if req_addaud.status_code == 202:
                        aud_id = json.loads(req_addaud.text)['audienceGroupId']
                        list_AudId.append(aud_id)
                    else:
                        log_msg = json.loads(req_addaud.text)['message']
                        cnx.execute("INSERT INTO error_log (log_msg, custom_id) VALUES (\'{}\', \'{}\');".format(log_msg, custom_id))
                        # return jsonify({"message":"error", "log":log_msg}), headers
                    page += 1    
                json_AUdIdList = str(list_AudId).replace("\'",'\"')
                with engine.connect() as cnx:
                    cnx.execute("SET sql_safe_updates = 0;")
                    cnx.execute("UPDATE scheduled_msg SET aud_id = \'{}\' WHERE task_id = \'{}\' and custom_id = \'{}\';".format(json_AUdIdList, data['task_id'], custom_id))
                    cnx.execute("DELETE FROM audience WHERE task_id = \'{}\' and custom_id = \'{}\';".format(data['task_id'], custom_id))
                        

        # push message to target audience_id
        with engine.connect() as cnx:
            cnx.execute("set sql_safe_updates = 0;")
            do_list = cnx.execute("SELECT task_id, msg_id, aud_id, msg_name, object, D_union, num_aud from scheduled_msg WHERE timing <= NOW() and custom_id = \'{}\';".format(custom_id)).fetchall()
            body_list = [{"task_id":x[0], "msg_id":x[1], "aud_id":json.loads(x[2]), "msg_name":x[3], "object":json.loads(x[4]), "union":x[5], "num_aud":x[6]} for x in do_list]
        
        for data in body_list:
            # push narrowcast msg
            with engine.connect() as cnx:
                Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
                query = cnx.execute("SELECT content, action_list, postback_list FROM msg_list WHERE msg_id = \'{}\' and custom_id = \'{}\';".format(data['msg_id'], custom_id)).fetchall()[0]
                content = query[0]
                json_action = query[1]
                json_postback = query[2]
            url_narrow = 'https://api.line.me/v2/bot/message/narrowcast'

            body_narrow = {
                "messages" : json.loads(content),
                "recipient": {
                    "type": "operator",
                    "or" : [{"type": "audience", "audienceGroupId": g_id} for g_id in data['aud_id']]
                }
            }

            push_headers = {
                "Content-Type" : "application/json",
                "Authorization" : "Bearer {}".format(Channel_Access_Token)
            }

            req_narrow = requests.post(url_narrow, headers = push_headers, data = json.dumps(body_narrow))
            aud_id = str(data['aud_id']).replace("\'",'\"')
            req_id = req_narrow.headers['x-line-request-id']
            json_object = str(data['object']).replace("\'",'\"')
            if req_narrow.status_code == 202:
                log_msg = "message sent"
                with engine.connect() as cnx:
                    cnx.execute("set sql_safe_updates = 0")
                    cnx.execute("update push_history set action_list = '[]' where action_list like \'{}\' and custom_id = \'{}\';".format(json_action, custom_id)) # 停止計算舊的
                    cnx.execute("update push_history set postback_list = '[]' where postback_list like \'{}\' and custom_id = \'{}\';".format(json_postback, custom_id))
                    cnx.execute("delete from scheduled_msg where task_id = \'{}\' and custom_id = \'{}\';".format(data['task_id'], custom_id))
                    cnx.execute("INSERT INTO push_history (msg_name, object, D_union, req_id, aud_id, log_msg, num_aud, action_list, postback_list, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', {}, \'{}\', \'{}\', \'{}\'\
                        );".format(data['msg_name'], json_object, data['union'], req_id, aud_id, log_msg, str(data['num_aud']), json_action, json_postback, custom_id))
                # return jsonify({"message": "request completed!"}), headers
            else:
                log_msg = json.loads(req_narrow.text)['message']
                with engine.connect() as cnx:
                    cnx.execute("INSERT INTO error_log (log_msg, custom_id) VALUES (\'{}\', \'{}\');".format(log_msg, custom_id))
                # return jsonify({"message":"error", "log":log_msg}), headers

    return "status code <200>", headers
#-----------------------------------------#
# Token Feature
#-----------------------------------------#
#-----------------------------------------#
# login page
#-----------------------------------------#
@app.route('/login', methods=['GET', 'POST', 'OPTIONS'])
def login():
    if request.method == 'POST':
        data = request.json

        with engine.connect() as cnx:
            query = cnx.execute("SELECT custom_id, pw FROM user_list WHERE id = \'{}\'".format(data['loginForm']['username'])).fetchall()
            if not query:
                return jsonify({"message" : "username not found!"}), headers
            else:
                custom_id = query[0][0]
                password = query[0][1]
        
        if check_password_hash(password, data['loginForm']['password']):
            token = jwt.encode({'custom_id' : custom_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=1440)}, app.config['SECRET_KEY'])
            return jsonify({"token" : token.decode("UTF-8")}), headers
        else:
            return jsonify({"message" : "Password is invalid!"}), headers
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# token data
#-----------------------------------------#
@app.route('/token_data', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def token_data(custom_id):
    if request.method == 'POST':
        try:
            with engine.connect() as cnx:
                cursor = cnx.execute("SELECT display_name, roles, avatar FROM user_list WHERE custom_id = \'{}\';".format(custom_id))
                query = cursor.fetchall()[0]
                userList = {"name" : query[0], "roles" : [query[1]], "avatar" : query[2]}
            return jsonify({"userList" : userList}), headers
        except:                 
            return 'Error :(', headers
    else:
        return "status code <200>", headers
#-----------------------------------------#
# create user
#-----------------------------------------#
@app.route('/create_user', methods=['GET', 'POST', 'OPTIONS'])
def create_user():
    if request.method == 'POST':
        data = request.json
        password = generate_password_hash(data['password'], method = 'sha256')

        with engine.connect() as cnx:
            cnx.execute("INSERT INTO user_list (custom_id, id, pw, display_name, roles, avatar) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\');"\
                .format(data['custom_id'], data['username'], password, data['display_name'], data['roles'], data['avatar']))

        return 'status code <200>', headers
    
    else:
        return 'status code <200>', headers
#-----------------------------------------#
# Scheduled Message Feature
#-----------------------------------------#
#-----------------------------------------#
# Create Task
#-----------------------------------------#
@app.route('/create_task', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def create_task(custom_id):
    if request.method == 'POST':
        data = request.json
        # setting timestamp
        year = data['year']
        month = data['month']
        day = data['day']
        hour = data['hour']
        minutes = data['minutes']
        second = data['second']
        timing_task = str(datetime.datetime(year, month, day, hour, minutes, second))
        timing_audi = str(datetime.datetime(year, month, day, hour, minutes, second) - datetime.timedelta(minutes=20))
        # gender
        in_gender = data['include']['gender']
        ex_gender = data['exclude']['gender']
        # label_id
        in_label = data['include']['label_id']
        ex_label = data['exclude']['label_id']
        #
        task_id = "task_{}".format(number())
        with engine.connect() as cnx:
            #label recording
            dict_label = dict(cnx.execute("SELECT label_id, label_name from tag_list where custom_id = \'{}\';".format(custom_id)).fetchall())
            
            in_list = [dict_label[x] for x in in_label] + in_gender
            ex_list = [dict_label[x] for x in ex_label] + ex_gender
            
            if in_list + ex_list == []:
                json_LabelName = '{"list_yes": ["全部會員"], "list_no": []}'
            else:
                json_LabelName = str({"list_yes" : in_list, "list_no" : ex_list}).replace("\'",'\"')
            #
            json_include = str(data['include']).replace("\'",'\"')
            json_exclude = str(data['exclude']).replace("\'",'\"')
            # 儲存排程
            msg_name = cnx.execute("select msg_name from msg_list where msg_id = '{}' and custom_id = \'{}\';".format(data['msg_id'], custom_id)).fetchall()[0][0]
            
            cnx.execute("INSERT INTO scheduled_msg (task_id, msg_id, msg_name, object, D_union, timing, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\');".format(task_id, data['msg_id'], msg_name, json_LabelName, data['union'], timing_task, custom_id))
            cnx.execute("INSERT INTO audience (task_id, include, exclude, D_union, timing, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\');".format(task_id, json_include, json_exclude, data['union'], timing_audi, custom_id))
            
        return jsonify({"message":"successed!"}), headers
    else:
        return "status code <200>", headers
#-----------------------------------------#
# Query Task
#-----------------------------------------#
@app.route('/query_task', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def query_task(custom_id): 
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            query = cnx.execute("SELECT msg_name, object, timing, state, task_id, D_union FROM scheduled_msg where custom_id = \'{}\';".format(custom_id)).fetchall()

        result = [{"msg_name": x[0], "object":json.loads(x[1]), "timing":str(x[2]), "state":x[3], "task_id":x[4], "D_union":x[5]} for x in query]
            
        body = {
            "data" : page_list(result, data['page'], data['limit']),
            "total" : len(result)
        }
        return jsonify(body), headers
    else:
        return 'status code <200>', headers

#-----------------------------------------#
# delete Task
#-----------------------------------------#
@app.route('/delete_task', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def delete_task(custom_id): 
    if request.method == 'POST':
        data = request.json
        with engine.connect() as cnx:
            cnx.execute('delete from scheduled_msg where task_id = \'{}\' and custom_id = \'{}\';'.format(data['task_id'], custom_id))
            cnx.execute('delete from audience where task_id = \'{}\' and custom_id = \'{}\';'.format(data['task_id'], custom_id))
        return jsonify({"message":"task deleted!"}), headers
    else:
        return jsonify({"message":"OK"}), headers

#-----------------------------------------#
# create welcome message
#-----------------------------------------#
@app.route('/set_welcome', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def set_welcome(custom_id):
    with engine.connect() as cnx:
        cnx.execute("set sql_safe_updates = 0;")
        cnx.execute("delete from scheduled_msg where task_id like \'day%%\' and custom_id = \'{}\';".format(custom_id))
    if request.method == "POST":
        data = request.json
        for day in range(1, 8):
            json_object = str({"list_yes" : ["加入第{}天會員".format(day)], "list_no" : []}).replace("\'",'\"')
            if data['welcome_msg_active' + str(day)] == "1":
                with engine.connect() as cnx:
                    query = cnx.execute("select * from welcome_msg_list where days = {} and custom_id = \'{}\';".format(day, custom_id)).fetchall()
                if len(query) == 0:
                    with engine.connect() as cnx:
                        cnx.execute("insert into welcome_msg_list (custom_id, days, msg_id, active, timing, object) values (\'{}\', {}, \'{}\', 1, \'{}\', \'{}\')".format(custom_id, day, data['welcome_msg_day' + str(day)], data["timing"], json_object))
                else:
                    with engine.connect() as cnx:
                        cnx.execute("set sql_safe_updates = 0;")
                        cnx.execute("update welcome_msg_list set active = 1, msg_id = \'{}\' , timing = \'{}\', object = \'{}\' where custom_id = \'{}\' and days = {};".format(data['welcome_msg_day' + str(day)], data["timing"], json_object, custom_id, day))
            else:
                with engine.connect() as cnx:
                    cnx.execute("update welcome_msg_list set active = 0 where custom_id = \'{}\' and days = {};".format(custom_id, day))
        return jsonify({"message":"success"}), headers
    else:
        return jsonify({"message":"OK"}), headers

#-----------------------------------------#
# query welcome message
#-----------------------------------------#
@app.route('/query_welcome', methods=['GET', 'POST', 'OPTIONS'])
#@token_required
def query_welcome(custom_id):
    if request.method == 'POST':
        result = dict()
        for day in range(1, 8):
            with engine.connect() as cnx:
                query = cnx.execute("select msg_id, active from welcome_msg_list where custom_id = \'{}\' and days = {};".format(custom_id, day)).fetchall()
                time = cnx.execute("select timing from welcome_msg_list where active = 1 and custom_id = \'{}\';".format(custom_id)).fetchall()
            # 時間
            if len(time) != 0:
                timing = time[0][0]
            else:
                timing = "10:00"
            
            # 訊息
            if len(query) != 0:
                if query[0][1] == 1:
                    result["day"+str(day)] = {
                        "msg_id" : query[0][0],
                        "active" : "true"
                    }
                else:
                    result["day"+str(day)] = {
                        "msg_id" : "",
                        "active" : "false"
                    }
            else:
                result["day"+str(day)] = {
                    "msg_id" : "",
                    "active" : "false"
                }
        return jsonify({"response" : result, "timing":timing}), headers
    else:
        return jsonify({"message":"OK"}), headers

#-----------------------------------------#
# Create Welcome Task
#-----------------------------------------#
@app.route('/create_welcome_task', methods = ['GET', 'POST', 'OPTIONS'])
def create_welcome_task():
    with engine.connect() as cnx:
        CustomIDList = [x[0] for x in cnx.execute("SELECT custom_id from user_list;").fetchall()]
    
    for custom_id in CustomIDList:
        with engine.connect() as cnx:
            query = cnx.execute("select days, msg_id from welcome_msg_list where active = 1 and custom_id = \'{}\';".format(custom_id)).fetchall()
        if len(query) == 0:
            continue
        else:
            with engine.connect() as cnx:
                time_set = cnx.execute("select timing from welcome_msg_list where active = 1 and custom_id = \'{}\';".format(custom_id)).fetchall()[0][0].split(":")
                today = cnx.execute("select curdate();").fetchall()[0][0]
                cond_hour = int(time_set[0])
                cond_minute = int(time_set[1])

            for task in query:
                # 第一天的不用送排程
                if int(task[0]) == 1:
                    continue
                else:
                    # task_id #
                    task_id = "day{}".format(task[0])
                    msg_id = task[1]
                    # msg_name
                    with engine.connect() as cnx:
                        msg_name = cnx.execute("select msg_name from msg_list where custom_id = \'{}\' and msg_id = \'{}\';".format(custom_id, task[1])).fetchall()[0][0]
                    # object
                    json_object = str({"list_yes" : ["加入第{}天會員".format(task[0])], "list_no" : []}).replace("\'",'\"')
                    # D_union
                    D_union = "false"
                    # timing
                    timing_cond = str(today - datetime.timedelta(days= (int(task[0])-1)))
                    timing = str(datetime.datetime(today.year, today.month, today.day, cond_hour, cond_minute, 0))
                    
                    # Total User_ID
                    with engine.connect() as cnx:
                        userList = {x[0] for x in cnx.execute("SELECT user_id FROM member_list WHERE user_id not in (SELECT user_id FROM unfriend_list) and custom_id = \'{}\';".format(custom_id)).fetchall()} 
                        targetID = {x[0] for x in cnx.execute("select user_id from member_list where jointime like \'{}%%\' and custom_id = \'{}\';".format(timing_cond, custom_id)).fetchall()}
                        userid_all = list(userList & targetID)
                    
                    # create audiences
                    if userid_all != []:
                        with engine.connect() as cnx:
                            Channel_Access_Token = cnx.execute("select msg_token from bot_info where custom_id = \'{}\';".format(custom_id)).fetchall()[0][0]
                        url_addaud = 'https://api.line.me/v2/bot/audienceGroup/upload'

                        list_AudId = list()
                        page = 1
                        while page_list(userid_all, page, 10000) != []:
                            body_addaud = {
                                "description": "audience_{}".format(number()),
                                "isIfaAudience": "false",
                                "audiences":[{"id" : x} for x in page_list(userid_all, page, 10000)],
                                "audiences[].id":"user id"
                            }

                            push_headers = {
                                "Content-Type" : "application/json",
                                "Authorization" : "Bearer {}".format(Channel_Access_Token)
                            }

                            req_addaud = requests.post(url_addaud, headers = push_headers, data = json.dumps(body_addaud))

                            if req_addaud.status_code == 202:
                                aud_id = json.loads(req_addaud.text)['audienceGroupId']
                                list_AudId.append(aud_id)
                            else:
                                log_msg = json.loads(req_addaud.text)['message']
                                with engine.connect() as cnx:    
                                    cnx.execute("INSERT INTO error_log (log_msg, custom_id) VALUES (\'{}\', \'{}\');".format(log_msg, custom_id))
                                # return jsonify({"message":"error", "log":log_msg}), headers
                            page += 1    
                        
                        json_AudIdList = str(list_AudId).replace("\'",'\"')
                        # create task
                        with engine.connect() as cnx:
                            cnx.execute("INSERT INTO scheduled_msg (task_id, msg_id, msg_name, object, D_union, timing, aud_id, num_aud, custom_id) VALUES (\'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', \'{}\', {}, \'{}\');"\
                                .format(task_id, msg_id, msg_name, json_object, D_union, timing, json_AudIdList, len(userid_all), custom_id))
                    else:
                        continue
    return jsonify({"message":"successed!"}), headers
#-----------------------------------------#
# Chatroom Feature
#-----------------------------------------#
#-----------------------------------------#
# user info
#-----------------------------------------#
@app.route('/user_info', methods = ['GET', 'POST', 'OPTIONS'])
#@token_required
def user_info(custom_id):
    if request.method == 'POST':
        data = request.json
        user_id = data['user_id']

        with engine.connect() as cnx:
            query = cnx.execute('SELECT user_id, displayname, username, gender, birth, picture, e_mail, phone, address, jointime, event_time, D_member \
                from member_list where user_id = \'{}\' and custom_id = \'{}\';'.format(user_id, custom_id)).fetchall()[0]

        body = {
            "user_id" : query[0],
            "line_name" : query[1],
            "real_name" : query[2],
            "gender" : query[3],
            "birth" : query[4],
            "picture" : query[5],
            "e_mail" : query[6],
            "phone" : query[7],
            "address": query[8],
            "friend_time" : str(query[9]),
            "link_time" : str(query[10])
        }

        return jsonify(body), headers    
    else:
        return jsonify({"message":"OK"}), headers
#-----------------------------------------#
# RESET
#-----------------------------------------#
@app.route('/reset', methods=['GET', 'POST', 'OPTIONS'])
def reset():
    if request.method == 'POST':
        data = request.json
        userid = data['user_id']
        empty = ""
        with engine.connect() as cnx:
            cnx.execute("set sql_safe_updates = 0;")    
            cnx.execute('update member_list set username = \'{}\', gender = \'{}\', e_mail = \'{}\', address = \'{}\', birth = \'{}\', phone = \'{}\', D_member = 0 where user_id = \'{}\' and custom_id = "cust_ieat";'.format(empty, empty, empty, empty, "20020314", empty, userid))
        return jsonify({"message" : "info reseted"}), headers
    else:
        return jsonify ({"message":"plz use post request"}), headers
#-----------------------------------------#
# FaceLanding link
#-----------------------------------------#
@app.route("/get_code", methods=['GET', 'POST', 'OPTIONS'])
def get_code():
    if request.method == 'POST':
        data = request.json
        code = random.randint(100000, 999999)
        token = jwt.encode({'phone' : "0931968899", 'exp' : datetime.datetime.utcnow()}, app.config['SECRET_KEY']).decode("utf8")
        phone = str(data['phone'])
        # send msg
        body = {
            "username" : "fatsheepgod",
            "password" : "fatsheepgod",
            "dstaddr" : phone,
            "smbody" : "親愛的貴賓您好，您的會員認證碼為[{}]。".format(code)
        }
        hash_url = urllib.parse.urlencode(body, encoding="big5")
        url = 'https://api.kotsms.com.tw/kotsmsapi-1.php?{}'.format(hash_url)
        req = requests.post(url)
        # saving info
        with engine.connect() as cnx:
            cnx.execute("insert into FL_verify (phone, code, token, log) values (\'{}\', \'{}\', \'{}\', \'{}\');".format(phone, code, token, req.text))
        engine.dispose()
        return jsonify({"token" : token}), headers
    else:
        engine.dispose()
        return jsonify({"message":"OK"})

@app.route("/test41")
def test41():
    return "Hello World41!"   
        
engine.dispose()
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    app.run(ssl_context=('certificate.crt', 'private.key'),host='0.0.0.0', port=port)
    # app.run(host='0.0.0.0', port=port)
