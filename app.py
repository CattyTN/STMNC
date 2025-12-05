from flask import Flask, render_template, request, flash, send_file
from flask import jsonify
from flask import session
import pandas as pd
import time
import json
from datetime import datetime, timedelta
from collections import Counter
import hashlib
import requests
import threading
from flask import redirect, url_for, Response, stream_with_context, abort
from sshtunnel import SSHTunnelForwarder
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
from pymongo import MongoClient
import urllib3
import uuid
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from docxtpl import DocxTemplate
import tempfile
import subprocess
from functools import wraps

app = Flask(__name__)
app.secret_key = "your_secret_key"  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

client = MongoClient("mongodb://localhost:27017/")
db = client["stmnc"]
user_collection = db["user"]
chart_collection = db['chart']
parameter_collection = db['parameter']
ram_collection = db['ram']
ram_2_collection = db['ram_2']
indicator_collection = db['indicator']
white_list_collection = db['white_list']
search_and_backup_collection = db["search_and_backup"]
miav_database_collection = db["miav_database"]
search_history_collection = db["search_history"]
login_event_collection = db["login_event"]

indicator_collection = db["indicator"]
relationship_collection = db["relationship"]
malware_collection = db["malware"]
campaign_collection = db["campaign"]
intrusion_set_collection = db["intrusion_set"]


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# path tới thư mục fonts trong project
font_regular = os.path.join(app.root_path, "static","assets", "fonts", "times.ttf")
font_bold    = os.path.join(app.root_path, "static","assets", "fonts", "timesbd.ttf")

pdfmetrics.registerFont(TTFont("TimesVN", font_regular))
pdfmetrics.registerFont(TTFont("TimesVN-Bold", font_bold))

#lấy ra df user
def get_users():
    user_data = list(user_collection.find())
    df = pd.DataFrame(user_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
# lấy ra thông số của chart
def get_chart():
    chart_data = list(chart_collection.find())
    df = pd.DataFrame(chart_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
# lấy ra thông số của chart
def get_parameter():
    parameter_data = list(parameter_collection.find())
    df = pd.DataFrame(parameter_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
def get_record():
    ram_data = list(ram_collection.find().sort("time_receive", -1))
    df = pd.DataFrame(ram_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df

def get_miav_database():
    miav_data = list(miav_database_collection.find())
    df = pd.DataFrame(miav_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
def get_device():
    """
    Lấy bảng device từ MongoDB.
    Giả sử collection tên là 'device'.
    Điều chỉnh lại tên collection/field cho đúng thực tế nếu khác.
    """
    device_collection = db["device"]          # đổi tên nếu bạn đang dùng tên khác
    device_data = list(device_collection.find())
    df = pd.DataFrame(device_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
#def get_search_and_backup():
#    search_and_backup_data = list(search_and_backup_collection.find())
#    df = pd.DataFrame(search_and_backup_data)
#    if "_id" in df.columns:
#        df.drop(columns=["_id"], inplace=True)
#    return df
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Chưa đăng nhập thì dùng cơ chế sẵn có của login_manager
        if not current_user.is_authenticated:
            return login_manager.unauthorized()

        # Lấy role từ Mongo
        role = get_user_role()

        # Chỉ cho admin (hoặc quyền bạn quy ước) truy cập
        if role != "admin":
            # Có thể dùng abort(403) nếu muốn trả lỗi
            # return abort(403)
            return redirect(url_for("index"))  # hoặc trang dashboard của user thường

        return f(*args, **kwargs)
    return decorated_function
def get_search_and_backup():
    user_id = current_user.id
    doc = search_and_backup_collection.find_one({"user_id": user_id})
    
    if not doc or "searched_data" not in doc:
        return pd.DataFrame([])  # không có dữ liệu

    df = pd.DataFrame(doc["searched_data"])
    return df

def get_login_event():
    login_data = list(login_event_collection.find().sort("login_time", -1))
    df = pd.DataFrame(login_data)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df


def get_indicator():
    indicator = list(indicator_collection.find())
    df = pd.DataFrame(indicator)
    print(df)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df

#lấy ra df user
def get_white_list():
    white_list = list(white_list_collection.find())
    df = pd.DataFrame(white_list)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df
#lấy ra df relationship
def get_relationship():
    relationship = list(relationship_collection.find())
    df = pd.DataFrame(relationship)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df

#lấy ra df relationship
def get_malware():
    malware = list(malware_collection.find())
    df = pd.DataFrame(malware)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df

#lấy ra df relationship
def get_intrusion_set():
    intrusion = list(intrusion_set_collection.find())
    df = pd.DataFrame(intrusion)
    if "_id" in df.columns:
        df.drop(columns=["_id"], inplace=True)
    return df

def investigate_ip_stmnc(ip_str):
    indicator = indicator_collection.find_one({"url": {"$regex": ip_str}})
    if not indicator:
        return pd.DataFrame([{"Kết luận": f"Không tìm thấy indicator chứa IP {ip_str}"}])

    indicator_id = indicator["id"]
    results = {
        "IOC": ip_str,
        "Indicator ID": indicator_id,
        "Indicator description": indicator.get("description"),
        "Malware": [],
        "Campaign": [],
        "Intrusion Set": []
    }
    if "relationship" in db.list_collection_names():
        relationships = db["relationship"].find({"fromId": indicator_id})
        for rel in relationships:
            to_type = rel.get("toType")
            to_id = rel.get("toId")
            if to_type == "Malware":
                malware = malware_collection.find_one({"id": to_id})
                if malware:
                    results["Malware"].append(malware.get("name"))
            elif to_type == "Campaign":
                campaign = campaign_collection.find_one({"id": to_id})
                if campaign:
                    results["Campaign"].append(campaign.get("name"))
            elif to_type == "Intrusion-Set":
                actor = intrusion_set_collection.find_one({"id": to_id})
                if actor:
                    results["Intrusion Set"].append(actor.get("name"))
    else:
        results["Ghi chú"] = "Không có bảng stix_core_relationship"
    print(results)
    return pd.DataFrame([results])

def get_user_role():
    user_doc = user_collection.find_one({"username": current_user.id})
    if user_doc and "role" in user_doc:
        return user_doc["role"]
    return None


loop_active = False
user_path = "user.xlsx"
black_list_path = "black_list.xlsx"
miav_database_path = "miav_database.xlsx"
white_list_path= "white_list.xlsx"
chart_path = "chart.xlsx"
other_parameter_path = "parameter.xlsx"
ram_path = 'ram.xlsx'

is_login = False


def get_token():
    print("----vao ham get_token")
    LOGIN_URL = 'https://86.64.1.18/api/v1/auth/login'
    payload = {
        'username': 'admin',
        'password': 'Zxcvbnm!@#'
    }
    response = requests.post(LOGIN_URL, json=payload, verify=False)
    print("----", response)
    if response.status_code == 200:
        try:
            data = response.json()
            print(data['data'][0]['token'])
            return data['data'][0]['token']
        except Exception as e:
            print("[!] Không trích được token:", e)
            return None
    else:
        print("[✗] Đăng nhập thất bại:", response.status_code)
        return None

def get_token_2():
    print("----vao ham get_token")
    LOGIN_URL = 'https://86.64.1.18/api/v1/auth/login'
    payload = {
        'username': 'admin',
        'password': 'Zxcvbnm!@#'
    }

    try:
        response = requests.post(LOGIN_URL, json=payload, verify=False, timeout=5)  # timeout 5s
        print("----", response)

        if response.status_code == 200:
            try:
                data = response.json()
                print(data['data'][0]['token'])
                return data['data'][0]['token']
            except Exception as e:
                print("[!] Không trích được token:", e)
                return None
        else:
            print("[✗] Đăng nhập thất bại:", response.status_code)
            return None

    except requests.exceptions.RequestException as e:
        print("[!] Lỗi khi gửi yêu cầu:", e)
        return None


def get_event_data(token, start_date, end_date):
    url = "https://86.64.1.18/api/v1/events/paginate"
    params = {
        'skip': 0,
        'take': 40,
        'requireTotalCount': 'true,true',
        'sort': '[{"selector":"alert_type","desc":false}]',
        'filter': '["alert_type","=","Gray_ip"]',
        'totalSummary': '[{"selector":"mac","summaryType":"count"}]',
        'start_date': start_date,
    	'end_date': end_date,
        'unit_code': 'all'
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0'
    }
    response = requests.get(url, headers=headers, params=params, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print("[✗] Lỗi khi gửi request:", response.status_code)
        return None

def get_list(file_path):
	df = pd.read_excel(file_path)
	return df
@app.route('/', methods=['GET', 'POST'])
def default():
    return render_template('/sign-in.html')

def convert_df_to_dict(df):
    users = {}
    for _, row in df.iterrows():
        users[row['username']] = {'password': row['password']}
    return users

#def get_users():
#    df = pd.read_excel(user_path)
#    return df

# trang của viruscheck cũ
@app.route('/virus_check', methods=['GET', 'POST'])
@login_required
def virus_check():
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    df_normal = pd.DataFrame()
    df_malicious = pd.DataFrame()
    a = df_normal.shape[0]
    b = df_malicious.shape[0]
    return render_template('virus_check.html', black_list_new = black_list.to_string(index=False, header=False),white_list_new = white_list.to_string(index=False, header=False),df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), a=a, b=b)

@app.route('/ioc', methods=['GET', 'POST'])
@login_required
def ioc():
    indicator = get_indicator()
    indicator = indicator.fillna("N/A").replace("", "N/A")
    indicator_json = indicator.to_dict(orient='records')
    total_pages = (len(indicator) + 9) // 7
    first_page_data = indicator.iloc[:7]
    m = 7
    current_user_role = get_user_role()
    return render_template('ioc.html', indicator=first_page_data, total_pages=total_pages, current_page = 1, m = 7, current_user_role=current_user_role)

@app.route('/ioc_page', methods=['GET'])
@login_required
def ioc_page():
    current_page = int(request.args.get("page", 1))  # Lấy số trang từ URL
    indicator = get_indicator()
    indicator = indicator.fillna("N/A").replace("", "N/A")

    total_pages = (len(indicator) + 9) // 7  # Tính tổng số trang
    start = (current_page - 1) * 7  # Dòng bắt đầu
    end = start + 7  # Dòng kết thúc
    paginated_data = indicator.iloc[start:end]
    current_user_role = get_user_role()
    return render_template('ioc.html', indicator=paginated_data, total_pages=total_pages, current_page = current_page, m = 7, current_user_role=current_user_role)

@app.route('/delete_ioc', methods=['POST'])
@login_required
@admin_required
def delete_ioc():
    print("vao ham delete ioc")
    data = request.get_json()
    ioc_id = data.get("id")

    if not ioc_id:
        return jsonify({"success": False, "message": "Thiếu ID IOC!"}), 400

    result = indicator_collection.delete_one({"id": ioc_id})
    print("---------------------")
    print("ioc_id", ioc_id)

    if result.deleted_count == 0:
        return jsonify({"success": False, "message": "Không tìm thấy IOC để xóa!"}), 404

    return jsonify({"success": True, "message": "Xóa IOC thành công!"})

@app.route('/update_ioc_status', methods=['POST'])
@login_required
@admin_required   # hoặc bỏ nếu user thường được phép
def update_ioc_status():
    data = request.get_json() or {}
    ioc_id = data.get("id")
    status = (data.get("status") or "").lower()

    if not ioc_id or status not in ["online", "offline"]:
        return jsonify({"success": False})

    result = indicator_collection.update_one(
        {"id": ioc_id},
        {"$set": {"status": status}}
    )

    return jsonify({"success": result.matched_count == 1})



def relabel_all_search_and_backup(ioc_url):
    """
    Reset toàn bộ label=0 trước, rồi gắn lại label=1
    cho các bản ghi trùng IOC (mọi user).
    """

    # Bước 1: Reset tất cả label = 0
    search_and_backup_collection.update_many(
        {},
        {"$set": {"data.$[].label": 0, "searched_data.$[].label": 0}}
    )

    # Bước 2: Gán 1 cho các phần tử trùng IOC
    r1 = search_and_backup_collection.update_many(
        {"data": {"$elemMatch": {"$or": [
            {"ip": ioc_url},
            {"extracted_ip": ioc_url}
        ]}}},
        {"$set": {"data.$[e].label": 1}},
        array_filters=[{"$or": [
            {"e.ip": ioc_url},
            {"e.extracted_ip": ioc_url}
        ]}]
    )

    r2 = search_and_backup_collection.update_many(
        {"searched_data": {"$elemMatch": {"$or": [
            {"ip": ioc_url},
            {"extracted_ip": ioc_url}
        ]}}},
        {"$set": {"searched_data.$[e].label": 1}},
        array_filters=[{"$or": [
            {"e.ip": ioc_url},
            {"e.extracted_ip": ioc_url}
        ]}]
    )

    total = (r1.modified_count or 0) + (r2.modified_count or 0)
    print(f"[INFO] Reset toàn bộ label=0 và cập nhật {total} bản ghi trùng IOC.")
    return total

def relabel_existing_records(ioc_url):
    """Reset toàn bộ label=0, rồi gắn label=1 cho các bản ghi trùng IOC."""
    print(f"[INFO] Bắt đầu gắn nhãn cho {ioc_url}")

    # Reset label = 0 cho tất cả
    ram_collection.update_many({}, {"$set": {"label": 0}})

    # Gắn label = 1 cho record trùng extracted_ip
    matched = ram_collection.update_many(
        {"extracted_ip": ioc_url},
        {"$set": {"label": 1}}
    ).modified_count

    print(f"[INFO] Đã gắn label=1 cho {matched} bản ghi trùng IOC {ioc_url}.")
    return matched

@app.route('/add_ioc', methods=['GET', 'POST'])
@login_required
def add_ioc():
    print("vao ham add ioc")
    data = request.get_json()
    required_fields = [ "url"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"success": False, "message": f"Trường {field} không được để trống!"})
    generated_id = str(uuid.uuid4())
    ioc_data = {
        "id": generated_id,  
        "url": data["url"],
        "description": data["description"],
        "status": data.get("status", "N/A"),
        'reporter': current_user.id,  
        "threat": data.get("threat", "N/A"),
        "pattern": data.get("pattern", "N/A"),
        "valid_from": data.get("valid_from", "N/A"),
        "valid_until": data.get("valid_until", "N/A")
    }
    matched_count = relabel_existing_records(data["url"])
    matched_count = relabel_all_search_and_backup(data["url"])
    indicator_collection.insert_one(ioc_data)
    return jsonify({"success": True, "message": "Thêm mới mối đe dọa thành công!"})
        

@app.route('/reset_search', methods=['POST'])
@login_required
def reset_search():
    session.pop('search_mode', None)
    search_history_collection.delete_many({
        "user_id": current_user.id
    })
    return '', 204


@app.route('/monitor', methods=['GET', 'POST'])
@login_required
def monitor():
    if session.get('search_mode'):
        print("Có session của ", current_user.id)
        record = search_history_collection.find_one(
            {"user_id": current_user.id},
            sort=[("_id", -1)]  
        )
        if record and "data" in record:
            records = pd.DataFrame(record["data"])
        else:
            records = pd.DataFrame()
    else:
        print('Hết session')
        records = get_record()

    records = records.fillna("N/A").replace("", "N/A")
    total_pages = (len(records) + 7) // 7
    first_page_data = records.iloc[:7]
    a = len(records)
    current_user_role = get_user_role()
    return render_template('monitor.html', records=first_page_data, total_pages=total_pages, current_page = 1, a = a,current_user_role=current_user_role)

@app.route('/monitor_page', methods=['GET', 'POST'])
@login_required
def monitor_page():
    current_page = int(request.args.get("page", 1))

    if session.get('search_mode'):
        print("Có session của ", current_user.id)
        record = search_history_collection.find_one(
            {"user_id": current_user.id},
            sort=[("_id", -1)]  # bản mới nhất
        )
        if record and "data" in record:
            records = pd.DataFrame(record["data"])
        else:
            records = pd.DataFrame()
    else:
        print("Hết session ")
        records = get_record()

    records = records.fillna("N/A").replace("", "N/A")
    total_pages = (len(records) + 7) // 7 
    start = (current_page - 1) * 7  
    end = start + 7 
    paginated_data = records.iloc[start:end]
    current_user_role = get_user_role()
    return render_template('monitor.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7,current_user_role=current_user_role)


@app.route('/user_managerment', methods=['GET', 'POST'])
@login_required
@admin_required
def user_managerment():
    user_data = get_users()
    total_pages = (len(user_data) + 7) // 7
    first_page_data = user_data.iloc[:7]
    m = 7
    current_user_role = get_user_role()
    return render_template('user_managerment.html', records=first_page_data, total_pages=total_pages, current_page = 1, m = 7,current_user_role=current_user_role)

@app.route('/user_managerment_page', methods=['GET', 'POST'])
@login_required
@admin_required
def user_managerment_page():
    current_page = int(request.args.get("page", 1))  
    print(current_page)
    user_data = get_users()
    user_data = user_data.fillna("N/A").replace("", "N/A")

    total_pages = (len(user_data) + 7) // 7 
    start = (current_page - 1) * 7  
    end = start + 7 
    paginated_data = user_data.iloc[start:end]
    current_user_role = get_user_role()
    return render_template('user_managerment.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7,current_user_role=current_user_role)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    data = request.get_json()
    required_fields = ["username", "password", "unit", "role"]

    # Kiểm tra thiếu dữ liệu
    for field in required_fields:
        if field not in data or not data[field].strip():
            return jsonify({"success": False, "message": f"Trường {field} không được để trống!"})

    username = data["username"].strip()

    # KIỂM TRA username đã tồn tại chưa
    existed = user_collection.find_one({"username": username})
    if existed:
        return jsonify({
            "success": False,
            "message": "Người dùng đã tồn tại trong hệ thống!"
        })

    # Hash password
    hash_password = hashlib.sha256(data['password'].encode()).hexdigest()

    user_data = {
        "username": username,
        "password": hash_password,
        "unit_name": data["unit"],
        "create_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "role": data.get("role", "N/A")
    }

    user_collection.insert_one(user_data)

    return jsonify({"success": True, "message": "Thêm mới người dùng thành công!"})


@app.route('/delete_user', methods=['GET', 'POST'])

@login_required
@admin_required
def delete_user():
    data = request.get_json()
    username = data["username"]
    print(username)
    if not username:
        return jsonify({"success": False, "message": f"Có lỗi trong quá trình nhận dữ liệu!"})
    result = user_collection.delete_one({"username": data["username"]})
    return jsonify({"success": True, "message": "Thêm mới mối đe dọa thành công!"})


@app.route('/update_user', methods=['POST'])
@login_required
@admin_required
def update_user():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    unit = data.get("unit", "").strip()
    role = data.get("role", "").strip()

    if not username or not unit or not role:
        return jsonify({"success": False, "message": "Các trường không được để trống!"})

    result = user_collection.update_one(
        {"username": username},
        {"$set": {
            "unit_name": unit,
            "role": role
        }}
    )

    if result.matched_count == 0:
        return jsonify({"success": False, "message": "Không tìm thấy người dùng!"})

    return jsonify({"success": True, "message": "Cập nhật người dùng thành công!"})

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    update_chart()
    update_parameter_stats()
    records = get_record()
    #print(len(records))
    month_list, month_count = get_monthly_record_counts(records)
    df_1, df_2 = get_dashboard_parameter()
    df_1_json = df_1.to_dict(orient='records')
    #print(df_1)
    current_user_role = get_user_role()
    return render_template('index.html',df_1_json=df_1_json, df_2 = df_2, month_list = month_list, month_count = month_count, current_user_role=current_user_role)

def update_parameter_stats():
    total_query = ram_collection.count_documents({})
    total_detect = ram_collection.count_documents({"label": 1})
    total_ioc_db = malware_collection.count_documents({})
    parameter_collection.update_one(
        {},   # update bản ghi đầu tiên (vì bảng chỉ có 1 record)
        {
            "$set": {
                "query": total_query,
                "detect": total_detect,
                "ioc_db": total_ioc_db
            }
        },
        upsert=True  # nếu chưa có thì tự tạo record
    )

    return {
        "query": total_query,
        "detect": total_detect,
        "ioc_db": total_ioc_db
    }



def update_chart():
    df = get_record()
    # Nếu không có dữ liệu thì xóa chart cũ và thoát
    if df.empty or "mac" not in df.columns:
        chart_collection.delete_many({})
        return
    mac_counts = (
        df["mac"]
        .dropna()              # bỏ NaN
        .value_counts()        # đếm
        .head(10)              # top 10
    )

    # Chuẩn bị document để ghi vào Mongo
    docs = [
        {"ip": str(mac), "count": int(cnt)}   # dùng field 'ip' để frontend khỏi sửa
        for mac, cnt in mac_counts.items()
    ]

    # Ghi đè chart_collection
    chart_collection.delete_many({})
    if docs:
        chart_collection.insert_many(docs)


@app.route("/chart")
def chart():
    # Tạo DataFrame mẫu (bạn có thể thay bằng get_record())
    df = get_record()

    df_filtered = df[df["label"] == 1]

    data = df_filtered.apply(lambda row: [row["ip"], row["extracted_ip"]], axis=1).tolist()

    # Tạo danh sách node với màu sắc tương ứng
    internal_ips = df_filtered["ip"].unique().tolist()
    external_iocs = df_filtered["extracted_ip"].unique().tolist()

    nodes = []
    for ip in internal_ips:
        nodes.append({
            "id": ip,
            "marker": {
                "radius": 10,
                "fillColor": "#2AA775"  # Đỏ: nội bộ
            }
        })
    for ioc in external_iocs:
        nodes.append({
            "id": ioc,
            "marker": {
                "radius": 25,
                "fillColor": "#E8544E"  # Xanh: IOC
            }
        })
    current_user_role = get_user_role()
    return render_template("chart.html", data=data, nodes=nodes, current_user_role=current_user_role)

@app.route('/search_and_backup', methods=['GET', 'POST'])
@login_required
def search_and_backup():
    records = get_search_and_backup()
    records = records.fillna("N/A").replace("", "N/A")
    indicator_json = records.to_dict(orient='records')
    total_pages = (len(records) + 7) // 7
    first_page_data = records.iloc[:7]
    a = len(records)
    current_user_role = get_user_role()
    return render_template('search_and_backup.html', records=first_page_data, total_pages=total_pages, current_page = 1, a = a, current_user_role=current_user_role)

@app.route('/search_and_backup_page', methods=['GET', 'POST'])
@login_required
def search_and_backup_page():
    current_page = int(request.args.get("page", 1))  
    print(current_page)
    records = get_search_and_backup()
    records = records.fillna("N/A").replace("", "N/A")

    total_pages = (len(records) + 7) // 7 
    start = (current_page - 1) * 7  
    end = start + 7 
    paginated_data = records.iloc[start:end]
    current_user_role = get_user_role()
    return render_template('search_and_backup.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7, current_user_role=current_user_role)

@app.route('/search_keyword', methods=['POST'])
def search_keyword():
    data = request.get_json()
    keyword = data.get('keyword', '').lower()

    # Lấy document của người dùng hiện tại
    record = search_and_backup_collection.find_one({"user_id": current_user.id})

    if not record or "data" not in record:
        return jsonify({"success": False, "message": "Không tìm thấy dữ liệu để tìm kiếm."}), 404

    # Tìm kiếm trong 'data' gốc
    df = pd.DataFrame(record["data"])
    mask = df.apply(lambda row: row.astype(str).str.lower().str.contains(keyword).any(), axis=1)
    filtered_df = df[mask]

    # Cập nhật searched_data nếu có kết quả
    if len(filtered_df) > 0:
        search_and_backup_collection.update_one(
            {"user_id": current_user.id},
            {"$set": {"searched_data": filtered_df.to_dict(orient="records")}}
        )

    return jsonify({"success": True, "message": f"Tìm thấy {len(filtered_df)} bản ghi!"})

#def search_keyword():
#    data = request.get_json()
#    keyword = data.get('keyword', '').lower()

#    df = get_search_and_backup()  

#    mask = df.apply(lambda row: row.astype(str).str.lower().str.contains(keyword).any(), axis=1)
#    filtered_df = df[mask]
#    if (len(filtered_df) > 0):
#        overwrite_collection(filtered_df, 'search_and_backup')

#    return jsonify({"success": True, "message": f"Tìm thấy {len(filtered_df)} bản ghi!!!"})



def get_detail_from_ram(mac):
    record = get_record()
    matched_ram = record[record['mac'] == mac]

    if not matched_ram.empty:
        return matched_ram.iloc[0]['ip'], matched_ram.iloc[0]['unit_name']
    else:
        return 'Chưa xác định', 'Chưa xác định'
# trả về giá trị của status và threat, id của record trong indicator. nếu rỗng thì trả về Na na none, thường là sẽ có
def get_detail_from_indicator(ioc_ip):
    indicator = get_indicator()
    matched_indicators = indicator[indicator['url'].str.contains(ioc_ip, na=False)]
    if not matched_indicators.empty:
        return matched_indicators.iloc[0]['Status'],matched_indicators.iloc[0]['Threat'], matched_indicators.iloc[0]['id']
    else:
        return 'Chưa xác định', 'Chưa xác định', None

# từ indicator id lấy ra to ID ---- sau sẽ phải sửa
def get_malware_id_from_indicator_id(indicator_id):
    relationship = get_relationship()
    matched_row = relationship[relationship['fromId'] == indicator_id]
    if not matched_row.empty:
        to_id = matched_row.iloc[0]['toId']
        to_type = matched_row.iloc[0]['toType']
    else:
        to_id = None
        to_type = None
    return to_id, to_type

def get_detail_from_malware(to_id):
    malware = get_malware()
    matched_malware = malware[malware['id'] == to_id]
    if not matched_malware.empty:
       return matched_malware.iloc[0]['name'], matched_malware.iloc[0]['description']
    else:
        return "Chưa xác định", "Không có mô tả"

def get_intrusion_id_from_malware_id(malware_id):
    relationship = get_relationship()
    matched_relationship = relationship[relationship['fromId'] == malware_id]
    if not matched_relationship.empty:
        to_id = matched_relationship.iloc[0]['toId']
        to_type = matched_relationship.iloc[0]['toType']
    else:
        to_id = None
        to_type = None
    return to_id, to_type

def get_detail_from_intrusion_set(intrusion_set_id):
    intrusion_set = get_intrusion_set()
    matched_intrusion = intrusion_set[intrusion_set['id'] == intrusion_set_id]
    if not matched_intrusion.empty:
       return matched_intrusion.iloc[0]['name']
    else:
        return "Chưa xác định"

def get_information_for_detail(ioc_ip, mac):
    df = pd.DataFrame()
    df['ioc_ip'] = [ioc_ip]
    df['source_mac'] = [mac]
    df['source_ip'], df['unit_name'] = get_detail_from_ram(mac)
    df['status'], df['threat'], indicator_id = get_detail_from_indicator(ioc_ip)
    
    if indicator_id != None:
        malware_id, to_type = get_malware_id_from_indicator_id(indicator_id)
    else:
        malware_id = None
        to_type = None
    
    if malware_id != None:
        df['malware_name'], df['malware_description'] = get_detail_from_malware(malware_id)
    else:
        df['malware_name'], df['malware_description'] = "Chưa xác định", "Không có mô tả"
    
    df['malware_description'].fillna("Không có mô tả", inplace=True)          

    intrusion_id, to_type_2 = get_intrusion_id_from_malware_id(malware_id)
    print(intrusion_id)
    if intrusion_id != None:
        df['intrusion_name'] = get_detail_from_intrusion_set(intrusion_id)
    else:
        df['intrusion_name'] = "Chưa xác định"
    return df

@app.route('/detail/<ioc>/<mac>', methods=['GET', 'POST'])
def detail(ioc, mac):
    ioc_ip = ioc
    df = get_information_for_detail(ioc, mac)
    return render_template('/detail.html', df=df)



@app.route('/ip_upload', methods=['GET', 'POST'])
@login_required
def ip_upload():

    file_name = request.form.get('a')
    df_malicious, df_normal = check(file_name)

    a = df_normal.shape[0]
    b = df_malicious.shape[0]
    
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)

    black_list_new = pd.concat([black_list, df_malicious], ignore_index=True)
    white_list_new = pd.concat([white_list, df_normal], ignore_index=True)

    append_data_to_excel(black_list_new, white_list_new)
    #, df_malicious = df_malicious, df_normal = df_normal, black_list_new = black_list_new
    print(df_malicious)
    return render_template('virus_check.html', df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), black_list_new = black_list_new.to_string(index=False, header=False),white_list_new = white_list_new.to_string(index=False, header=False),a=a, b=b)

@app.route('/ip_upload_2', methods=['GET', 'POST'])
@login_required
def ip_upload_2():
    ip_list_json = request.form.get('ip_list', None)
    ip_list = json.loads(ip_list_json)
    df_ip = pd.DataFrame(ip_list, columns=['ip'])
    df_malicious, df_normal = check_2(df_ip)

    a = df_normal.shape[0]
    b = df_malicious.shape[0]

    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)

    black_list_new = pd.concat([black_list, df_malicious], ignore_index=True)
    white_list_new = pd.concat([white_list, df_normal], ignore_index=True)

    append_data_to_excel(black_list_new, white_list_new)
    return render_template('virus_check.html', df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), black_list_new = black_list_new.to_string(index=False, header=False),white_list_new = white_list_new.to_string(index=False, header=False),a=a, b=b)



def insert_dataframe(df):
    try:
        df = pd.DataFrame(df)
        records = df.to_dict(orient='records')
        if records:
            ram_collection.insert_many(records)
        return jsonify({"message": "Dữ liệu đã được thêm vào MongoDB!", "inserted": len(records)})
    except Exception as e:
        return jsonify({"error": str(e)})


def get_dashboard_parameter():
    df_1 = get_chart()
    df_1 = df_1.head(6)
    df_2 = get_parameter()
    return df_1, df_2

@app.route('/update_list', methods=['GET', 'POST'])
@login_required
def update_list():
    list_type = request.form.get('listType')   
    list_index = int(request.form.get('listIndex'))  
    ip_array_json = request.form.get('ips')    
    
    ip_array = pd.read_json(ip_array_json).values.flatten().tolist()

    df = pd.DataFrame(ip_array, columns=['ip'])
    black_list = get_database(black_list_path)
    white_list = get_database(white_list_path)
    print(df)
    print(black_list)
    if list_index == 0:
        black_list = pd.concat([black_list, df], ignore_index=True)
        black_list = black_list.drop_duplicates(subset=['ip'], keep='first', ignore_index=True)
    if list_index == 1:
        white_list = pd.concat([white_list, df], ignore_index=True)
        white_list = white_list.drop_duplicates(subset=['ip'], keep='first', ignore_index=True)
    append_data_to_excel(black_list, white_list)       
    return redirect(url_for('virus_check'))

@app.route('/search_history_goc', methods=['GET', 'POST'])
@login_required
def search_history_goc():
    date_1 = request.form.get('date_1')
    date_2 = request.form.get('date_2')

    ssh_host = "86.64.60.71"
    ssh_port = 22
    ssh_user = 'root'
    ssh_password = 'P52abc@123456'

    mongo_host = 'localhost.localdomain'
    mongo_port = 27017
    mongo_db = 'fms_v3'
    mongo_collection = 'events'

    before_start = '2024-08-19 23:59:59'
    start_time = '2024-08-18 00:00:00'
    filter,name = get_filter(date_1, date_2)

    #result1 = get_mongo_data(ssh_host, ssh_port, ssh_user, ssh_password, mongo_host, mongo_port, mongo_db, mongo_collection, filter, sample_size=10)
    #df = raw_to_df_goc(result1)
    #df = pd.DataFrame(df)
    df = pd.read_excel(r'2024-08-19-2024-08-20-records.xlsx')   
    df_white_list = get_white_list()
    rule = df_white_list['ip'].tolist()
    df_filtered = filtering_2(df, rule)
    df_filtered_2 = match_miav_database(df_filtered)
    session['search_mode'] = True
    #print(df_filtered_2)
    #update_other_parameter(len(df), 'query')
    #update_chart_parameter(df_filtered)
    count = len(df_filtered)
    #update_other_parameter(count, 'detect')
    print(f"There are {count} alert for 300s from {before_start} to {start_time}")
    if len(df_filtered_2) > 0:

        record_to_insert = {
            "user_id": current_user.id,
            "data": df_filtered_2.to_dict(orient="records")
        }
        search_history_collection.insert_one(record_to_insert)
    return '1'



@app.route('/search_history', methods=['GET', 'POST']) 
@login_required

# Hàm search_history dùng cho việc gửi request đến FMS, lấy token, đọc response - hoạt động tốt

# def search_history():
#     print("vao ham")
#     date_1 = request.form.get('date_1')
#     date_2 = request.form.get('date_2')
#     token = get_token()
#     if not token:
#         print("[!] Không lấy được token, chờ 10s rồi thử lại...")
#         return '1'
#     start_str = date_1
#     end_str = date_2
#     raw_data = get_event_data(token, start_str, end_str)
#     print(raw_data)
#     if raw_data is None:
#         print('data is none')
#         return '1'
#     df = raw_to_df(raw_data)
#     df_white_list = get_white_list()
#     rule = df_white_list['ip'].tolist()
#     df_filtered = filtering_2(df, rule)
#     df_filtered_2 = match_miav_database(df_filtered)
#     session['search_mode'] = True
#     count = len(df_filtered)
#     print(f"There are {count} alert for 300s from {date_1} to {date_2}")
#     print('count')
#     if len(df_filtered_2) > 0:

#         record_to_insert = {
#             "user_id": current_user.id,
#             "data": df_filtered_2.to_dict(orient="records")
#         }
#         search_history_collection.insert_one(record_to_insert)
#     return '1'
def search_history_records():
    """Tìm kiếm bản ghi trong ram_collection theo khoảng thời gian."""
    date_1 = request.form.get('date_1')
    date_2 = request.form.get('date_2')

    if not date_1 or not date_2:
        return jsonify({"success": False, "message": "Thiếu thông tin thời gian tìm kiếm"}), 400

    try:
        start_dt = datetime.strptime(date_1, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(date_2, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return jsonify({"success": False, "message": "Sai định dạng thời gian (YYYY-MM-DD HH:MM:SS)"}), 400

    # Tìm trong MongoDB (ram_collection)
    query = {"time_receive": {"$gte": date_1, "$lte": date_2}}
    result = list(ram_collection.find(query, {"_id": 0}))

    if not result:
        return jsonify({"success": True, "message": "Không có bản ghi trong khoảng thời gian này", "count": 0})

    # Lưu lại kết quả tìm kiếm vào collection search_history
    session['search_mode'] = True
    record_to_insert = {
        "user_id": current_user.id,
        "data": result
    }
    search_history_collection.insert_one(record_to_insert)

    return jsonify({
        "success": True,
        "message": f"Tìm thấy {len(result)} bản ghi trong khoảng {date_1} - {date_2}",
        "count": len(result)
    })



@app.route("/export_file", methods=["GET"])
def export_file():
    print("aaaaaaaaaaaaaa---------------")
    print(current_user.id)
    try:
        data = list(ram_collection.find({}, {"_id": 0}))
        return jsonify({
            "success": True,
            "message": "Xuất file thành công",
            "data": data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Lỗi khi xuất dữ liệu: {str(e)}"
        }), 500


@app.route("/import_file", methods=["POST"])
def import_file():
    required_fields = [
        "alert_level_id", "alert_type", "description", "extracted_ip",
        "ip", "label", "mac", "time_receive",
        "unit_full_name", "unit_name", "user_name"
    ]

    if 'file' not in request.files:
        return jsonify({
            "success": False,
            "message": "Chưa có file được gửi lên."
        }), 400

    file = request.files['file']

    try:
        data = json.load(file)

        if not isinstance(data, list):
            return jsonify({
                "success": False,
                "message": "Dữ liệu JSON phải là danh sách các bản ghi."
            }), 400

        # Kiểm tra từng bản ghi có đầy đủ trường bắt buộc không
        for i, record in enumerate(data):
            missing = [field for field in required_fields if field not in record]
            if missing:
                return jsonify({
                    "success": False,
                    "message": f"Bản ghi thứ {i+1} thiếu: {', '.join(missing)}"
                }), 400

        # Nếu hợp lệ, xóa dữ liệu cũ của user
        search_and_backup_collection.delete_many({"user_id": current_user.id})

        # Tạo document mới theo format 3 trường
        file_record = {
            "user_id": current_user.id,
            "data": data,
            "searched_data": data  # ban đầu giống hệt bản gốc
        }

        search_and_backup_collection.insert_one(file_record)

        return jsonify({
            "success": True,
            "message": "Import thành công và dữ liệu đã lưu.",
            "count": len(data)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Lỗi xử lý file: {str(e)}"
        }), 500


@app.route('/login_event', methods=['GET', 'POST'])
@login_required
@admin_required
def login_event():
    logs = get_login_event()
    logs = logs.fillna("N/A").replace("", "N/A")

    total_pages = (len(logs) + 9) // 7   # giữ cách tính như ioc
    first_page_data = logs.iloc[:7]
    m = 7
    current_user_role = get_user_role()

    return render_template(
        'login_event.html',
        records=first_page_data,        # trong template: for index, row in records.iterrows()
        total_pages=total_pages,
        current_page=1,
        m=m,
        current_user_role=current_user_role
    )

@app.route('/login_event_page', methods=['GET'])
@login_required
@admin_required
def login_event_page():
    current_page = int(request.args.get("page", 1))
    print(current_page)

    logs = get_login_event()
    logs = logs.fillna("N/A").replace("", "N/A")

    total_pages = (len(logs) + 9) // 7
    print("------------------------")
    print(total_pages)
    start = (current_page - 1) * 7
    end = start + 7
    paginated_data = logs.iloc[start:end]
    m = 7
    current_user_role = get_user_role()

    return render_template(
        'login_event.html',
        records=paginated_data,
        total_pages=total_pages,
        current_page=current_page,
        m=m,
        current_user_role=current_user_role
    )


def import_file_2():
    required_fields = [
        "alert_level_id", "alert_type", "description", "extracted_ip",
        "ip", "label", "mac", "time_receive",
        "unit_full_name", "unit_name", "user_name"
    ]

    if 'file' not in request.files:
        return jsonify({
            "success": False,
            "message": "Chưa có file được gửi lên."
        }), 400

    file = request.files['file']

    try:
        data = json.load(file)
        print(type(data))
        df_data = pd.DataFrame(data)
        if not isinstance(data, list):
            return jsonify({
                "success": False,
                "message": "Dữ liệu JSON phải là danh sách các bản ghi."
            }), 400

        for i, record in enumerate(data):
            missing = [field for field in required_fields if field not in record]
            if missing:
                return jsonify({
                    "success": False,
                    "message": f"Bản ghi thứ {i+1} không đúng định dạng! Trường: {', '.join(missing)}"
                }), 400

        print("Dữ liệu import hợp lệ:")
        overwrite_collection(df_data, 'search_and_backup')

        return jsonify({
            "success": True,
            "message": "Dữ liệu hợp lệ và đã được xử lý.",
            "count": len(data)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Lỗi xử lý file: {str(e)}"
        }), 500

def overwrite_collection(df, collection_name):
    collection = db[collection_name]
    collection.delete_many({})
    df = pd.DataFrame(df)
    records = df.to_dict(orient='records')
    if records:
        collection.insert_many(records)
    return ''

def get_monthly_record_counts(df):
    df["time_receive"] = pd.to_datetime(df["time_receive"])
    today = datetime.today()
    months = [(today - timedelta(days=30*i)).strftime("%m/%Y") for i in range(12)]
    months.reverse()  
    df["Month_Year"] = df["time_receive"].dt.strftime("%m/%Y")
    record_counts = [df[df["Month_Year"] == month].shape[0] for month in months]
    return months, record_counts


def delete_collection(collection):
    collection = db[collection] 
    collection.drop()


def update_chart_parameter(df_new):
    df = pd.read_excel(chart_path)
    for index, row in df_new.iterrows():
        ip = row['ip']
        if ip in df['ip'].values:
            df.loc[df['ip'] == ip, 'count'] += 1
        else:
            df = pd.concat([df, pd.DataFrame([[ip, 1]], columns=['ip', 'count'])], ignore_index=True)
    df = df.sort_values(by='count', ascending=False)
    df.to_excel(chart_path, index=False)


def update_other_parameter(a, b):
    df = pd.read_excel(other_parameter_path)
    if b in df.columns:
        df.at[0, b] += a
    else:
        print(f"Cột '{b}' không tồn tại trong DataFrame.")
    df.to_excel(other_parameter_path, index=False)


def get_user(file_path):
	df = pd.read_excel(file_path)
	df.columns = ['user']
	return df   

def check(file_name):
    new_ip_list = get_unique_ip_list(file_name)
    api_key = '991b2155df7d9dc2dad646878f5ba4892163d9ccf6b573c68d5afedbcf8f00be'
    df_to_check = pd.DataFrame(new_ip_list, columns=['ip'])
    df_result = auto_check_virus_total(df_to_check, api_key)
    df_malicious = df_result[df_result['check_result'] != 0]
    df_normal = df_result[df_result['check_result'] == 0]
    print(df_malicious)
    return pd.DataFrame(df_malicious['ip']), pd.DataFrame(df_normal['ip'])

def check_2(df):
    new_ip_list = get_unique_ip_list_2(df)
    api_key = '991b2155df7d9dc2dad646878f5ba4892163d9ccf6b573c68d5afedbcf8f00be'
    df_to_check = pd.DataFrame(new_ip_list, columns=['ip'])
    df_result = auto_check_virus_total(df_to_check, api_key)
    df_malicious = df_result[df_result['check_result'] != 0]
    df_normal = df_result[df_result['check_result'] == 0]
    return pd.DataFrame(df_malicious['ip']), pd.DataFrame(df_normal['ip'])

def auto_check_virus_total(df_a, api_key):
    results = []
    for item in df_a['ip'].tolist():
        result = check_virus_total(item, api_key)
        results.append({
            'ip': item,
            'check_result': result
        })
    return pd.DataFrame(results)

def check_virus_total(item, api_key):
    url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if item.count('.') == 3 else 'domains'}/{item}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        a = response.json()
        return a['data']['attributes']['last_analysis_stats']['malicious']
    else:
        return None


def get_unique_ip_list(file_name):
    ip_list = get_list(file_name)
    ip_list = ip_list['ip'].tolist()
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    new_ip_list = [ip for ip in ip_list if ip not in black_list and ip not in white_list]
    return new_ip_list

def get_unique_ip_list_2(ip_list):
    ip_list = ip_list['ip'].tolist()
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    new_ip_list = [ip for ip in ip_list if ip not in black_list and ip not in white_list]
    update_other_parameter(len(new_ip_list), 'ioc_db')
    return new_ip_list



def append_data_to_excel(black_list, white_list):
    black_list = pd.DataFrame(black_list)
    white_list = pd.DataFrame(white_list)
    black_list.to_excel(black_list_path, index=False)
    white_list.to_excel(white_list_path, index=False)
    return 0






def get_database(file_path):
	df = pd.read_excel(file_path)
	df.columns = ['ip']
	return df

def filtering(df, list):
    df_filtered = pd.DataFrame(columns = df.columns)
    for _,row in df.iterrows():
        a = row
        if str(a['alert_type']) == "Gray_ip" or str(a['alert_type']) == "Gray_domain":
            if any(key in str(a['description']) for key in list):
                df_filtered = df_filtered._append(a, ignore_index = True)
    return df_filtered
# Hàm filtering2, bỏ các white record, giữ lại black và gray
def filtering_2(df, list):
	df_filtered = pd.DataFrame(columns = df.columns)
	for _,row in df.iterrows():
		a = row
		if not any(key in str(a['description']) for key in list):
			df_filtered = df_filtered._append(a, ignore_index = True)
	return df_filtered

def match_miav_database(df_filtered):
    miav_database_df = get_miav_database()
    miav_ip_list = miav_database_df['IP'].tolist()

    df_filtered['extracted_ip'] = df_filtered['description'].str.replace("connect to ", "", regex=False)

    def check_match(value):
        return 1 if value in miav_ip_list else 0
    df_filtered['label'] = df_filtered['extracted_ip'].apply(check_match)
    print(df_filtered)
    return df_filtered
    


def get_filter(formatted_date_1, formatted_date_2):
	filter = {"time_receive":{"$gte": formatted_date_1,"$lte": formatted_date_2 }}
	name = str(formatted_date_1) + '-' + str(formatted_date_2)
	return filter,name

def raw_to_df_goc(result):
	data = {'mac': [],'IP': [],'unit_name': [],'user_name': [],'unit_full_name': [],'alert_type': [],'alert_level_id': [], 'time_receive': [],'description': []}
	for record in result:
		data['mac'].append(str(record['mac']))
		data['IP'].append(str(record['ip']))
		data['unit_name'].append(str(record['unit_full_name']))
		data['user_name'].append(str('Chua dinh danh'))
		data['unit_full_name'].append(str(record['unit_full_name']))
		data['alert_type'].append(str(record['alert_type']))
		data['alert_level_id'].append(str(record['alert_level_id']))
		data['time_receive'].append(str(record['time_receive']))
		data['description'].append(str(record.get('alert_info', {}).get('description', 'No description available')))
	df = pd.DataFrame(data)
	return df

def get_mongo_data(ssh_host, ssh_port, ssh_user, ssh_password, mongo_host, mongo_port, mongo_db, mongo_collection, filter, sample_size=10):
	print('start 1')
	with SSHTunnelForwarder((ssh_host, ssh_port),
	ssh_username=ssh_user,
	ssh_password=ssh_password,
	
	remote_bind_address=(mongo_host, mongo_port)
	) as tunnel:
		client = MongoClient('127.0.0.1', tunnel.local_bind_port)
		db = client[mongo_db]
		collection = db[mongo_collection]
		result = list(collection.find(filter).limit(100000))	
	print('done 1')
	return result

def insert_with_limit_ram(data_list, limit=500000):
    current_count = ram_collection.count_documents({})
    insert_count = len(data_list)
    excess = (current_count + insert_count) - limit
    if excess > 0:
        ram_collection.delete_many({}, limit=excess, sort=[("time_receive", 1)])
    ram_collection.insert_many(data_list)


def insert_with_limit_search(data_list, limit=500000):
    current_count = search_history_collection.count_documents({})
    insert_count = len(data_list)
    excess = (current_count + insert_count) - limit
    if excess > 0:
        search_history_collection.delete_many({}, limit=excess, sort=[("time_receive", 1)])
    search_history_collection.insert_many(data_list)

def core_goc():
    ssh_host = "86.64.60.71"
    ssh_port = 22
    ssh_user = 'root'
    ssh_password = 'P52abc@123456'  

    mongo_host = 'localhost.localdomain'
    mongo_port = 27017
    mongo_db = 'fms_v3'
    mongo_collection = 'events'
    database_path = white_list_path
    a = 1
    global loop_active
    while loop_active:
        start_time = datetime.now()		
        before_start = start_time - timedelta(minutes=1)
        filter,name = get_filter(before_start.strftime("%Y-%m-%d %H:%M:%S"), start_time.strftime("%Y-%m-%d %H:%M:%S"))
        #result1 = get_mongo_data(ssh_host, ssh_port, ssh_user, ssh_password, mongo_host, mongo_port, mongo_db, mongo_collection, filter, sample_size=10)
        #df = raw_to_df(result1)
        #df = pd.DataFrame(df)
        df = pd.read_excel(r'2024-08-19-2024-08-20-records.xlsx')   
        df_white_list = get_white_list()
        rule = df_white_list['ip'].tolist()
        df_filtered = filtering_2(df, rule)
        df_filtered_2 = match_miav_database(df_filtered)
        #print(df_filtered_2)
        #update_other_parameter(len(df), 'query')
        #update_chart_parameter(df_filtered)
        count = len(df_filtered)
        #update_other_parameter(count, 'detect')
        print(f"There are {count} alert for 300s from {before_start} to {start_time}")
        if len(df_filtered_2) > 0:
            records_to_insert = df_filtered_2.to_dict(orient="records")
            insert_with_limit_ram(records_to_insert)
        a = a + 1
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        sleep_time =  max(0, (timedelta(seconds=60) - elapsed_time).total_seconds())
        time.sleep(sleep_time)
        data = df_filtered_2.to_json(orient='records')
        if loop_active:
            socketio.emit('new_data', data)

def raw_to_df(response_json):
    records = response_json.get("data", {}).get("event", [])
    data = {
        'mac': [],
        'ip': [],
        'unit_name': [],
        'user_name': [],
        'unit_full_name': [],
        'alert_type': [],
        'alert_level_id': [],
        'time_receive': [],
        'description': []
    }
    for record in records:
        data['mac'].append(str(record.get('mac', '')))
        data['IP'].append(str(record.get('ip', '')))
        data['unit_name'].append(str(record.get('unit_full_name', '').split(' - ')[0]))
        data['user_name'].append("Chua dinh danh")
        data['unit_full_name'].append(str(record.get('unit_full_name', '')))
        data['alert_type'].append(str(record.get('alert_type', '')))
        data['alert_level_id'].append(str(record.get('alert_level_id', '')))
        data['time_receive'].append(str(record.get('time_receive', '')))
        data['description'].append(
            str(record.get('alert_info', {}).get('description', 'No description available'))
        )

    return pd.DataFrame(data)



def core():
    global loop_active
    print(loop_active)
    while loop_active:
        start_time = datetime.now() - timedelta(minutes=10)
        before_start = start_time - timedelta(minutes=1)
        token = get_token()
        if not token:
            print("[!] Không lấy được token, chờ 10s rồi thử lại...")
            continue

        start_str = before_start.strftime("%Y-%m-%d %H:%M:%S")
        end_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        raw_data = get_event_data(token, start_str, end_str)

        if raw_data is None:
            time.sleep(10)
            continue
        df = raw_to_df(raw_data)
        df_white_list = get_white_list()
        rule = df_white_list['ip'].tolist()
        df_filtered = filtering_2(df, rule)
        count = len(df_filtered)
        df_filtered_2 = match_miav_database(df_filtered)
        print(f"There are {count} alert for 300s from {before_start} to {start_time}")
        if len(df_filtered_2) > 0:
            records_to_insert = df_filtered_2.to_dict(orient="records")
            insert_with_limit_ram(records_to_insert)
        a = a + 1
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        sleep_time =  max(0, (timedelta(seconds=60) - elapsed_time).total_seconds())
        time.sleep(sleep_time)

@app.route('/start', methods=['GET', 'POST'])
@login_required
def start():
    global loop_active
    if not loop_active:
        loop_active = True
        print("start")
        processing_thread = threading.Thread(target=core)
        processing_thread.daemon = True
        processing_thread.start()
        return '1'
    return '0'

def generate_data():
    global loop_active
    print("vào hàm lặp")
    while loop_active:
        print("Lặp")
        time.sleep(2)
        new_data = {
            'Name': ['Row 1'],
            'Status': ['pending']
        }
        df = pd.DataFrame(new_data)
        data = df.to_json(orient='records')
        socketio.emit('new_data', data)
        print(data)


@app.route('/end', methods=['GET', 'POST'])
@login_required
def end():
    print("vào end")
    global loop_active
    loop_active = False 
    return redirect(url_for('monitor'))



def append_record_to_ram(path, df_filtered):
    df_1 = pd.read_excel(path)
    df_1 = pd.concat([df_1, df_filtered], ignore_index=True)
    df_1.to_excel(path, index=False)
    return 0
def reset_ram():
    df = pd.read_excel(ram_path)  
    empty_df = pd.DataFrame(columns=df.columns)
    empty_df.to_excel(ram_path, index=False)
    return 0

# đây là cho login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = convert_df_to_dict(get_users())

#users = {'a': {'password': 'a'}}
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None
def convert_password(plain_text):
    hashed_password = hashlib.sha256(plain_text.encode()).hexdigest()
    return hashed_password

def log_login_event(username, status):
    """Ghi lại log đăng nhập / đăng xuất vào collection login_event"""

    ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("-------------------------")
    print(current_time)

    login_event_collection.insert_one({
        "username": username,
        "ip": ip,
        "time": current_time,
        "status": status,        # success / failed / logout
        "user_agent": user_agent
    })

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    hash_hex = hashlib.sha256(password.encode()).hexdigest()

    if email in users and users[email]['password'] == hash_hex:
        user = User(email)
        login_user(user)

        # Ghi log đăng nhập thành công
        log_login_event(email, "Đăng nhập thành công")

        return jsonify({'status': 'success', 'message': 'Đăng nhập thành công'})
    else:
        # Ghi log đăng nhập thất bại
        log_login_event(email, "Đăng nhập thất bại")

        return jsonify({'status': 'error', 'message': 'Email hoặc mật khẩu không đúng'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    username = current_user.id           # lấy username đang đăng nhập
    log_login_event(username, "Đăng xuất")  # ghi log logout

    session.clear()
    logout_user()

    return jsonify({'status': 'success', 'message': 'Đăng xuất thành công'})

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "Mật khẩu cũ và mật khẩu mới không được để trống!"}), 400

    username = current_user.id  # key trong users và field 'username' trong Mongo

    # Lấy user từ DB
    user_doc = user_collection.find_one({"username": username})
    if not user_doc:
        return jsonify({"success": False, "message": "Không tìm thấy người dùng!"}), 404

    old_hash = hashlib.sha256(old_password.encode()).hexdigest()

    if user_doc.get("password") != old_hash:
        return jsonify({"success": False, "message": "Mật khẩu cũ không chính xác!"}), 400

    new_hash = hashlib.sha256(new_password.encode()).hexdigest()

    # Cập nhật vào MongoDB
    user_collection.update_one(
        {"username": username},
        {"$set": {"password": new_hash}}
    )

    # Cập nhật vào cache 'users' dùng cho login()
    if username in users:
        users[username]["password"] = new_hash
    username = current_user.id           # lấy username đang đăng nhập
    log_login_event(username, "Đổi mật khẩu")  # ghi log logout
    return jsonify({"success": True, "message": "Đổi mật khẩu thành công!"})


@app.route('/protected')
@login_required
def protected():
    return f'Logged in as: {current_user.id}'


@app.route("/export_report", methods=["POST"])
def export_report():
    username = current_user.id           # lấy username đang đăng nhập
    log_login_event(username, "Xuất báo cáo")

    start = request.form.get("from")
    end   = request.form.get("to")

    stats = compute_report_stats(start, end)
    if not stats:
        return "Không có dữ liệu trong ram_collection", 400

    template_path = os.path.join(app.root_path, "templates", "report_templates.docx")
    doc = DocxTemplate(template_path)

    most_source_display = f"{stats['most_source_mac']} - {stats['most_source_name']} - {stats['most_source_unit']}"

    context = {
        "start_date":      start,
        "end_date":        end,
        "total_count":     stats["total_count"],
        "abnormal_count":  stats["abnormal_count"],
        "benign_count":    stats["benign_count"],
        "most_source":     most_source_display,
        "most_destination": stats["most_destination"],
        "most_source_mac":  stats["most_source_mac"],
        "most_source_name": stats["most_source_name"],
        "most_source_unit": stats["most_source_unit"],
        "quankhu_count":    stats["quankhu_count"],
        "quandoan_count":   stats["quandoan_count"],
        "trungtam_count":   stats["trungtam_count"],
        "congbinh_count":   stats["congbinh_count"],
        "thongtin_count":   stats["thongtin_count"],
        "bienphong_count":  stats["bienphong_count"],
        "daccong_count":    stats["daccong_count"],
        "khongquan_count":  stats["khongquan_count"],
        "haiquan_count":    stats["haiquan_count"],
        "botong_count":     stats["botong_count"],

        # THÊM CÁC TRƯỜNG % Ở ĐÂY
        "abnormal_percent":  stats["abnormal_percent"],
        "benign_percent":    stats["benign_percent"],
        "quankhu_percent":   stats["quankhu_percent"],
        "quandoan_percent":  stats["quandoan_percent"],
        "trungtam_percent":  stats["trungtam_percent"],
        "congbinh_percent":  stats["congbinh_percent"],
        "thongtin_percent":  stats["thongtin_percent"],
        "bienphong_percent": stats["bienphong_percent"],
        "daccong_percent":   stats["daccong_percent"],
        "khongquan_percent": stats["khongquan_percent"],
        "haiquan_percent":   stats["haiquan_percent"],
        "botong_percent":    stats["botong_percent"],
    }

    doc.render(context)

    temp_dir = tempfile.mkdtemp()
    docx_path = os.path.join(temp_dir, "report.docx")
    doc.save(docx_path)

    return send_file(docx_path, as_attachment=True, download_name="baocao.docx")

def compute_report_stats(start_date, end_date):
    query = {}
    if start_date and end_date:
        query["time_receive"] = {"$gte": start_date, "$lte": end_date}
    elif start_date:
        query["time_receive"] = {"$gte": start_date}
    elif end_date:
        query["time_receive"] = {"$lte": end_date}

    ram_data = list(ram_collection.find(query).sort("time_receive", -1))
    df = pd.DataFrame(ram_data)
    device_df = get_device()

    # Nếu không có dữ liệu → trả toàn bộ 0 và chuỗi "0.00 %"
    if df.empty:
        return {
            "total_count": 0,
            "abnormal_count": 0,
            "benign_count": 0,
            "most_source_mac": "Không có dữ liệu",
            "most_source_name": "Không có dữ liệu",
            "most_source_unit": "Không có dữ liệu",
            "most_destination": "Không có dữ liệu",
            "quankhu_count": 0,
            "quandoan_count": 0,
            "trungtam_count": 0,
            "congbinh_count":0,
            "thongtin_count": 0,
            "bienphong_count": 0,
            "daccong_count": 0,
            "khongquan_count": 0,
            "haiquan_count": 0,
            "botong_count": 0,


            # Luôn trả về string "0.00 %"
            "abnormal_percent": "0.00 %",
            "benign_percent": "0.00 %",
            "quankhu_percent": "0.00 %",
            "quandoan_percent": "0.00 %",
            "trungtam_percent": "0.00 %",
            "congbinh_percent": "0.00 %",
            "thongtin_percent": "0.00 %",
            "bienphong_percent": "0.00 %",
            "daccong_percent": "0.00 %",
            "khongquan_percent": "0.00 %",
            "haiquan_percent": "0.00 %",
            "botong_percent": "0.00 %",
        }

    total_count    = len(df)
    abnormal_count = (df["label"] == 1).sum()
    benign_count   = (df["label"] == 0).sum()

    def pct(x):
        return f"{round(x * 100.0 / total_count, 2):.2f} %" if total_count > 0 else "0.00 %"

    # Máy có nhiều bản ghi nhất
    most_source_mac = None
    most_source_name = "Chưa xác định"
    most_source_unit = "Chưa xác định"

    if "mac" in df.columns and not df["mac"].isna().all():
        most_source_mac = df["mac"].value_counts().idxmax()
        if not device_df.empty and "mac" in device_df.columns:
            matched = device_df[device_df["mac"] == most_source_mac]
            if not matched.empty:
                row = matched.iloc[0]
                most_source_name = row.get("device_name", "Chưa xác định")
                most_source_unit = row.get("unit_full_name", "Chưa xác định")

    # IP đích nhiều nhất
    most_destination = "Chưa xác định"
    if "extracted_ip" in df.columns and not df["extracted_ip"].isna().all():
        most_destination = df["extracted_ip"].value_counts().idxmax()

    # Đếm theo đơn vị
    unit_series = df["unit_full_name"].fillna("") if "unit_full_name" in df.columns else pd.Series([])

    quankhu_count  = unit_series.str.contains("quân khu 5",  case=False, na=False).sum()
    quandoan_count = unit_series.str.contains("quân đoàn",  case=False, na=False).sum()
    trungtam_count = unit_series.str.contains("386",        case=False, na=False).sum()
    congbinh_count = unit_series.str.contains("công binh",  case=False, na=False).sum()
    thongtin_count = unit_series.str.contains("thông tin",  case=False, na=False).sum()
    bienphong_count= unit_series.str.contains("biên phòng", case=False, na=False).sum()
    daccong_count  = unit_series.str.contains("đặc công",   case=False, na=False).sum()
    khongquan_count= unit_series.str.contains("không quân", case=False, na=False).sum()
    haiquan_count  = unit_series.str.contains("hải quân",   case=False, na=False).sum()
    botong_count   = unit_series.str.contains("bộ tổng",    case=False, na=False).sum()

    return {
        "total_count": total_count,
        "abnormal_count": abnormal_count,
        "benign_count": benign_count,

        "most_source_mac": most_source_mac,
        "most_source_name": most_source_name,
        "most_source_unit": most_source_unit,
        "most_destination": most_destination,

        "quankhu_count": quankhu_count,
        "quandoan_count": quandoan_count,
        "trungtam_count": trungtam_count,
        "congbinh_count":congbinh_count,
        "thongtin_count": thongtin_count,
        "bienphong_count": bienphong_count,
        "daccong_count": daccong_count,
        "khongquan_count": khongquan_count,
        "haiquan_count": haiquan_count,
        "botong_count": botong_count,

        # Luôn trả string dạng "xx.xx %"
        "abnormal_percent": pct(abnormal_count),
        "benign_percent": pct(benign_count),
        "quankhu_percent": pct(quankhu_count),
        "quandoan_percent": pct(quandoan_count),
        "trungtam_percent": pct(trungtam_count),
        "congbinh_percent": pct(congbinh_count),
        "thongtin_percent": pct(thongtin_count),
        "bienphong_percent": pct(bienphong_count),
        "daccong_percent": pct(daccong_count),
        "khongquan_percent": pct(khongquan_count),
        "haiquan_percent": pct(haiquan_count),
        "botong_percent": pct(botong_count),
    }



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
#investigate_ip_stmnc('45.125.66.56')
#print(get_relationship())


#chuyen core thành core_goc
#chuyen raw_to_df thành raw_to_df_goc
# chuyen raw_to_df trong search_history