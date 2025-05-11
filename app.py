from flask import Flask, render_template, request, flash
from flask import jsonify
import pandas as pd
import time
import json
from datetime import datetime, timedelta
from collections import Counter
import hashlib
import requests
import threading
from flask import redirect, url_for, Response, stream_with_context
from flask_socketio import SocketIO, emit
from sshtunnel import SSHTunnelForwarder
from pymongo import MongoClient
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = "your_secret_key"  
socketio = SocketIO(app)

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

indicator_collection = db["indicator"]
relationship_collection = db["relationship"]
malware_collection = db["malware"]
campaign_collection = db["campaign"]
intrusion_set_collection = db["intrusion_set"]


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
    ram_data = list(ram_collection.find())
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

#def get_search_and_backup():
#    search_and_backup_data = list(search_and_backup_collection.find())
#    df = pd.DataFrame(search_and_backup_data)
#    if "_id" in df.columns:
#        df.drop(columns=["_id"], inplace=True)
#    return df
def get_search_and_backup():
    user_id = current_user.id
    doc = search_and_backup_collection.find_one({"user_id": user_id})
    
    if not doc or "searched_data" not in doc:
        return pd.DataFrame([])  # không có dữ liệu

    df = pd.DataFrame(doc["searched_data"])
    return df


def get_indicator():
    indicator = list(indicator_collection.find())
    df = pd.DataFrame(indicator)
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
        "Indicator Description": indicator.get("description"),
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






loop_active = False
user_path = "user.xlsx"
black_list_path = "black_list.xlsx"
miav_database_path = "miav_database.xlsx"
white_list_path= "white_list.xlsx"
chart_path = "chart.xlsx"
other_parameter_path = "parameter.xlsx"
ram_path = 'ram.xlsx'

is_login = False

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
    return render_template('ioc.html', indicator=first_page_data, total_pages=total_pages, current_page = 1, m = 7)

@app.route('/ioc_page', methods=['GET'])
@login_required
def ioc_page():
    current_page = int(request.args.get("page", 1))  # Lấy số trang từ URL
    print(current_page)
    indicator = get_indicator()
    indicator = indicator.fillna("N/A").replace("", "N/A")

    total_pages = (len(indicator) + 9) // 7  # Tính tổng số trang
    start = (current_page - 1) * 7  # Dòng bắt đầu
    end = start + 7  # Dòng kết thúc
    paginated_data = indicator.iloc[start:end]
    return render_template('ioc.html', indicator=paginated_data, total_pages=total_pages, current_page = current_page, m = 7)


@app.route('/add_ioc', methods=['GET', 'POST'])
@login_required
def add_ioc():
    data = request.get_json()
    required_fields = ["id", "url"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"success": False, "message": f"Trường {field} không được để trống!"})
    ioc_data = {
        "_id": data["id"],  
        "url": data["url"],
        "description": data["description"],
        "status": data.get("status", "N/A"),  
        "threat": data.get("threat", "N/A"),
        "pattern": data.get("pattern", "N/A"),
        "valid_from": data.get("valid_from", "N/A"),
        "valid_until": data.get("valid_until", "N/A")
    }
    print(ioc_data)
    #indicator_collection.insert_one(ioc_data)
    return jsonify({"success": True, "message": "Thêm mới mối đe dọa thành công!"})
        




@app.route('/monitor', methods=['GET', 'POST'])
@login_required
def monitor():
    records = get_record()
    records = records.fillna("N/A").replace("", "N/A")
    indicator_json = records.to_dict(orient='records')
    total_pages = (len(records) + 7) // 7
    first_page_data = records.iloc[:7]
    a = len(records)
    return render_template('monitor.html', records=first_page_data, total_pages=total_pages, current_page = 1, a = a)

@app.route('/monitor_page', methods=['GET', 'POST'])
@login_required
def monitor_page():
    current_page = int(request.args.get("page", 1))  
    print(current_page)
    records = get_record()
    records = records.fillna("N/A").replace("", "N/A")

    total_pages = (len(records) + 7) // 7 
    start = (current_page - 1) * 7  
    end = start + 7 
    paginated_data = records.iloc[start:end]
    return render_template('monitor.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7)


@app.route('/user_managerment', methods=['GET', 'POST'])
@login_required
def user_managerment():
    user_data = get_users()
    total_pages = (len(user_data) + 7) // 7
    first_page_data = user_data.iloc[:7]
    m = 7
    return render_template('user_managerment.html', records=first_page_data, total_pages=total_pages, current_page = 1, m = 7)

@app.route('/user_managerment_page', methods=['GET', 'POST'])
@login_required
def user_managerment_page():
    current_page = int(request.args.get("page", 1))  
    print(current_page)
    user_data = get_users()
    user_data = user_data.fillna("N/A").replace("", "N/A")

    total_pages = (len(user_data) + 7) // 7 
    start = (current_page - 1) * 7  
    end = start + 7 
    paginated_data = user_data.iloc[start:end]
    return render_template('user_managerment.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    data = request.get_json()
    required_fields = ["username", "password", "unit", "role"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"success": False, "message": f"Trường {field} không được để trống!"})
    hash_password = hashlib.sha256(data['password'].encode()).hexdigest()
    user_data = {
        "username": data["username"],  
        "password": hash_password,
        "unit_name": data["unit"],
        "create_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "role": data.get("role", "N/A")
    }
    print(user_data)
    user_collection.insert_one(user_data)
    return jsonify({"success": True, "message": "Thêm mới mối đe dọa thành công!"})


@app.route('/delete_user', methods=['GET', 'POST'])
@login_required
def delete_user():
    data = request.get_json()
    username = data["username"]
    print(username)
    if not username:
        return jsonify({"success": False, "message": f"Có lỗi trong quá trình nhận dữ liệu!"})
    result = user_collection.delete_one({"username": data["username"]})
    return jsonify({"success": True, "message": "Thêm mới mối đe dọa thành công!"})

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    #df1 là biểu đồ cột, df2 là 3 thôn số thống kê, monthlist và monthcount là thông số cho biểu đồ đường
    records = get_record()
    month_list, month_count = get_monthly_record_counts(records)
    df_1, df_2 = get_dashboard_parameter()
    df_1_json = df_1.to_dict(orient='records')
    print(df_1)
    return render_template('index.html',df_1_json=df_1_json, df_2 = df_2, month_list = month_list, month_count = month_count)

@app.route("/chart")
def chart():
    # Tạo DataFrame mẫu (bạn có thể thay bằng get_record())
    df = get_record()

    df_filtered = df[df["LABEL"] == 1]

    data = df_filtered.apply(lambda row: [row["IP"], row["EXTRACTED_IP"]], axis=1).tolist()

    # Tạo danh sách node với màu sắc tương ứng
    internal_ips = df_filtered["IP"].unique().tolist()
    external_iocs = df_filtered["EXTRACTED_IP"].unique().tolist()

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

    return render_template("chart.html", data=data, nodes=nodes)

@app.route('/search_and_backup', methods=['GET', 'POST'])
@login_required
def search_and_backup():
    records = get_search_and_backup()
    records = records.fillna("N/A").replace("", "N/A")
    indicator_json = records.to_dict(orient='records')
    total_pages = (len(records) + 7) // 7
    first_page_data = records.iloc[:7]
    a = len(records)
    return render_template('search_and_backup.html', records=first_page_data, total_pages=total_pages, current_page = 1, a = a)

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
    return render_template('search_and_backup.html', records=paginated_data, total_pages=total_pages, current_page = current_page, m = 7)

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
    matched_ram = record[record['MAC'] == mac]

    if not matched_ram.empty:
        return matched_ram.iloc[0]['IP'], matched_ram.iloc[0]['UNIT_NAME']
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

@app.route('/search_history', methods=['GET', 'POST'])
@login_required
def search_history():
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

        record_to_insert = {
            "user_id": current_user.id,
            "data": df_filtered_2.to_dict(orient="records")
        }
        search_history_collection.insert_one(record_to_insert)
    return '1'


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
        "ALERT_LEVEL_ID", "ALERT_TYPE", "DESCRIPTION", "EXTRACTED_IP",
        "IP", "LABEL", "MAC", "TIME_RECEIVE",
        "UNIT_FULL_NAME", "UNIT_NAME", "USER_NAME"
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


def import_file_2():
    required_fields = [
        "ALERT_LEVEL_ID", "ALERT_TYPE", "DESCRIPTION", "EXTRACTED_IP",
        "IP", "LABEL", "MAC", "TIME_RECEIVE",
        "UNIT_FULL_NAME", "UNIT_NAME", "USER_NAME"
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
    df["TIME_RECEIVE"] = pd.to_datetime(df["TIME_RECEIVE"])
    today = datetime.today()
    months = [(today - timedelta(days=30*i)).strftime("%m/%Y") for i in range(12)]
    months.reverse()  
    df["Month_Year"] = df["TIME_RECEIVE"].dt.strftime("%m/%Y")
    record_counts = [df[df["Month_Year"] == month].shape[0] for month in months]
    return months, record_counts


def delete_collection(collection):
    collection = db[collection] 
    collection.drop()


def update_chart_parameter(df_new):
    df = pd.read_excel(chart_path)
    for index, row in df_new.iterrows():
        ip = row['IP']
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
		if any(key in str(a['DESCRIPTION']) for key in list):
			df_filtered = df_filtered._append(a, ignore_index = True)
	return df_filtered
# Hàm filtering2, bỏ các white record, giữ lại black và gray
def filtering_2(df, list):
	df_filtered = pd.DataFrame(columns = df.columns)
	for _,row in df.iterrows():
		a = row
		if not any(key in str(a['DESCRIPTION']) for key in list):
			df_filtered = df_filtered._append(a, ignore_index = True)
	return df_filtered

def match_miav_database(df_filtered):
    miav_database_df = get_miav_database()
    miav_ip_list = miav_database_df['IP'].tolist()

    df_filtered['EXTRACTED_IP'] = df_filtered['DESCRIPTION'].str.replace("connect to ", "", regex=False)

    def check_match(value):
        return 1 if value in miav_ip_list else 0
    df_filtered['label'] = df_filtered['EXTRACTED_IP'].apply(check_match)
    print(df_filtered)
    return df_filtered
    


def get_filter(formatted_date_1, formatted_date_2):
	filter = {"time_receive":{"$gte": formatted_date_1,"$lte": formatted_date_2 }}
	name = str(formatted_date_1) + '-' + str(formatted_date_2)
	return filter,name

def raw_to_df(result):
	data = {'MAC': [],'IP': [],'UNIT_NAME': [],'USER_NAME': [],'UNIT_FULL_NAME': [],'ALERT_TYPE': [],'ALERT_LEVEL_ID': [], 'TIME_RECEIVE': [],'DESCRIPTION': []}
	for record in result:
		data['MAC'].append(str(record['mac']))
		data['IP'].append(str(record['ip']))
		data['UNIT_NAME'].append(str(record['unit_full_name']))
		data['USER_NAME'].append(str('Chua dinh danh'))
		data['UNIT_FULL_NAME'].append(str(record['unit_full_name']))
		data['ALERT_TYPE'].append(str(record['alert_type']))
		data['ALERT_LEVEL_ID'].append(str(record['alert_level_id']))
		data['TIME_RECEIVE'].append(str(record['time_receive']))
		data['DESCRIPTION'].append(str(record.get('alert_info', {}).get('description', 'No description available')))
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
        ram_collection.delete_many({}, limit=excess, sort=[("TIME_RECEIVE", 1)])
    ram_collection.insert_many(data_list)


def insert_with_limit_search(data_list, limit=500000):
    current_count = search_history_collection.count_documents({})
    insert_count = len(data_list)
    excess = (current_count + insert_count) - limit
    if excess > 0:
        search_history_collection.delete_many({}, limit=excess, sort=[("TIME_RECEIVE", 1)])
    search_history_collection.insert_many(data_list)

def core():
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
        sleep_time =  max(0, (timedelta(seconds=10) - elapsed_time).total_seconds())
        time.sleep(sleep_time)
        data = df_filtered_2.to_json(orient='records')
        if loop_active:
            socketio.emit('new_data', data)

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

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    hash_hex = hashlib.sha256(password.encode()).hexdigest()

    print(hash_hex)
    if email in users and users[email]['password'] == hash_hex:
        user = User(email)
        login_user(user)
        return jsonify({'status': 'success', 'message': 'Đăng nhập thành công'})
    else:
        return jsonify({'status': 'error', 'message': 'Email hoặc mật khẩu không đúng'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'status': 'success', 'message': 'Đăng xuất thành công'})

@app.route('/protected')
@login_required
def protected():
    return f'Logged in as: {current_user.id}'


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

#investigate_ip_stmnc('45.125.66.56')
#print(get_relationship())