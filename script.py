import requests
import pandas as pd
from datetime import datetime, timedelta
import json




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

def raw_to_df(response_json):
    records = response_json.get("data", {}).get("event", [])
    data = {
        'MAC': [],
        'IP': [],
        'UNIT_NAME': [],
        'USER_NAME': [],
        'UNIT_FULL_NAME': [],
        'ALERT_TYPE': [],
        'ALERT_LEVEL_ID': [],
        'TIME_RECEIVE': [],
        'DESCRIPTION': []
    }
    for record in records:
        data['MAC'].append(str(record.get('mac', '')))
        data['IP'].append(str(record.get('ip', '')))
        data['UNIT_NAME'].append(str(record.get('unit_full_name', '').split(' - ')[0]))
        data['USER_NAME'].append("Chua dinh danh")
        data['UNIT_FULL_NAME'].append(str(record.get('unit_full_name', '')))
        data['ALERT_TYPE'].append(str(record.get('alert_type', '')))
        data['ALERT_LEVEL_ID'].append(str(record.get('alert_level_id', '')))
        data['TIME_RECEIVE'].append(str(record.get('time_receive', '')))
        data['DESCRIPTION'].append(
            str(record.get('alert_info', {}).get('description', 'No description available'))
        )

    return pd.DataFrame(data)


def core_once(start_date, end_date):
    token = get_token_2()
    if not token:
        print("[!] Không lấy được token")
        return None

    raw_data = get_event_data(token, start_date, end_date)
    if raw_data is None:
        print("[!] Không có dữ liệu trả về")
        return None

    df = raw_to_df(raw_data)
    print(df.head())   # in thử vài dòng
    return df

def main():
    # sample date đúng format
    start_date = "2025-10-01 00:00:00"
    end_date   = "2025-10-02 23:59:59"

    df = core_once(start_date, end_date)
    if df is not None:
        print(f"Tổng số bản ghi lấy được: {len(df)}")

if __name__ == "__main__":
    main()