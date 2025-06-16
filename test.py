import json
import pandas as pd
import ast

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

# Đọc và xử lý file
with open("response_2.txt", "r", encoding="utf-8") as f:
    raw_text = f.read()

# Chuyển chuỗi có dấu nháy đơn thành dict hợp lệ
response_json = ast.literal_eval(raw_text)

# Tạo DataFrame
df = raw_to_df(response_json)

# Hiển thị kết quả (nếu cần)
print(df.head())
