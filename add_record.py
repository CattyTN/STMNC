

from pymongo import MongoClient
import pandas as pd
import hashlib
import bcrypt

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME   = "stmnc"
def append_ram3_to_db(excel_path="ram_3.xlsx", target_collection="ram"):
    """
    Đọc file ram_3.xlsx và thêm các dòng vào collection target_collection (ví dụ 'ram').
    Không xóa dữ liệu cũ, chỉ insert thêm.
    """
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[target_collection]

    df = pd.read_excel(excel_path, engine="openpyxl")
    data = df.to_dict(orient="records")

    if not data:
        print("File Excel không có dữ liệu, không insert.")
        return

    result = col.insert_many(data)
    print(f"Đã chèn {len(result.inserted_ids)} bản ghi từ '{excel_path}' vào collection '{target_collection}'.")

def set_all_ram_labels_to_zero(collection_name="ram"):
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[collection_name]

    result = collection.update_many({}, {"$set": {"label": 0}})

    print(f"Đã cập nhật {result.modified_count} bản ghi: đặt label = 0.")

if __name__ == "__main__":
    # ví dụ: thêm dữ liệu người dùng từ user.xlsx
    # delete_collection("user")
    # create_collection("user.xlsx", "user")

    # thêm các dòng trong ram_3.xlsx vào collection 'ram'
    set_all_ram_labels_to_zero("ram")
    append_ram3_to_db("ram_3.xlsx", "ram")