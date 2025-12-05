from pymongo import MongoClient
import pandas as pd
import hashlib
import bcrypt

def create_collection(excel_path, collection):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["stmnc"]
    collection = db[collection] 
    file_path = excel_path
    df = pd.read_excel(file_path, engine="openpyxl")

    data = df.to_dict(orient="records")
    print(data)

    collection.insert_many(data)
    print("Dữ liệu đã được chèn vào MongoDB!")
def delete_collection(collection):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["stmnc"]
    collection = db[collection] 
    collection.drop()
def delete_document_by_id(doc_id):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["stmnc"]
    collection = db["indicator"]

    result = collection.delete_one({"_id": doc_id})
    
    if result.deleted_count > 0:
        print(f"Đã xóa thành công tài liệu có _id: {doc_id}")
    else:
        print(f"Không tìm thấy tài liệu có _id: {doc_id}")
#pd.set_option('display.max_colwidth', None)
#delete_document_by_id('be12e55c7b524947e974677557fc1fda52083891b6aa9bbf9b17341fd9480f5a')


def create_password(plain_text):
    salt = bcrypt.gensalt()  
    hashed_password = bcrypt.hashpw(plain_text.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


delete_collection('user')
create_collection('user.xlsx', 'user')


def convert_password(plain_text):
    hashed_password = hashlib.sha256(plain_text.encode()).hexdigest()
    return hashed_password
