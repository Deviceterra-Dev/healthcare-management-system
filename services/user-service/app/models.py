from pymongo import MongoClient
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, username, password, email, phone, role='patient'):
        self.username = username
        self.password = generate_password_hash(password)
        self.email = email
        self.phone = phone
        self.role = role
        self.profile_picture = None
        self.mfa_enabled = False
        self.email_verified = False

    def save_to_db(self):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.insert_one(self.__dict__)

    @staticmethod
    def find_by_username(username):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        return users.find_one({'username': username})

    @staticmethod
    def find_by_email(email):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        return users.find_one({'email': email})

    @staticmethod
    def check_password(stored_password, provided_password):
        return check_password_hash(stored_password, provided_password)

    @staticmethod
    def update_user(username, updates):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'username': username}, {'$set': updates})
