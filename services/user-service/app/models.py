from pymongo import MongoClient
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, email, password, username=None, phone=None, role='patient', specialty=None, availability=None, approved=False):
        self.email = email
        self.password = generate_password_hash(password)
        self.username = username
        self.phone = phone
        self.role = role
        self.profile_picture = None
        self.mfa_enabled = False
        self.email_verified = False
        self.specialty = specialty
        self.availability = availability if availability is not None else []
        self.approved = approved  # New field to track approval status

    def save_to_db(self):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.insert_one(self.__dict__)

    @staticmethod
    def find_by_email(email):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        return users.find_one({'email': email})

    @staticmethod
    def find_by_username(username):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        return users.find_one({'username': username})

    @staticmethod
    def find_doctors():
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        return list(users.find({'role': 'doctor', 'approved': True}))

    @staticmethod
    def check_password(stored_password, provided_password):
        return check_password_hash(stored_password, provided_password)

    @staticmethod
    def update_user(email, updates):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'email': email}, {'$set': updates})
