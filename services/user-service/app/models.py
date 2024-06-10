from pymongo import MongoClient
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from bson import ObjectId  # Don't forget to import ObjectId

class User:
    def __init__(self, email, password, username=None, phone=None, role='patient', specialty=None, availability=None, approved=False, address=None, dob=None, profile_picture=None):
        self.email = email
        self.password = generate_password_hash(password)
        self.username = username
        self.phone = phone
        self.role = role
        self.profile_picture = profile_picture
        self.mfa_enabled = False
        self.email_verified = False
        self.specialty = specialty
        self.availability = availability if availability is not None else []
        self.approved = approved  # New field to track approval status
        self.address = address
        self.dob = dob
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.last_login = None
        self.login_attempts = 0
        self.locked_until = None

    def save_to_db(self):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.insert_one(self.to_dict())

    def to_dict(self):
        return {
            'email': self.email,
            'password': self.password,
            'username': self.username,
            'phone': self.phone,
            'role': self.role,
            'profile_picture': self.profile_picture,
            'mfa_enabled': self.mfa_enabled,
            'email_verified': self.email_verified,
            'specialty': self.specialty,
            'availability': self.availability,
            'approved': self.approved,
            'address': self.address,
            'dob': self.dob,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'last_login': self.last_login,
            'login_attempts': self.login_attempts,
            'locked_until': self.locked_until
        }

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
    def find_by_id(user_id):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        try:
            return users.find_one({'_id': ObjectId(user_id)})
        except:
            return None

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
        updates['updated_at'] = datetime.utcnow()
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'email': email}, {'$set': updates})

    @staticmethod
    def increment_login_attempts(email):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        user = users.find_one({'email': email})
        if user:
            new_attempts = user.get('login_attempts', 0) + 1
            lock_time = None
            if new_attempts >= 5:
                lock_time = datetime.utcnow() + timedelta(minutes=15)
            users.update_one({'email': email}, {'$set': {'login_attempts': new_attempts, 'locked_until': lock_time}})
    
    @staticmethod
    def reset_login_attempts(email):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'email': email}, {'$set': {'login_attempts': 0, 'locked_until': None}})
    
    @staticmethod
    def set_last_login(email):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'email': email}, {'$set': {'last_login': datetime.utcnow()}})
