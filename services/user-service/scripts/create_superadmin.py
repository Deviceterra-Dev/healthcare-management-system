import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime

# Connect to MongoDB
client = MongoClient(os.getenv('MONGO_URI'))
db = client.healthcare
users = db.users

# Create super admin user
superadmin_email = os.getenv('SUPERADMIN_EMAIL')
superadmin_password = generate_password_hash(os.getenv('SUPERADMIN_PASSWORD'))
superadmin_user = {
    'email': superadmin_email,
    'password': superadmin_password,
    'username': 'superadmin',
    'phone': '123-456-7890',
    'role': 'superadmin',
    'address': 'Super Admin Address',
    'dob': '1970-01-01',
    'profile_picture': None,
    'mfa_enabled': False,
    'email_verified': True,
    'specialty': None,
    'availability': [],
    'approved': True,
    'created_at': datetime.utcnow(),
    'updated_at': datetime.utcnow(),
    'last_login': None,
    'login_attempts': 0,
    'locked_until': None
}

# Insert super admin user into the database if not already exists
if not users.find_one({'email': superadmin_email}):
    users.insert_one(superadmin_user)
    print("Super admin user created.")
else:
    print("Super admin user already exists.")
