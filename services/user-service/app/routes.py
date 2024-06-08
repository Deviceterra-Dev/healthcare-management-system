from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    create_refresh_token, get_jwt
)
from app.models import User
from app.utils import generate_confirmation_token, confirm_token
from app.middlewares import role_required
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import swag_from

auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['POST'])
@swag_from('../docs/register.yml')
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')
    phone = data.get('phone')
    role = data.get('role', 'patient')
    specialty = data.get('specialty')
    availability = data.get('availability', [])
    approved = role != 'doctor'  # Doctors require admin approval

    if User.find_by_email(email):
        return jsonify({'message': 'User already exists'}), 400

    user = User(email, password, username, phone, role, specialty, availability, approved)
    user.save_to_db()

    token = create_access_token(identity={'email': email, 'role': role, 'approved': approved})
    refresh_token = create_refresh_token(identity={'email': email, 'role': role, 'approved': approved})
    return jsonify({'token': token, 'refresh_token': refresh_token}), 201

@auth.route('/admin/register', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from('../docs/admin_register.yml')
def admin_register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')
    phone = data.get('phone')
    role = 'admin'  # Ensure the role is set to admin
    approved = True  # Admins are approved immediately

    if User.find_by_email(email):
        return jsonify({'message': 'User already exists'}), 400

    user = User(email, password, username, phone, role, approved=approved)
    user.save_to_db()

    token = create_access_token(identity={'email': email, 'role': role, 'approved': approved})
    refresh_token = create_refresh_token(identity={'email': email, 'role': role, 'approved': approved})
    return jsonify({'token': token, 'refresh_token': refresh_token}), 201

@auth.route('/admin-only', methods=['GET'])
@jwt_required()
@role_required('admin')
@swag_from('../docs/admin_only.yml')
def admin_only():
    return jsonify({'message': 'Welcome, admin!'}), 200

@auth.route('/approve-doctor', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from('../docs/approve_doctor.yml')
def approve_doctor():
    data = request.get_json()
    email = data.get('email')
    approve = data.get('approve', True)

    user = User.find_by_email(email)
    if not user or user['role'] != 'doctor':
        return jsonify({'message': 'User not found or not a doctor'}), 404

    User.update_user(email, {'approved': approve})
    return jsonify({'message': f'Doctor {"approved" if approve else "rejected"} successfully'}), 200

@auth.route('/login', methods=['POST'])
@swag_from('../docs/login.yml')
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user_data = User.find_by_email(email)
    if not user_data or not User.check_password(user_data['password'], password):
        return jsonify({'message': 'Invalid credentials'}), 401

    if user_data['role'] == 'doctor' and not user_data.get('approved', False):
        return jsonify({'message': 'Doctor not approved by admin'}), 403

    token = create_access_token(identity={'email': email, 'role': user_data['role'], 'approved': user_data.get('approved', False)})
    refresh_token = create_refresh_token(identity={'email': email, 'role': user_data['role'], 'approved': user_data.get('approved', False)})
    return jsonify({'token': token, 'refresh_token': refresh_token}), 200

@auth.route('/profile', methods=['GET'])
@jwt_required()
@swag_from('../docs/profile.yml')
def profile():
    current_user = get_jwt_identity()
    user = User.find_by_email(current_user['email'])
    if not user:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'username': user['username'],
        'email': user['email'],
        'phone': user['phone'],
        'role': user['role'],
        'specialty': user.get('specialty'),
        'availability': user.get('availability'),
        'approved': user.get('approved', False)
    }), 200

@auth.route('/update-availability', methods=['PUT'])
@jwt_required()
@role_required('doctor')
@swag_from('../docs/update_availability.yml')
def update_availability():
    current_user = get_jwt_identity()
    data = request.get_json()
    availability = data.get('availability', [])

    user = User.find_by_email(current_user['email'])
    if not user:
        return jsonify({'message': 'User not found'}), 404

    User.update_user(current_user['email'], {'availability': availability})
    return jsonify({'message': 'Availability updated successfully'}), 200

@auth.route('/send-verification-email', methods=['POST'])
@swag_from('../docs/send_verification_email.yml')
def send_verification_email():
    data = request.get_json()
    email = data.get('email')

    user_data = User.find_by_email(email)
    if not user_data:
        return jsonify({'message': 'User not found'}), 404

    verification_token = generate_confirmation_token(user_data['email'])

    # TODO: Send email with the verification token (omitted for brevity)
    
    return jsonify({'message': 'Verification email sent'}), 200

@auth.route('/verify-email', methods=['GET'])
@swag_from('../docs/verify_email.yml')
def verify_email():
    token = request.args.get('token')

    try:
        email = confirm_token(token)
        user_data = User.find_by_email(email)
        if not user_data:
            return jsonify({'message': 'Invalid token'}), 400

        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        users = db.users
        users.update_one({'email': email}, {'$set': {'email_verified': True}})

        return jsonify({'message': 'Email has been verified successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Invalid token or token has expired'}), 400

@auth.route('/setup-mfa', methods=['POST'])
@jwt_required()
@swag_from('../docs/setup_mfa.yml')
def setup_mfa():
    current_user = get_jwt_identity()
    data = request.get_json()
    mfa_enabled = data.get('mfa_enabled')

    user_data = User.find_by_email(current_user['email'])
    if not user_data:
        return jsonify({'message': 'User not found'}), 404

    User.update_user(current_user['email'], {'mfa_enabled': mfa_enabled})

    return jsonify({'message': 'MFA setting updated successfully'}), 200

@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@swag_from('../docs/refresh.yml')
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({'token': new_token}), 200

@auth.route('/logout', methods=['POST'])
@jwt_required()
@swag_from('../docs/logout.yml')
def logout():
    jti = get_jwt()['jti']
    # TODO: Add token to blacklist (requires implementation)
    return jsonify({'message': 'Successfully logged out'}), 200

@auth.route('/change-password', methods=['POST'])
@jwt_required()
@swag_from('../docs/change_password.yml')
def change_password():
    current_user = get_jwt_identity()
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    user_data = User.find_by_email(current_user['email'])
    if not user_data or not User.check_password(user_data['password'], current_password):
        return jsonify({'message': 'Current password is incorrect'}), 401

    hashed_new_password = generate_password_hash(new_password)
    User.update_user(current_user['email'], {'password': hashed_new_password})

    return jsonify({'message': 'Password updated successfully'}), 200

@auth.route('/forgot-password', methods=['POST'])
@swag_from('../docs/forgot_password.yml')
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user_data = User.find_by_email(email)
    if not user_data:
        return jsonify({'message': 'User not found'}), 404

    reset_token = generate_confirmation_token(user_data['email'])
    # TODO: Send email with the reset token (omitted for brevity)

    return jsonify({'message': 'Password reset email sent'}), 200

@auth.route('/confirm-reset-password', methods=['POST'])
@swag_from('../docs/confirm_reset_password.yml')
def confirm_reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    try:
        email = confirm_token(token)
        user_data = User.find_by_email(email)
        if not user_data:
            return jsonify({'message': 'Invalid token'}), 400

        hashed_new_password = generate_password_hash(new_password)
        User.update_user(user_data['email'], {'password': hashed_new_password})

        return jsonify({'message': 'Password has been reset successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Invalid token or token has expired'}), 400

@auth.route('/setup-2fa', methods=['POST'])
@jwt_required()
@swag_from('../docs/setup_2fa.yml')
def setup_2fa():
    current_user = get_jwt_identity()
    # TODO: Implement 2FA setup logic, e.g., generating a QR code or secret key
    return jsonify({'message': '2FA setup successful'}), 200

@auth.route('/verify-2fa', methods=['POST'])
@jwt_required()
@swag_from('../docs/verify_2fa.yml')
def verify_2fa():
    current_user = get_jwt_identity()
    data = request.get_json()
    # TODO: Implement 2FA verification logic, e.g., validating the provided 2FA code
    return jsonify({'message': '2FA verification successful'}), 200

@auth.route('/doctors', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_doctors.yml')
def get_doctors():
    doctors = User.find_doctors()
    for doctor in doctors:
        doctor['_id'] = str(doctor['_id'])  # Convert ObjectId to string
    return jsonify(doctors), 200

@auth.route('/available-doctors', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_available_doctors.yml')
def get_available_doctors():
    client = MongoClient(current_app.config['MONGO_URI'])
    db = client.healthcare
    doctors = db.users.find({'role': 'doctor', 'approved': True}, {'_id': 0, 'username': 1, 'specialty': 1, 'availability': 1})
    return jsonify(list(doctors)), 200
