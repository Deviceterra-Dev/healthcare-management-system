from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from functools import wraps
from app.models import User
import logging

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                current_user = get_jwt_identity()
                user = User.find_by_email(current_user['email'])
                if not user or user['role'] != role:
                    return jsonify({'message': 'You do not have permission to access this resource'}), 403
                return f(*args, **kwargs)
            except Exception as e:
                logging.error(f"Error in role_required middleware: {e}")
                return jsonify({'message': 'Internal server error'}), 500
        return decorated_function
    return decorator

def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user = get_jwt_identity()
            user = User.find_by_email(current_user['email'])
            if user and user.get('mfa_enabled'):
                mfa_token = request.headers.get('X-MFA-Token')
                if not mfa_token or not verify_mfa_token(user, mfa_token):
                    return jsonify({'message': 'MFA verification failed'}), 403
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in mfa_required middleware: {e}")
            return jsonify({'message': 'Internal server error'}), 500
    return decorated_function

def verify_mfa_token(user, mfa_token):
    # Placeholder for actual MFA token verification logic
    # This should integrate with your MFA solution (e.g., TOTP, SMS, etc.)
    return True  # Replace with actual verification logic

def log_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.info(f"Request to {request.path} with method {request.method} and data {request.get_json()}")
        return f(*args, **kwargs)
    return decorated_function
