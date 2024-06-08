from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from functools import wraps
from app.models import User

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            user = User.find_by_email(current_user['email'])
            if not user or user['role'] != role:
                return jsonify({'message': 'You do not have permission to access this resource'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
