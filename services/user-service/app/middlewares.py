from functools import wraps
from flask_jwt_extended import get_jwt_identity
from flask import request, jsonify
from app.models import User

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            user = User.find_by_username(current_user)
            if user.role != role:
                return jsonify({"message": "Access forbidden: insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
