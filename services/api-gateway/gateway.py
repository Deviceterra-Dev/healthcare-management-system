from flask import Flask, request, jsonify
from flasgger import Swagger, swag_from
import jwt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from functools import wraps
import logging
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter, generate_latest
from flask_httpauth import HTTPTokenAuth
from config import Config
from utils import call_service, get_doc_path

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Prometheus metrics
metrics = PrometheusMetrics(app)

# Define custom metrics
login_requests = Counter('login_requests', 'Number of login requests')
login_success = Counter('login_success', 'Number of successful logins')
login_failures = Counter('login_failures', 'Number of failed logins')
register_requests = Counter('register_requests', 'Number of registration requests')
api_errors = Counter('api_errors', 'Number of errors encountered in the API gateway')

# Caching configuration
cache = Cache(app)

# Rate limiting configuration
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=Config.RATELIMIT_STORAGE_URL,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Setup Swagger
swagger = Swagger(app, config=Config.SWAGGER_CONFIG, template=Config.SWAGGER_TEMPLATE)
jwt_manager = JWTManager(app)
auth = HTTPTokenAuth(scheme='Bearer')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_token(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        logger.error("Expired token")
        return None
    except jwt.InvalidTokenError:
        logger.error("Invalid token")
        return None

@app.before_request
def authenticate_request():
    open_paths = [
        '/apidocs',
        '/auth/login',
        '/auth/register',
        '/flasgger_static',
        '/apispec_1.json',
        '/metrics'
    ]
    if any(request.path.startswith(path) for path in open_paths):
        return

    token = request.headers.get('Authorization')
    if token:
        token = token.split(" ")[1] if ' ' in token else None

    if not token or not validate_token(token):
        return jsonify({'message': 'Token is missing or invalid!'}), 401

    request.user = validate_token(token)

@auth.verify_token
def verify_token(token):
    user = validate_token(token)
    if user:
        return user

def role_required(role):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user = get_jwt_identity()
            if user['role'] != role:
                return jsonify({'message': 'You do not have permission to access this resource'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes (ensure all paths are correct and utilities are used)
@app.route('/auth/register', methods=['POST'])
@swag_from(get_doc_path('register.yml'))
@limiter.limit("10 per minute")
def register():
    register_requests.inc()
    service_url = 'http://user-service:5000/auth/register'
    return call_service('POST', service_url, json=request.get_json())

@app.route('/auth/login', methods=['POST'])
@swag_from(get_doc_path('login.yml'))
@limiter.limit("10 per minute")
def login():
    login_requests.inc()
    service_url = 'http://user-service:5000/auth/login'
    response = call_service('POST', service_url, json=request.get_json())
    if response[1] == 200:
        login_success.inc()
    else:
        login_failures.inc()
    return response

@app.route('/auth/profile', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('profile.yml'))
@limiter.limit("5 per minute")
def profile():
    service_url = 'http://user-service:5000/auth/profile'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/auth/send-verification-email', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('send_verification_email.yml'))
@limiter.limit("5 per minute")
def send_verification_email():
    service_url = 'http://user-service:5000/auth/send-verification-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/verify-email', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('verify_email.yml'))
@limiter.limit("5 per minute")
def verify_email():
    service_url = 'http://user-service:5000/auth/verify-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers, params=request.args)

@app.route('/auth/admin-only', methods=['GET'])
@jwt_required()
@role_required('admin')
@swag_from(get_doc_path('admin_only.yml'))
@limiter.limit("5 per minute")
def admin_only():
    service_url = 'http://user-service:5000/auth/admin-only'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/auth/setup-mfa', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('setup_mfa.yml'))
@limiter.limit("5 per minute")
def setup_mfa():
    service_url = 'http://user-service:5000/auth/setup-mfa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
@swag_from(get_doc_path('refresh.yml'))
@limiter.limit("5 per minute")
def refresh():
    service_url = 'http://user-service:5000/auth/refresh'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, headers=headers)

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('logout.yml'))
@limiter.limit("5 per minute")
def logout():
    service_url = 'http://user-service:5000/auth/logout'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, headers=headers)

@app.route('/auth/change-password', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('change_password.yml'))
@limiter.limit("5 per minute")
def change_password():
    service_url = 'http://user-service:5000/auth/change-password'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/forgot-password', methods=['POST'])
@swag_from(get_doc_path('forgot_password.yml'))
@limiter.limit("5 per minute")
def forgot_password():
    service_url = 'http://user-service:5000/auth/forgot-password'
    return call_service('POST', service_url, json=request.get_json())

@app.route('/auth/confirm-reset-password', methods=['POST'])
@swag_from(get_doc_path('confirm_reset_password.yml'))
@limiter.limit("5 per minute")
def confirm_reset_password():
    service_url = 'http://user-service:5000/auth/confirm-reset-password'
    return call_service('POST', service_url, json=request.get_json())

@app.route('/auth/setup-2fa', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('setup_2fa.yml'))
@limiter.limit("5 per minute")
def setup_2fa():
    service_url = 'http://user-service:5000/auth/setup-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/verify-2fa', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('verify_2fa.yml'))
@limiter.limit("5 per minute")
def verify_2fa():
    service_url = 'http://user-service:5000/auth/verify-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/admin/register', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from(get_doc_path('admin_register.yml'))
@limiter.limit("5 per minute")
def admin_register():
    service_url = 'http://user-service:5000/auth/admin/register'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/approve-doctor', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from(get_doc_path('approve_doctor.yml'))
@limiter.limit("5 per minute")
def approve_doctor():
    service_url = 'http://user-service:5000/auth/approve-doctor'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = call_service('POST', service_url, json=request.get_json(), headers=headers)
    if response[1] == 200:
        cache.delete_memoized(get_doctors)
        cache.delete_memoized(get_available_doctors)
    return response

@app.route('/auth/update-availability', methods=['PUT'])
@jwt_required()
@role_required('doctor')
@swag_from(get_doc_path('update_availability.yml'))
@limiter.limit("5 per minute")
def update_availability():
    service_url = 'http://user-service:5000/auth/update-availability'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('PUT', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/update-profile', methods=['PUT'])
@jwt_required()
@swag_from(get_doc_path('update_profile.yml'))
@limiter.limit("5 per minute")
def update_profile():
    service_url = 'http://user-service:5000/auth/update-profile'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('PUT', service_url, json=request.get_json(), headers=headers)

@app.route('/auth/doctors', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_doctors.yml'))
@limiter.limit("5 per minute")
@cache.cached(timeout=300, query_string=True)
def get_doctors():
    service_url = 'http://user-service:5000/auth/doctors'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/auth/available-doctors', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_available_doctors.yml'))
@limiter.limit("5 per minute")
@cache.cached(timeout=300, query_string=True)
def get_available_doctors():
    service_url = 'http://user-service:5000/auth/available-doctors'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

# Appointment Service Endpoints
@app.route('/appointments', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('create_appointment.yml'))
@limiter.limit("5 per minute")
def create_appointment():
    service_url = 'http://appointment-service:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, json=request.get_json(), headers=headers)

@app.route('/appointments/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_appointment.yml'))
@limiter.limit("5 per minute")
def get_appointment(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/appointments', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_user_appointments.yml'))
@limiter.limit("5 per minute")
def get_user_appointments():
    service_url = 'http://appointment-service:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/appointments/<appointment_id>', methods=['PUT'])
@jwt_required()
@swag_from(get_doc_path('update_appointment.yml'))
@limiter.limit("5 per minute")
def update_appointment(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('PUT', service_url, json=request.get_json(), headers=headers)

@app.route('/appointments/<appointment_id>', methods=['DELETE'])
@jwt_required()
@swag_from(get_doc_path('delete_appointment.yml'))
@limiter.limit("5 per minute")
def delete_appointment(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('DELETE', service_url, headers=headers)

@app.route('/appointments/<appointment_id>/cancel', methods=['POST'])
@jwt_required()
@swag_from(get_doc_path('cancel_appointment.yml'))
@limiter.limit("5 per minute")
def cancel_appointment(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/{appointment_id}/cancel'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('POST', service_url, headers=headers)

@app.route('/appointments/<appointment_id>/reschedule', methods=['PUT'])
@jwt_required()
@swag_from(get_doc_path('reschedule_appointment.yml'))
@limiter.limit("5 per minute")
def reschedule_appointment(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/{appointment_id}/reschedule'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('PUT', service_url, json=request.get_json(), headers=headers)

@app.route('/appointments/doctor-availability/<doctor_id>', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_doctor_availability.yml'))
@limiter.limit("5 per minute")
def get_doctor_availability(doctor_id):
    service_url = f'http://user-service:5000/auth/doctors/{doctor_id}/availability'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/appointments/status/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('get_appointment_status.yml'))
@limiter.limit("5 per minute")
def get_appointment_status(appointment_id):
    service_url = f'http://appointment-service:5001/api/appointments/status/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers)

@app.route('/appointments/search', methods=['GET'])
@jwt_required()
@swag_from(get_doc_path('search_appointments.yml'))
@limiter.limit("5 per minute")
def search_appointments():
    service_url = 'http://appointment-service:5001/api/appointments/search'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    return call_service('GET', service_url, headers=headers, params=request.args)

@app.route('/metrics')
def metrics():
    return generate_latest()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
