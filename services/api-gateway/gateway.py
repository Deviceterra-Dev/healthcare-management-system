from flask import Flask, request, jsonify
from flasgger import Swagger, swag_from
import requests
import jwt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

template = {
    "swagger": "2.0",
    "info": {
        "title": "API Gateway",
        "description": "API Gateway for the Healthcare Management System",
        "contact": {
            "responsibleOrganization": "My Company",
            "responsibleDeveloper": "Developer Name",
            "email": "developer@example.com",
            "url": "www.example.com",
        },
        "termsOfService": "http://example.com/terms",
        "version": "1.0"
    },
    "basePath": "/",
    "schemes": [
        "http",
        "https"
    ],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
        }
    }
}

swagger = Swagger(app, config=swagger_config, template=template)
jwt_manager = JWTManager(app)

def validate_token(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.before_request
def authenticate_request():
    open_paths = [
        '/apidocs', 
        '/auth/login', 
        '/auth/register', 
        '/flasgger_static', 
        '/apispec_1.json'
    ]
    if any(request.path.startswith(path) for path in open_paths):
        return

    token = request.headers.get('Authorization')
    if token:
        token = token.split(" ")[1] if ' ' in token else None

    if not token or not validate_token(token):
        return jsonify({'message': 'Token is missing or invalid!'}), 401

    request.user = validate_token(token)

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

@app.route('/auth/register', methods=['POST'])
@swag_from('docs/register.yml')
def register():
    service_url = 'http://localhost:5000/auth/register'
    response = requests.post(service_url, json=request.get_json())
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/login', methods=['POST'])
@swag_from('docs/login.yml')
def login():
    service_url = 'http://localhost:5000/auth/login'
    response = requests.post(service_url, json=request.get_json())
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/profile', methods=['GET'])
@jwt_required()
@swag_from('docs/profile.yml')
def profile():
    service_url = 'http://localhost:5000/auth/profile'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/send-verification-email', methods=['POST'])
@jwt_required()
@swag_from('docs/send_verification_email.yml')
def send_verification_email():
    service_url = 'http://localhost:5000/auth/send-verification-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/verify-email', methods=['GET'])
@jwt_required()
@swag_from('docs/verify_email.yml')
def verify_email():
    service_url = 'http://localhost:5000/auth/verify-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers, params=request.args)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/admin-only', methods=['GET'])
@jwt_required()
@role_required('admin')
@swag_from('docs/admin_only.yml')
def admin_only():
    service_url = 'http://localhost:5000/auth/admin-only'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/setup-mfa', methods=['POST'])
@jwt_required()
@swag_from('docs/setup_mfa.yml')
def setup_mfa():
    service_url = 'http://localhost:5000/auth/setup-mfa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
@swag_from('docs/refresh.yml')
def refresh():
    service_url = 'http://localhost:5000/auth/refresh'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
@swag_from('docs/logout.yml')
def logout():
    service_url = 'http://localhost:5000/auth/logout'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/change-password', methods=['POST'])
@jwt_required()
@swag_from('docs/change_password.yml')
def change_password():
    service_url = 'http://localhost:5000/auth/change-password'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/forgot-password', methods=['POST'])
@swag_from('docs/forgot_password.yml')
def forgot_password():
    service_url = 'http://localhost:5000/auth/forgot-password'
    response = requests.post(service_url, json=request.get_json())
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/confirm-reset-password', methods=['POST'])
@swag_from('docs/confirm_reset_password.yml')
def confirm_reset_password():
    service_url = 'http://localhost:5000/auth/confirm-reset-password'
    response = requests.post(service_url, json=request.get_json())
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/setup-2fa', methods=['POST'])
@jwt_required()
@swag_from('docs/setup_2fa.yml')
def setup_2fa():
    service_url = 'http://localhost:5000/auth/setup-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/verify-2fa', methods=['POST'])
@jwt_required()
@swag_from('docs/verify_2fa.yml')
def verify_2fa():
    service_url = 'http://localhost:5000/auth/verify-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/admin/register', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from('docs/admin_register.yml')
def admin_register():
    service_url = 'http://localhost:5000/auth/admin/register'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/approve-doctor', methods=['POST'])
@jwt_required()
@role_required('admin')
@swag_from('docs/approve_doctor.yml')
def approve_doctor():
    service_url = 'http://localhost:5000/auth/approve-doctor'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/update-availability', methods=['PUT'])
@jwt_required()
@role_required('doctor')
@swag_from('docs/update_availability.yml')
def update_availability():
    service_url = 'http://localhost:5000/auth/update-availability'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.put(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/update-profile', methods=['PUT'])
@jwt_required()
@swag_from('docs/update_profile.yml')
def update_profile():
    service_url = 'http://localhost:5000/auth/update-profile'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.put(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/doctors', methods=['GET'])
@jwt_required()
@swag_from('docs/get_doctors.yml')
def get_doctors():
    service_url = 'http://localhost:5000/auth/doctors'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/auth/available-doctors', methods=['GET'])
@jwt_required()
@swag_from('docs/get_available_doctors.yml')
def get_available_doctors():
    service_url = 'http://localhost:5000/auth/available-doctors'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

# Appointment Service Endpoints
@app.route('/appointments', methods=['POST'])
@jwt_required()
@swag_from('docs/create_appointment.yml')
def create_appointment():
    service_url = 'http://localhost:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from('docs/get_appointment.yml')
def get_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments', methods=['GET'])
@jwt_required()
@swag_from('docs/get_user_appointments.yml')
def get_user_appointments():
    service_url = 'http://localhost:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/<appointment_id>', methods=['PUT'])
@jwt_required()
@swag_from('docs/update_appointment.yml')
def update_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.put(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/<appointment_id>', methods=['DELETE'])
@jwt_required()
@swag_from('docs/delete_appointment.yml')
def delete_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.delete(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/<appointment_id>/cancel', methods=['POST'])
@jwt_required()
@swag_from('docs/cancel_appointment.yml')
def cancel_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}/cancel'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/<appointment_id>/reschedule', methods=['PUT'])
@jwt_required()
@swag_from('docs/reschedule_appointment.yml')
def reschedule_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}/reschedule'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.put(service_url, json=request.get_json(), headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/doctor-availability/<doctor_id>', methods=['GET'])
@jwt_required()
@swag_from('docs/get_doctor_availability.yml')
def get_doctor_availability(doctor_id):
    service_url = f'http://localhost:5000/auth/doctors/{doctor_id}/availability'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/status/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from('docs/get_appointment_status.yml')
def get_appointment_status(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/status/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return response.content, response.status_code, response.headers.items()

@app.route('/appointments/search', methods=['GET'])
@jwt_required()
@swag_from('docs/search_appointments.yml')
def search_appointments():
    service_url = 'http://localhost:5001/api/appointments/search'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers, params=request.args)
    return response.content, response.status_code, response.headers.items()

if __name__ == '__main__':
    app.run(debug=True, port=8000)
