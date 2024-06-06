from flask import Flask, request, jsonify
from flasgger import Swagger, swag_from
import requests
import jwt  # Import the jwt package for decoding
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,  # all endpoints
            "model_filter": lambda tag: True,  # all models
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
    ],
}


swagger = Swagger(app, config=swagger_config)

# Initialize JWT Manager
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

    token = None
    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1]

    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    decoded_token = validate_token(token)
    if not decoded_token:
        return jsonify({'message': 'Token is invalid!'}), 401

    request.user = decoded_token

# User Service Endpoints
@app.route('/auth/register', methods=['POST'])
@swag_from('docs/register.yml')
def register():
    service_url = 'http://localhost:5000/auth/register'
    response = requests.post(service_url, json=request.get_json())
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/login', methods=['POST'])
@swag_from('docs/login.yml')
def login():
    service_url = 'http://localhost:5000/auth/login'
    response = requests.post(service_url, json=request.get_json())
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/profile', methods=['GET'])
@jwt_required()
@swag_from('docs/profile.yml')
def profile():
    service_url = 'http://localhost:5000/auth/profile'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/send-verification-email', methods=['POST'])
@jwt_required()
@swag_from('docs/send_verification_email.yml')
def send_verification_email():
    service_url = 'http://localhost:5000/auth/send-verification-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/verify-email', methods=['GET'])
@jwt_required()
@swag_from('docs/verify_email.yml')
def verify_email():
    service_url = 'http://localhost:5000/auth/verify-email'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers, params=request.args)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/admin-only', methods=['GET'])
@jwt_required()
@swag_from('docs/admin_only.yml')
def admin_only():
    service_url = 'http://localhost:5000/auth/admin-only'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/setup-mfa', methods=['POST'])
@jwt_required()
@swag_from('docs/setup_mfa.yml')
def setup_mfa():
    service_url = 'http://localhost:5000/auth/setup-mfa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
@swag_from('docs/refresh.yml')
def refresh():
    service_url = 'http://localhost:5000/auth/refresh'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
@swag_from('docs/logout.yml')
def logout():
    service_url = 'http://localhost:5000/auth/logout'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/change-password', methods=['POST'])
@jwt_required()
@swag_from('docs/change_password.yml')
def change_password():
    service_url = 'http://localhost:5000/auth/change-password'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/forgot-password', methods=['POST'])
@swag_from('docs/forgot_password.yml')
def forgot_password():
    service_url = 'http://localhost:5000/auth/forgot-password'
    response = requests.post(service_url, json=request.get_json())
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/confirm-reset-password', methods=['POST'])
@swag_from('docs/confirm_reset_password.yml')
def confirm_reset_password():
    service_url = 'http://localhost:5000/auth/confirm-reset-password'
    response = requests.post(service_url, json=request.get_json())
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/setup-2fa', methods=['POST'])
@jwt_required()
@swag_from('docs/setup_2fa.yml')
def setup_2fa():
    service_url = 'http://localhost:5000/auth/setup-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/auth/verify-2fa', methods=['POST'])
@jwt_required()
@swag_from('docs/verify_2fa.yml')
def verify_2fa():
    service_url = 'http://localhost:5000/auth/verify-2fa'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

# Appointment Service Endpoints
@app.route('/appointments', methods=['POST'])
@jwt_required()
@swag_from('docs/create_appointment.yml')
def create_appointment():
    service_url = 'http://localhost:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.post(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/appointments/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from('docs/get_appointment.yml')
def get_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/appointments', methods=['GET'])
@jwt_required()
@swag_from('docs/get_user_appointments.yml')
def get_user_appointments():
    service_url = 'http://localhost:5001/api/appointments'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.get(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/appointments/<appointment_id>', methods=['PUT'])
@jwt_required()
@swag_from('docs/update_appointment.yml')
def update_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.put(service_url, json=request.get_json(), headers=headers)
    return (response.content, response.status_code, response.headers.items())

@app.route('/appointments/<appointment_id>', methods=['DELETE'])
@jwt_required()
@swag_from('docs/delete_appointment.yml')
def delete_appointment(appointment_id):
    service_url = f'http://localhost:5001/api/appointments/{appointment_id}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.delete(service_url, headers=headers)
    return (response.content, response.status_code, response.headers.items())

if __name__ == '__main__':
    app.run(debug=True, port=8000)
