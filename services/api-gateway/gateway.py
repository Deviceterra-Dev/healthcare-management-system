from flask import Flask, request, jsonify
import requests
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_jwt_secret_key'

def validate_token(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded_token
    except Exception as e:
        return None

@app.before_request
def authenticate_request():
    token = None
    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1]

    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    decoded_token = validate_token(token)
    if not decoded_token:
        return jsonify({'message': 'Token is invalid!'}), 401

    request.user = decoded_token

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    service_url = f"http://user-service:5000/{path}"  # Adjust this as needed
    headers = {key: value for key, value in request.headers if key != 'Host'}
    response = requests.request(
        method=request.method,
        url=service_url,
        headers=headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    return (response.content, response.status_code, response.headers.items())

if __name__ == '__main__':
    app.run(debug=True, port=8000)
