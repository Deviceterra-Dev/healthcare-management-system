from flask import Flask
from flasgger import Swagger
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_jwt_secret_key'
    app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/healthcare'

    jwt = JWTManager(app)

    swagger = Swagger(app)

    from app.routes import auth
    app.register_blueprint(auth, url_prefix='/auth')

    return app
