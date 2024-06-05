from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from .routes import auth
from .swagger import swagger

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    jwt = JWTManager(app)

    app.register_blueprint(auth, url_prefix='/auth')

    swagger.init_app(app)

    return app
