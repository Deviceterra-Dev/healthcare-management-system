from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
import logging
import os
from config import config_by_name
from app.swagger import init_swagger

mail = Mail()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions
    jwt = JWTManager(app)
    swagger = init_swagger(app)
    CORS(app)
    mail.init_app(app)

    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Register blueprints
    from app.routes import auth
    app.register_blueprint(auth, url_prefix='/auth')

    return app

if __name__ == '__main__':
    config_name = os.getenv('FLASK_ENV', 'development')
    app = create_app(config_name)
    app.run(host='0.0.0.0', port=5000)
