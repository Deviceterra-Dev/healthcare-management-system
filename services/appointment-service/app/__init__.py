from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from prometheus_flask_exporter import PrometheusMetrics
from app.routes import appointments
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    jwt = JWTManager(app)

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
        ],
    }

    swagger = Swagger(app, config=swagger_config)

    metrics = PrometheusMetrics(app)  # Initialize Prometheus Metrics

    app.register_blueprint(appointments, url_prefix='/api/appointments')

    return app
