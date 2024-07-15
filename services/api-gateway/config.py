import os
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_jwt_secret_key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
    
    SWAGGER = {
        'title': 'API Gateway',
        'uiversion': 3
    }
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_HOST = os.getenv('CACHE_REDIS_HOST', 'localhost')
    CACHE_REDIS_PORT = int(os.getenv('CACHE_REDIS_PORT', 6379))
    CACHE_REDIS_DB = int(os.getenv('CACHE_REDIS_DB', 0))
    CACHE_REDIS_URL = os.getenv('CACHE_REDIS_URL', 'redis://localhost:6379/0')

    # Flask-Limiter configuration
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'redis://localhost:6379/1')

    SWAGGER_CONFIG = {
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

    SWAGGER_TEMPLATE = {
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

    RATELIMIT_STORAGE_URL = "redis://redis:6379/0"
    CACHE_TYPE = "redis"
    CACHE_REDIS_URL = "redis://redis:6379/0"
