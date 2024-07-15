from flasgger import Swagger

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

template = {
    "swagger": "2.0",
    "info": {
        "title": "Healthcare Management System API",
        "description": "API documentation for the Healthcare Management System",
        "contact": {
            "responsibleOrganization": "Healthcare Solutions Inc.",
            "responsibleDeveloper": "Dev Team",
            "email": "devteam@healthcare-solutions.com",
            "url": "https://www.healthcare-solutions.com",
        },
        "termsOfService": "https://www.healthcare-solutions.com/terms",
        "version": "1.0"
    },
    "basePath": "/",  # base path for blueprint registration
    "schemes": [
        "https",  # Ensure HTTPS is used
        "http"
    ],
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

def init_swagger(app):
    swagger = Swagger(app, config=swagger_config, template=template)
    return swagger
