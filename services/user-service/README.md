Here's the Markdown content for your `README.md` file. You can copy and paste this directly into your `README.md` file.

# User Service Microservice

This is the User Service microservice for the Healthcare Management System. It provides user authentication and authorization functionalities, including JWT-based authentication, role-based access control, and support for multi-factor authentication (MFA).

## Features

- User registration
- User login
- JWT-based authentication
- Role-based access control (RBAC) with roles: Admin, Patient, Doctor
- Multi-factor authentication (MFA)
- Password reset and change
- Email verification
- Swagger UI for API documentation

## Setup

### Prerequisites

- Python 3.8+
- MongoDB
- pip (Python package installer)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/healthcare-management-system.git
   cd healthcare-management-system/services/user-service
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\\Scripts\\activate`
   ```

3. **Install the dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   Create a `.env` file in the root of the `user-service` directory and add the following:
   ```plaintext
   FLASK_APP=run.py
   FLASK_ENV=development
   MONGO_URI=mongodb://localhost:27017/healthcare
   JWT_SECRET_KEY=your_jwt_secret_key
   ```

### Running the Application

1. **Start the Flask application**:
   ```bash
   flask run
   ```

2. **Access the Swagger UI**:
   Open your web browser and go to `http://localhost:5000/apidocs/` to access the Swagger UI and view the API documentation.

## API Endpoints

### Auth
- `POST /auth/register`: Register a new user
- `POST /auth/login`: User login
- `POST /auth/refresh`: Refresh JWT token
- `POST /auth/logout`: Logout user
- `POST /auth/change-password`: Change user password
- `POST /auth/forgot-password`: Request password reset email
- `POST /auth/confirm-reset-password`: Reset password using token
- `POST /auth/send-verification-email`: Send email verification link
- `GET /auth/verify-email`: Verify email using token
- `POST /auth/setup-mfa`: Set up multi-factor authentication (MFA)
- `POST /auth/verify-2fa`: Verify MFA code

### Admin
- `GET /auth/admin-only`: Admin-only access

### Profile
- `GET /auth/profile`: Get user profile

## Project Structure

```
healthcare-management-system/
├── services/
│   ├── user-service/
│   │   ├── app/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   ├── routes.py
│   │   │   ├── middlewares.py
│   │   │   ├── utils.py
│   │   │   └── swagger.py
│   │   ├── docs/
│   │   │   ├── register.yml
│   │   │   ├── login.yml
│   │   │   ├── profile.yml
│   │   │   ├── send_verification_email.yml
│   │   │   ├── verify_email.yml
│   │   │   ├── admin_only.yml
│   │   │   ├── setup_mfa.yml
│   │   │   ├── refresh.yml
│   │   │   ├── logout.yml
│   │   │   ├── change_password.yml
│   │   │   ├── forgot_password.yml
│   │   │   ├── confirm_reset_password.yml
│   │   │   ├── setup_2fa.yml
│   │   │   └── verify_2fa.yml
│   │   ├── config.py
│   │   ├── docker-compose.yml
│   │   ├── Dockerfile
│   │   ├── Procfile
│   │   ├── README.md
│   │   ├── requirements.txt
│   │   └── run.py
```

## Testing

To run the tests, use the following command:
```bash
pytest
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```

You can replace the contents of your `README.md` file with the above Markdown content. This will provide detailed instructions and information about your project.
