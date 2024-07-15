```markdown
# Healthcare Management System

## Overview

This project is a microservices-based healthcare management system designed to facilitate efficient management of medical appointments, user authentication, and document storage. It includes the following services:

- **API Gateway Service**
- **Appointment Service**
- **User Service**

## Microservices

### API Gateway Service
- **Purpose**: Acts as a single entry point for all client requests, routing them to the appropriate microservices.
- **Key Features**:
  - JWT Authentication and Authorization
  - Rate Limiting
  - Caching with Redis
  - Swagger API Documentation
  - Prometheus Metrics

### Appointment Service
- **Purpose**: Manages appointments between patients and doctors.
- **Key Features**:
  - CRUD operations for appointments
  - JWT Authentication
  - Swagger API Documentation
  - Prometheus Metrics

### User Service
- **Purpose**: Manages user data and authentication.
- **Key Features**:
  - User Registration and Login
  - JWT Authentication
  - Role-Based Access Control
  - Multi-Factor Authentication (MFA)
  - Email Verification
  - Swagger API Documentation

## Configuration and Deployment

The project uses Docker Compose to manage multi-container Docker applications, including MongoDB and Redis.

### Services
- `user-service`
- `api-gateway`
- `appointment-service`
- `mongo`
- `redis`
- `prometheus`
- `grafana`

## How to Run the App in a Development Environment

### Prerequisites
- Docker
- Docker Compose

### Steps to Run

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/healthcare-management-system.git
   cd healthcare-management-system
   ```

2. **Set Up Environment Variables**

   Create a `.env` file in the root directory of the project with the following content:

   ```env
   SECRET_KEY=your_secret_key
   MONGO_URI=mongodb://mongo:27017/healthcare
   JWT_SECRET_KEY=your_jwt_secret_key
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USE_SSL=False
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_email_password
   MAIL_DEFAULT_SENDER=your_email@gmail.com
   FRONTEND_URL=http://localhost:3000
   ```

3. **Build and Run the Containers**
   ```bash
   docker-compose up --build
   ```

4. **Access the Services**
   - **API Gateway**: `http://localhost:8000`
   - **User Service**: `http://localhost:5000`
   - **Appointment Service**: `http://localhost:5001`
   - **MongoDB**: `mongodb://localhost:27017`
   - **Redis**: `redis://localhost:6379`
   - **Prometheus**: `http://localhost:9090`
   - **Grafana**: `http://localhost:3000`

### Notes
- Ensure that ports `5000`, `5001`, `8000`, `27017`, `6379`, `9090`, and `3000` are not in use by other applications.
- The default credentials for Grafana are `admin` for both the username and password. Change the password immediately after the first login.

### Documentation
- API documentation for each service is available at `/apidocs` endpoint of each service.

### Example API Requests
- **Register a User**: `POST /auth/register`
- **Login**: `POST /auth/login`
- **Create Appointment**: `POST /api/appointments`

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
