
# Healthcare Management System

This repository contains a healthcare management system implemented as a set of microservices. Each microservice handles a specific domain within the system.

## Table of Contents

- [Healthcare Management System](#healthcare-management-system)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Services](#services)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the System](#running-the-system)
  - [API Endpoints](#api-endpoints)
    - [User Service](#user-service)
    - [Appointment Service](#appointment-service)
  - [License](#license)

## Overview

This project aims to provide a comprehensive solution for managing various aspects of healthcare, including user management, appointment scheduling, and more. It is built using a microservices architecture to ensure scalability and maintainability.

## Services

- **User Service**: Manages user registration, authentication, and profile management.
- **Appointment Service**: Manages scheduling, retrieving, updating, and deleting appointments.
- **...** (other services can be added similarly)

## Prerequisites

- Docker
- Docker Compose
- MongoDB

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-username/healthcare-system.git
   cd healthcare-system
   ```

2. **Create Environment Variables**

   Create a `.env` file in the root of the project directory with the following content:

   ```env
   SECRET_KEY=your_secret_key
   MONGO_URI=mongodb://mongo:27017
   JWT_SECRET_KEY=your_jwt_secret_key
   ```

## Running the System

1. **Start Docker Compose**

   ```bash
   docker-compose up --build
   ```

2. **Access the Services**

   - User Service: `http://localhost:5000`
   - Appointment Service: `http://localhost:5001`

## API Endpoints

### User Service

- **Register a User**
  - **Endpoint**: `POST /api/auth/register`
  - **Headers**: `Content-Type: application/json`
  - **Body**:
    ```json
    {
      "username": "testuser",
      "password": "password123",
      "email": "testuser@example.com",
      "phone": "1234567890",
      "role": "patient"
    }
    ```

- **Login a User**
  - **Endpoint**: `POST /api/auth/login`
  - **Headers**: `Content-Type: application/json`
  - **Body**:
    ```json
    {
      "username": "testuser",
      "password": "password123"
    }
    ```

- **Get User Profile**
  - **Endpoint**: `GET /api/auth/profile`
  - **Headers**: `Authorization: Bearer {token}`

- **Update User Profile**
  - **Endpoint**: `PUT /api/auth/profile`
  - **Headers**: `Authorization: Bearer {token}`, `Content-Type: application/json`
  - **Body**:
    ```json
    {
      "email": "newemail@example.com",
      "phone": "0987654321",
      "profile_picture": "new_profile_picture_url"
    }
    ```

### Appointment Service

- **Create an Appointment**
  - **Endpoint**: `POST /api/appointments`
  - **Headers**: `Authorization: Bearer {token}`, `Content-Type: application/json`
  - **Body**:
    ```json
    {
      "doctor": "Dr. John Doe",
      "date_time": "2024-06-01 14:00:00"
    }
    ```

- **Get an Appointment**
  - **Endpoint**: `GET /api/appointments/{appointment_id}`
  - **Headers**: `Authorization: Bearer {token}`

- **Get All Appointments for a User**
  - **Endpoint**: `GET /api/appointments`
  - **Headers**: `Authorization: Bearer {token}`

- **Update an Appointment**
  - **Endpoint**: `PUT /api/appointments/{appointment_id}`
  - **Headers**: `Authorization: Bearer {token}`, `Content-Type: application/json`
  - **Body**:
    ```json
    {
      "doctor": "Dr. Jane Smith",
      "date_time": "2024-06-02 10:00:00",
      "status": "rescheduled"
    }
    ```

- **Delete an Appointment**
  - **Endpoint**: `DELETE /api/appointments/{appointment_id}`
  - **Headers**: `Authorization: Bearer {token}`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

