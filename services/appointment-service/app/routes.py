from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Appointment
from datetime import datetime
from flasgger import swag_from
import logging
from bson import ObjectId
import requests

appointments = Blueprint('appointments', __name__)

@appointments.route('', methods=['POST'])
@jwt_required()
@swag_from('../docs/create_appointment.yml')
def create_appointment():
    data = request.get_json()
    current_user = get_jwt_identity()  # Get current user identity from JWT token
    doctor = data.get('doctor_id')
    date_time_str = data.get('date_time')

    logging.debug(f"Creating appointment for user: {current_user}, doctor: {doctor}, date_time: {date_time_str}")

    try:
        date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return jsonify({'message': 'Invalid date format. Please use the format: YYYY-MM-DDTHH:MM:SS'}), 400

    if date_time <= datetime.now():
        return jsonify({'message': 'Appointment date and time must be in the future'}), 400

    appointment = Appointment(current_user, doctor, date_time)
    appointment.save_to_db()
    return jsonify({'message': 'Appointment created successfully'}), 201

@appointments.route('/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_appointment.yml')
def get_appointment(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    appointment = Appointment.find_by_id(ObjectId(appointment_id))
    if not appointment:
        return jsonify({'message': 'Appointment not found'}), 404

    appointment['_id'] = str(appointment['_id'])
    return jsonify(appointment), 200

@appointments.route('', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_user_appointments.yml')
def get_user_appointments():
    current_user = get_jwt_identity()
    appointments = Appointment.find_by_user(current_user)
    for appointment in appointments:
        appointment['_id'] = str(appointment['_id'])
    return jsonify(appointments), 200

@appointments.route('/<appointment_id>', methods=['PUT'])
@jwt_required()
@swag_from('../docs/update_appointment.yml')
def update_appointment(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    data = request.get_json()
    update_fields = {}

    if 'doctor' in data:
        update_fields['doctor'] = data['doctor']
    if 'date_time' in data:
        try:
            update_fields['date_time'] = datetime.strptime(data['date_time'], '%Y-%m-%dT%H:%M:%S')
            if update_fields['date_time'] <= datetime.now():
                return jsonify({'message': 'Appointment date and time must be in the future'}), 400
        except ValueError:
            return jsonify({'message': 'Invalid date format'}), 400
    if 'status' in data:
        update_fields['status'] = data['status']

    Appointment.update_appointment(ObjectId(appointment_id), update_fields)
    return jsonify({'message': 'Appointment updated successfully'}), 200

@appointments.route('/<appointment_id>', methods=['DELETE'])
@jwt_required()
@swag_from('../docs/delete_appointment.yml')
def delete_appointment(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    Appointment.delete_appointment(ObjectId(appointment_id))
    return jsonify({'message': 'Appointment deleted successfully'}), 200

@appointments.route('/<appointment_id>/cancel', methods=['POST'])
@jwt_required()
@swag_from('../docs/cancel_appointment.yml')
def cancel_appointment(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    Appointment.update_appointment(ObjectId(appointment_id), {'status': 'Canceled'})
    return jsonify({'message': 'Appointment canceled successfully'}), 200

@appointments.route('/<appointment_id>/reschedule', methods=['PUT'])
@jwt_required()
@swag_from('../docs/reschedule_appointment.yml')
def reschedule_appointment(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    data = request.get_json()
    new_date_time_str = data.get('new_date_time')

    try:
        new_date_time = datetime.strptime(new_date_time_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return jsonify({'message': 'Invalid date format. Please use the format: YYYY-MM-DDTHH:MM:SS'}), 400

    if new_date_time <= datetime.now():
        return jsonify({'message': 'Appointment date and time must be in the future'}), 400

    Appointment.update_appointment(ObjectId(appointment_id), {'date_time': new_date_time})
    return jsonify({'message': 'Appointment rescheduled successfully'}), 200


@appointments.route('/doctor-availability/<doctor_id>', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_doctor_availability.yml')
def get_doctor_availability(doctor_id):
    if not doctor_id:
        return jsonify({'message': 'Doctor ID is required'}), 400

    api_gateway_url = f"http://api-gateway-url/appointments/doctor-availability/{doctor_id}"  # Replace with actual API Gateway URL
    headers = {
        'Authorization': request.headers.get('Authorization')
    }
    response = requests.get(api_gateway_url, headers=headers)

    if response.status_code == 404:
        return jsonify({'message': 'Doctor not found'}), 404
    elif response.status_code != 200:
        return jsonify({'message': 'Error fetching doctor data'}), response.status_code

    return jsonify(response.json()), 200

@appointments.route('/status/<appointment_id>', methods=['GET'])
@jwt_required()
@swag_from('../docs/get_appointment_status.yml')
def get_appointment_status(appointment_id):
    if not ObjectId.is_valid(appointment_id):
        return jsonify({'message': 'Invalid appointment ID'}), 400

    appointment = Appointment.find_by_id(ObjectId(appointment_id))
    if not appointment:
        return jsonify({'message': 'Appointment not found'}), 404

    return jsonify({'status': appointment['status']}), 200

@appointments.route('/search', methods=['GET'])
@jwt_required()
@swag_from('../docs/search_appointments.yml')
def search_appointments():
    doctor_id = request.args.get('doctor_id')
    status = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Logic to search appointments by criteria
    # Example: appointments = Appointment.search(criteria)
    appointments = []  # Replace with actual search logic
    return jsonify(appointments), 200
