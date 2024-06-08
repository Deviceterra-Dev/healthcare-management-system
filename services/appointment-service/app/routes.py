from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Appointment
from datetime import datetime
from flasgger import swag_from
import logging
from bson import ObjectId

appointments = Blueprint('appointments', __name__)

def is_doctor_available(doctor, date_time):
    # Implement the logic to check if the doctor is available at the given date_time
    appointments = Appointment.find_by_doctor_and_date(doctor, date_time)
    return len(appointments) == 0

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Appointment
from datetime import datetime
from flasgger import swag_from
import logging

appointments = Blueprint('appointments', __name__)

@appointments.route('', methods=['POST'])
@jwt_required()
@swag_from('../docs/create_appointment.yml')
def create_appointment():
    data = request.get_json()
    current_user = get_jwt_identity()  # Get current user identity from JWT token
    doctor = data.get('doctor')
    date_time_str = data.get('date_time')

    logging.debug(f"Creating appointment for user: {current_user}, doctor: {doctor}, date_time: {date_time_str}")

    try:
        date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return jsonify({'message': 'Invalid date format. Please use the format: YYYY-MM-DDTHH:MM:SS'}), 400

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
            update_fields['date_time'] = datetime.strptime(data['date_time'], '%Y-%m-%d %H:%M:%S')
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
