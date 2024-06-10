from pymongo import MongoClient
from flask import current_app
from datetime import datetime
from bson import ObjectId

class Appointment:
    def __init__(self, user, doctor, date_time, status="Scheduled"):
        self.user = user
        self.doctor = doctor
        self.date_time = date_time
        self.status = status
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def save_to_db(self):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        appointment_data = self.__dict__.copy()
        appointments.insert_one(appointment_data)

    @staticmethod
    def find_by_id(appointment_id):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        return appointments.find_one({'_id': ObjectId(appointment_id)})

    @staticmethod
    def find_by_user(user):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        return list(appointments.find({'user': user}))

    @staticmethod
    def find_by_doctor_and_date(doctor, date_time):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        return list(appointments.find({'doctor': doctor, 'date_time': date_time}))

    @staticmethod
    def update_appointment(appointment_id, update_fields):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        update_fields['updated_at'] = datetime.utcnow()
        appointments.update_one({'_id': ObjectId(appointment_id)}, {'$set': update_fields})

    @staticmethod
    def delete_appointment(appointment_id):
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.healthcare
        appointments = db.appointments
        appointments.delete_one({'_id': ObjectId(appointment_id)})
