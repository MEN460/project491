# models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(20))
    current_latitude = db.Column(db.Float)
    current_longitude = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'user_type': self.user_type,
            'phone': self.phone,
            'current_latitude': self.current_latitude,
            'current_longitude': self.current_longitude
        }


class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    car_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    mechanic_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'car_owner_id': self.car_owner_id,
            'mechanic_id': self.mechanic_id,
            'status': self.status,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
