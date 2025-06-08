# models.py

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import or_
import logging

logger = logging.getLogger(__name__)
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    _password = db.Column("password", db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(20))
    current_latitude = db.Column(db.Float)
    current_longitude = db.Column(db.Float)

    # ------------------------
    # Password handling
    # ------------------------

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, plain_password):
        self._password = generate_password_hash(plain_password)

    def check_password(self, plain_password) -> bool:
        result = check_password_hash(self._password, plain_password)
        logger.debug(
            f"[User: {self.username}] Password check: {'PASS' if result else 'FAIL'}"
        )
        return result

    def update_password(self, new_password: str):
        self.password = new_password
        db.session.commit()
        logger.info(f"[User: {self.username}] Password updated")

    # ------------------------
    # Authentication & lookup
    # ------------------------

    @classmethod
    def authenticate(cls, login_id: str, password: str):
        user = cls.query.filter(
            or_(cls.email == login_id.lower(), cls.username == login_id.lower())
        ).first()
        if user and user.check_password(password):
            return user
        return None

    @classmethod
    def exists(cls, **kwargs) -> bool:
        return db.session.query(cls.id).filter_by(**kwargs).first() is not None

    # ------------------------
    # Serialization
    # ------------------------

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'user_type': self.user_type,
            'phone': self.phone,
            'current_latitude': self.current_latitude,
            'current_longitude': self.current_longitude,
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

    def to_dict(self) -> dict:
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
