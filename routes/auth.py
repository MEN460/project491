"""
Authentication routes for user registration, login, and password management.
Includes JWT token generation, password reset flows, and user profile endpoints.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    current_user,
    get_jti
)
from jose import jwt, JWTError, ExpiredSignatureError
from pydantic import BaseModel, EmailStr
from utils.mail import EmailService
from utils.rate_limit import register_limit, login_limit, reset_password_limit
from utils.validators import (
    validate_password_strength,
    validate_username_format,
    validate_unique_email,
    validate_unique_username
)
from models import db, User

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

RESET_TOKEN_EXPIRE_MINUTES = 30

# -----------------------------
# Request schemas (Pydantic)
# -----------------------------


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    user_type: str
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    login_id: str
    password: str


class PasswordResetRequest(BaseModel):
    token: str
    new_password: str

# -----------------------------
# Auth Endpoints
# -----------------------------


@auth_bp.route('/register', methods=['POST'])
@register_limit
def register():
    """Register a new user account."""
    try:
        data = RegisterRequest(**request.get_json())
    except ValueError as e:
        logger.warning(f"Invalid registration data: {str(e)}")
        return jsonify({'error': str(e)}), 400

    if data.user_type.lower() not in {'car_owner', 'mechanic'}:
        return jsonify({'error': 'Invalid user type'}), 400

    if not validate_username_format(data.username):
        return jsonify({'error': 'Invalid username format'}), 400

    if not validate_unique_username(data.username):
        return jsonify({'error': 'Username already exists'}), 409

    if not validate_unique_email(data.email):
        return jsonify({'error': 'Email already exists'}), 409

    if not validate_password_strength(data.password):
        return jsonify({
            'error': 'Password must be 8+ chars with mix of upper, lower, number, and symbol'
        }), 400

    try:
        new_user = User(
            username=data.username.lower(),
            email=data.email.lower(),
            password=data.password,
            user_type=data.user_type,
            phone=data.phone
        )
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"New user registered: {new_user.id}")
        return jsonify({'message': 'Registration successful', 'user_id': new_user.id}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/login', methods=['POST'])
@login_limit
def login():
    """Authenticate user and return JWT tokens."""
    try:
        data = LoginRequest(**request.get_json())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    user = User.authenticate(data.login_id, data.password)
    if not user:
        logger.warning(f"Failed login for: {data.login_id}")
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'user_type': user.user_type,
            'is_admin': getattr(user, 'is_admin', False)
        }
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    logger.info(f"User logged in: {user.id}")
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh an access token."""
    user = current_user
    if not user:
        return jsonify({'error': 'User not found'}), 404

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'user_type': user.user_type,
            'is_admin': getattr(user, 'is_admin', False)
        }
    )
    return jsonify({'access_token': access_token}), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user_profile():
    """Get current user's profile."""
    return jsonify(current_user.to_dict()), 200


@auth_bp.route('/request-password-reset', methods=['POST'])
@reset_password_limit
async def request_password_reset():
    """Initiate password reset flow."""
    email = request.json.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        reset_token = create_reset_token(user.id)
        await EmailService.send_password_reset(user.email, reset_token)

    logger.info(f"Password reset requested for {email}")
    return jsonify({'message': 'If this email exists, a reset link has been sent'}), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Perform password reset using a token."""
    try:
        data = PasswordResetRequest(**request.get_json())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    user_id = verify_reset_token(data.token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not validate_password_strength(data.new_password):
        return jsonify({'error': 'Password does not meet security requirements'}), 400

    user.update_password(data.new_password)
    logger.info(f"Password updated for user {user.id}")
    return jsonify({'message': 'Password reset successful'}), 200

# -----------------------------
# Helper Functions
# -----------------------------


def create_reset_token(user_id: str) -> str:
    """Generate a time-limited password reset token."""
    expires = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "exp": expires,
        "type": "reset",
        "jti": get_jti({"sub": str(user_id)})
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")


def verify_reset_token(token: str) -> Optional[str]:
    """Decode and verify reset token, return user ID."""
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=["HS256"]
        )
        if payload.get("type") != "reset":
            return None
        return payload.get("sub")
    except ExpiredSignatureError:
        logger.warning("Expired reset token")
        return None
    except JWTError as e:
        logger.warning(f"Invalid reset token: {str(e)}")
        return None
