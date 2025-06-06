# routes/auth.py

from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from models import db, User
from flask import jsonify  # Add this import
from utils.auth import requires_role
import logging
from datetime import datetime, timedelta
from jose import jwt
import os
from flask_mailing import Mail, Message
from pydantic import EmailStr
from typing import Optional

auth_bp = Blueprint('auth', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)

# Configuration (should move to config.py in production)
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
RESET_TOKEN_EXPIRE_MINUTES = 30
PASSWORD_RESET_LIMIT = "5 per hour"

# Initialize Flask-Mail (should be initialized in app.py and imported here)
mail = Mail()


def create_reset_token(user_id: str) -> str:
    expires = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(user_id), "exp": expires, "type": "reset"}
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def verify_reset_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "reset":
            return None
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        logger.warning("Expired password reset token")
        return None
    except jwt.JWTError:
        logger.warning("Invalid password reset token")
        return None


@auth_bp.route('/register', methods=['POST'])
def register():
    """Endpoint for user registration"""
    data = request.get_json()

    # Normalize input fields
    if 'userType' in data:
        data['user_type'] = data['userType'].lower()

    required_fields = ('username', 'password', 'email', 'user_type')
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate user_type
    if data['user_type'] not in ['car_owner', 'mechanic']:
        return jsonify({'error': 'Invalid user type'}), 400

    # Sanitize inputs
    username = data['username'].strip().lower()
    email = data['email'].strip().lower()

    # Validate password strength
    if len(data['password']) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        # Check for existing user
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400

        new_user = User(
            username=username,
            password=generate_password_hash(data['password']),
            email=email,
            user_type=data['user_type'],
            phone=data.get('phone', '').strip()
        )

        db.session.add(new_user)
        db.session.commit()

        logger.info(f"New user registered: {username} ({data['user_type']})")

        return jsonify({
            'message': 'User registered successfully',
            'user_id': new_user.id
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    """Endpoint for user login"""
    data = request.get_json()

    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400

    username = data['username'].strip().lower()
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(
        identity=str(user.id),
        expires_delta=timedelta(hours=1),
        additional_claims={'user_type': user.user_type}
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    logger.info(f"User logged in: {username}")

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user_id': user.id,
        'user_type': user.user_type,
        'message': 'Login successful'
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Endpoint for refreshing access tokens"""
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    new_token = create_access_token(
        identity=str(user.id),
        expires_delta=timedelta(hours=1),
        additional_claims={'user_type': user.user_type}
    )

    return jsonify({
        'access_token': new_token,
        'user_id': user.id,
        'user_type': user.user_type
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user_profile():
    """Endpoint to get current user's profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(user.to_dict()), 200


@auth_bp.route('/request-password-reset', methods=['POST'])
async def request_password_reset():
    """Endpoint to request password reset"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal whether email exists for security
        logger.info(
            f"Password reset requested for non-existent email: {email}")
        return jsonify({'message': 'If this email exists, a reset link has been sent'}), 200

    # Generate reset token
    reset_token = create_reset_token(user.id)
    reset_url = f"https://yourapp.com/reset-password?token={reset_token}"

    # Send email
    message = Message(
        subject="Password Reset Request",
        recipients=[email],
        body=f"""
        You requested a password reset. Click the link below to reset your password:
        {reset_url}
        
        This link will expire in {RESET_TOKEN_EXPIRE_MINUTES} minutes.
        If you didn't request this, please ignore this email.
        """,
        subtype="plain"
    )

    try:
        await mail.send_message(message)
        logger.info(f"Password reset email sent to {email}")
        return jsonify({'message': 'If this email exists, a reset link has been sent'}), 200
    except Exception as e:
        logger.error(f"Failed to send reset email to {email}: {str(e)}")
        return jsonify({'error': 'Failed to send reset email'}), 500


@auth_bp.route('/validate-reset-token', methods=['POST'])
def validate_reset_token():
    """Endpoint to validate reset token before showing password reset form"""
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'error': 'Token is required'}), 400

    user_id = verify_reset_token(token)
    if not user_id:
        return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 400

    return jsonify({'valid': True, 'user_id': user_id}), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Endpoint to actually reset the password"""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400

    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        user_id = verify_reset_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update password
        user.password = generate_password_hash(new_password)
        db.session.commit()

        logger.info(f"Password reset for user {user.id}")
        return jsonify({'message': 'Password updated successfully'}), 200

    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({'error': 'Password reset failed'}), 400
