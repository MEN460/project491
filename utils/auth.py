from flask_jwt_extended import get_jwt_identity
from functools import wraps
from flask import jsonify
from models import User


def get_current_user():
    """
    Extract the current user from the JWT token.
    """
    try:
        user_id = int(get_jwt_identity())
        return User.query.get(user_id)
    except Exception:
        return None


def requires_role(required_role):
    """
    Enforce that the current user has the specified role (e.g., 'mechanic', 'car_owner').

    Usage:
        @jwt_required()
        @requires_role('mechanic')
        def route(): ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'User not found or unauthorized'}), 401
            if user.user_type != required_role:
                return jsonify({'error': f'{required_role.capitalize()} role required'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
