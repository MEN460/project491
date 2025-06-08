"""
Authentication utilities for role-based access control.

Provides decorators and helpers for JWT-based authentication and authorization.
"""

from functools import wraps
from typing import Any, Callable, Optional, Union

from flask import jsonify, request, abort
from flask_jwt_extended import (
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt
)
from werkzeug.exceptions import Forbidden, Unauthorized

from models import User


def get_current_user() -> Optional[User]:
    """
    Retrieve the authenticated user from the JWT token.
    
    Returns:
        User: The authenticated user object.
    
    Raises:
        Unauthorized: If JWT is invalid or user is not found.
    """
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    if not user_id:
        raise Unauthorized("Missing or invalid user identity in token")

    user = User.query.get(user_id)
    if not user:
        raise Unauthorized("User not found")

    return user


def requires_role(required_role: str) -> Callable:
    """
    Decorator to enforce role-based access control.

    Args:
        required_role (str): Required role ('mechanic', 'car_owner', etc.)

    Usage:
        @jwt_required()
        @requires_role('mechanic')
        def dashboard():
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()

            # Enforce user role
            if user.user_type != required_role:
                raise Forbidden(
                    f"{required_role.capitalize()} role required. "
                    f"Your role: {user.user_type}"
                )

            # Check optional claims (e.g. account blacklist)
            claims = get_jwt()
            if claims.get("is_blacklisted", False):
                raise Forbidden("Account temporarily suspended")

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(fn: Callable) -> Callable:
    """
    Specialized decorator for admin-only access.

    Usage:
        @jwt_required()
        @admin_required
        def admin_panel():
            ...
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()

        if not getattr(user, "is_admin", False):
            raise Forbidden("Admin privileges required")

        return fn(*args, **kwargs)
    return wrapper


def get_authorized_user_or_404() -> User:
    """
    Get the current user or raise a 404 error.

    Use when the user must exist for the route to proceed.
    """
    user = get_current_user()
    if not user:
        abort(404, description="User account not found")
    return user
