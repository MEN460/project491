"""
Reusable validators for user input fields and business logic rules.
"""

import re
from models import User


def validate_password_strength(password: str) -> bool:
    """
    Ensures password has at least 8 characters with letters, numbers, and symbols.
    """
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[\W_]", password):  # special character
        return False
    return True


def validate_username_format(username: str) -> bool:
    """
    Ensures username is alphanumeric or underscore, 3-30 chars.
    """
    return re.match(r"^[a-zA-Z0-9_]{3,30}$", username) is not None


def validate_unique_email(email: str) -> bool:
    """
    Returns True if email is NOT used (i.e., is valid for registration).
    """
    return User.query.filter_by(email=email.lower()).first() is None


def validate_unique_username(username: str) -> bool:
    """
    Returns True if username is NOT used (i.e., is valid for registration).
    """
    return User.query.filter_by(username=username.lower()).first() is None
