"""
Reusable rate limit decorators for Flask routes.
Encapsulates limiter instance and pre-defined per-endpoint limits.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialized in app.py, this must be imported back to avoid circular import
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Semantic aliases for route-specific rate limits
register_limit = limiter.limit("10 per hour")
login_limit = limiter.limit("5 per minute")
reset_password_limit = limiter.limit("3 per hour")
"""
Reusable rate limit decorators for Flask routes.
Encapsulates limiter instance and pre-defined per-endpoint limits.
"""


# Initialized in app.py, this must be imported back to avoid circular import
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Semantic aliases for route-specific rate limits
register_limit = limiter.limit("10 per hour")
login_limit = limiter.limit("5 per minute")
reset_password_limit = limiter.limit("3 per hour")
