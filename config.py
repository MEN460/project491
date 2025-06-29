import os
from datetime import timedelta
from typing import Dict, Type


class Config:
    """Base configuration with environment-aware defaults."""

    # Core Application Settings
    APP_NAME: str = "Mechanic Finder"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure-dev-key-change-me")
    ENV: str = os.getenv("FLASK_ENV", "development")
    DEBUG: bool = False
    TESTING: bool = False

    # Database URI: set in init_app if not provided via DATABASE_URL
    SQLALCHEMY_DATABASE_URI: str = None
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: Dict = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # Authentication & Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(days=30)
    JWT_TOKEN_LOCATION: list = ['headers', 'cookies']
    JWT_COOKIE_SECURE: bool = False  # Should be True in production
    JWT_COOKIE_SAMESITE: str = "Lax"
    SECURITY_PASSWORD_SALT: str = os.getenv(
        "SECURITY_PASSWORD_SALT", "insecure-salt-change-me"
    )

    # Email Configuration
    MAIL_SERVER: str = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT: int = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS: bool = os.getenv("MAIL_USE_TLS", "true").lower() in [
        "true", "1", "on"]
    MAIL_USERNAME: str = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.getenv(
        "MAIL_DEFAULT_SENDER", "no-reply@mechanicfinder.com"
    )
    MAIL_SUPPRESS_SEND: bool = False  # Override in TestingConfig

    # Frontend Integration
    FRONTEND_BASE_URL: str = os.getenv(
        "FRONTEND_BASE_URL", "http://localhost:3000")
    PASSWORD_RESET_URL: str = f"{FRONTEND_BASE_URL}/reset-password"
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # Rate Limiting
    RATELIMIT_DEFAULT: str = "200 per day, 50 per hour"
    RATELIMIT_AUTH_ENDPOINTS: str = "10 per minute"
    RATELIMIT_STORAGE_URI: str = os.getenv(
        "RATELIMIT_STORAGE_URI", "memory://")

    # Logging Configuration
    LOG_FILE: str = os.getenv(
        "LOG_FILE",
        os.path.join(os.path.dirname(__file__), "../logs/app.log")
    )
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    @staticmethod
    def init_app(app):
        """Initialize Flask application with configuration."""
        # Ensure instance directory exists
        os.makedirs(app.instance_path, exist_ok=True)

        # If no DATABASE_URL in env, set SQLite at instance/app.db
        if not app.config.get('SQLALCHEMY_DATABASE_URI'):
            db_path = os.path.join(app.instance_path, 'app.db')
            app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"


class DevelopmentConfig(Config):
    """Development-specific configuration."""
    DEBUG: bool = True
    SQLALCHEMY_ECHO: bool = True
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(hours=3)
    LOG_LEVEL: str = "DEBUG"


class TestingConfig(Config):
    """Testing configuration with isolated environment."""
    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    MAIL_SUPPRESS_SEND: bool = True
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(seconds=30)
    RATELIMIT_DEFAULT: str = "1000 per hour"


class ProductionConfig(Config):
    """Production configuration with security optimizations."""
    DEBUG: bool = False
    JWT_COOKIE_SECURE: bool = True
    JWT_COOKIE_CSRF_PROTECT: bool = True
    LOG_LEVEL: str = "WARNING"

    @staticmethod
    def init_app(app):
        super().init_app(app)
        # Add any production-specific initialization here


# Registry of available configurations
config: Dict[str, Type[Config]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
