import os
from datetime import timedelta


class Config:
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///mechanic_finder.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ['headers', 'cookies']

    # Email Configuration (for password reset)
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() in [
        "true", "1", "on"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "your-email@gmail.com")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "your-email-password")
    MAIL_DEFAULT_SENDER = os.getenv(
        "MAIL_DEFAULT_SENDER", "no-reply@mechanicfinder.com")

    # Password Reset Configuration
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 30
    PASSWORD_RESET_URL = os.getenv(
        "PASSWORD_RESET_URL", "https://yourfrontend.com/reset-password")

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "your-application-secret-key")
    SECURITY_PASSWORD_SALT = os.getenv(
        "SECURITY_PASSWORD_SALT", "your-password-salt")

    # Rate Limiting
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_AUTH_ENDPOINTS = "10 per minute"

    # Application Settings
    APP_NAME = "Mechanic Finder"
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

    # Logging
    LOG_FILE = os.getenv("LOG_FILE", "instance/app.log")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        hours=3)  # Longer tokens for development


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MAIL_SUPPRESS_SEND = True  # Don't send emails during tests


class ProductionConfig(Config):
    DEBUG = False
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_CSRF_PROTECT = True


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}
