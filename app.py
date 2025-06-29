# app.py
"""Main Flask application module."""

import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mailing import Mail
from flask_limiter.util import get_remote_address

from config import config
from models import db
from utils.mail import mail
from utils.rate_limit import limiter
from routes.auth import auth_bp
from routes.location import location_bp
from routes.service import service_bp
from routes.mechanics import mechanics_bp


# Initialize extensions
jwt = JWTManager()
mail = mail  # imported instance
limiter = limiter  # imported instance
# Note: db is imported from models


def create_app(config_name=None):
    # Tell Flask to use the instance folder for config & DB
    app = Flask(__name__, instance_relative_config=True)

    

    # Determine configuration
    cfg_name = config_name or os.getenv('FLASK_ENV', 'default')
    cfg_class = config.get(cfg_name, config['default'])
    app.config.from_object(cfg_class)
    cfg_class.init_app(app)

    # Ensure instance folder exists (for SQLite DB file, etc.)
    os.makedirs(app.instance_path, exist_ok=True)

    # If no external DATABASE_URL provided, point to instance/app.db
    if not app.config.get('SQLALCHEMY_DATABASE_URI'):
        db_path = os.path.join(app.instance_path, 'app.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"

    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    CORS(app, supports_credentials=True)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(location_bp)
    app.register_blueprint(service_bp)
    app.register_blueprint(mechanics_bp)

    # JWT error handlers
    register_jwt_callbacks(app)

    # Logging (only when not in debug)
    if not app.debug:
        setup_logging(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app


def register_jwt_callbacks(app):
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_expired',
            'message': 'The token has expired'
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'invalid_token',
            'message': 'Signature verification failed'
        }), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'authorization_required',
            'message': 'Request does not contain an access token'
        }), 401


def setup_logging(app):
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    log_file = os.path.join(logs_dir, 'app.log')
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10240, backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')



# Entry point
if __name__ == '__main__':
    app = create_app()
    @app.route('/')
    def home():
        return "Hello from Production Server!"
    app.run(host='0.0.0.0', port=5000, debug=True)
