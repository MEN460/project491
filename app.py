from flask import Flask
from flask_cors import CORS
from flask import jsonify  # Add this import
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mailing import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from models import db
from routes.auth import auth_bp
from routes.location import location_bp
from routes.service import service_bp
from routes.mechanics import mechanics_bp
import logging
from logging.handlers import RotatingFileHandler
import os

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app) # This allows all domains to make requests
CORS(app, supports_credentials=True)

# # Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disables warning
# Shows SQL queries in console (great for debugging)
app.config['SQLALCHEMY_ECHO'] = True

# Configure Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # Explicitly use memory storage (dev only)
)

# Configure logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler(
        'logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)

# Configure email
mail = Mail(app)  # Uses MAIL_* settings from Config

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(location_bp)
app.register_blueprint(service_bp)
app.register_blueprint(mechanics_bp)

# JWT configuration


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


# Entry point
if __name__ == '__main__':
    # Ensure database tables are created before the server starts
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=5000, debug=True)
