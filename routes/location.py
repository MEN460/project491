# routes/location.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import db
from utils.auth import get_current_user
import logging

location_bp = Blueprint('location', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)


@location_bp.route('/update-location', methods=['POST'])
@jwt_required()
def update_location():
    """
    Allows any authenticated user (car_owner or mechanic) to update their location.
    """
    data = request.get_json()

    # Validate input fields exist
    if 'latitude' not in data or 'longitude' not in data:
        return jsonify({'error': 'Missing latitude or longitude'}), 400

    try:
        latitude = float(data['latitude'])
        longitude = float(data['longitude'])
    except (TypeError, ValueError):
        return jsonify({'error': 'Latitude and longitude must be valid numbers'}), 400

    # Validate coordinate ranges
    if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
        return jsonify({'error': 'Latitude must be between -90 and 90; longitude between -180 and 180'}), 400

    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found or unauthorized'}), 404

    # Update location
    user.current_latitude = latitude
    user.current_longitude = longitude
    db.session.commit()

    logger.info(
        f"{user.user_type.capitalize()} '{user.username}' updated location to ({latitude}, {longitude})")

    return jsonify({
        'message': 'Location updated successfully',
        'user_id': user.id,
        'role': user.user_type,
        'latitude': latitude,
        'longitude': longitude
    }), 200


@location_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "service": "location"}), 200
