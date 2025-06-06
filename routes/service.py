# routes/service.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import db, ServiceRequest, User
from datetime import datetime
from utils.auth import get_current_user, requires_role
import logging

service_bp = Blueprint('service', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)


@service_bp.route('/request-service', methods=['POST'])
@jwt_required()
@requires_role('car_owner')
def request_service():
    data = request.get_json()
    required_fields = ('latitude', 'longitude', 'description')
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    user = get_current_user()  # safe: already validated role
    new_request = ServiceRequest(
        car_owner_id=user.id,
        latitude=data['latitude'],
        longitude=data['longitude'],
        description=data['description']
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({
        'message': 'Service request created successfully',
        'request_id': new_request.id
    }), 201


@service_bp.route('/accept-request', methods=['POST'])
@jwt_required()
@requires_role('mechanic')
def accept_request():
    data = request.get_json()
    request_id = data.get('request_id')
    if not request_id:
        return jsonify({'error': 'Missing request_id'}), 400

    user = get_current_user()  # already verified as mechanic

    service_request = ServiceRequest.query.get(request_id)
    if not service_request:
        return jsonify({'error': 'Request not found'}), 404

    if service_request.status != 'pending':
        return jsonify({'error': 'Request is no longer pending'}), 400

    service_request.mechanic_id = user.id
    service_request.status = 'accepted'
    service_request.accepted_at = datetime.utcnow()
    db.session.commit()

    car_owner = User.query.get(service_request.car_owner_id)
    return jsonify({
        'message': 'Request accepted successfully',
        'request_id': service_request.id,
        'car_owner': car_owner.to_dict(),
        'mechanic': user.to_dict()
    }), 200


@service_bp.route('/nearby-requests', methods=['GET'])
@jwt_required()
def get_nearby_requests():
    try:
        latitude = float(request.args.get('latitude', 0))
        longitude = float(request.args.get('longitude', 0))

        pending_requests = ServiceRequest.query.filter_by(
            status='pending').all()

        return jsonify([r.to_dict() for r in pending_requests]), 200

    except Exception as e:
        logger.error(f"Nearby requests error: {str(e)}")
        return jsonify({'error': str(e)}), 400
