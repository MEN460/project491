# routes/mechanics.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import User
from math import radians, cos, sin, sqrt, atan2
from utils.auth import get_current_user, requires_role

mechanics_bp = Blueprint('mechanics', __name__, url_prefix='/api')


def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


@mechanics_bp.route('/nearby-mechanics', methods=['GET'])
@jwt_required()
@requires_role('car_owner')
def get_nearby_mechanics():
    """
    Allow only car owners to search for nearby mechanics.
    Accepts optional ?latitude=&longitude=&radius=
    """
    try:
        # Priority: query params > saved location
        lat_param = request.args.get('latitude')
        lon_param = request.args.get('longitude')

        if lat_param and lon_param:
            try:
                latitude = float(lat_param)
                longitude = float(lon_param)
            except ValueError:
                return jsonify({
                    "error": "Latitude and longitude must be valid numbers"
                }), 400
        else:
            user = get_current_user()
            if not user or not user.current_latitude or not user.current_longitude:
                return jsonify({
                    "error": "Location required",
                    "message": "Either provide coordinates or update your profile location"
                }), 400
            latitude = user.current_latitude
            longitude = user.current_longitude

        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({
                "error": "Invalid coordinates",
                "message": "Latitude must be -90 to 90, longitude -180 to 180"
            }), 400

        try:
            radius_km = float(request.args.get('radius', 10))
        except ValueError:
            return jsonify({
                "error": "Radius must be a valid number"
            }), 400

        mechanics = User.query.filter_by(user_type='mechanic').all()
        nearby = []

        for mech in mechanics:
            if mech.current_latitude and mech.current_longitude:
                dist = haversine(latitude, longitude,
                                 mech.current_latitude, mech.current_longitude)
                if dist <= radius_km:
                    data = mech.to_dict()
                    data['distance_km'] = round(dist, 2)
                    nearby.append(data)

        nearby.sort(key=lambda x: x['distance_km'])
        return jsonify(nearby), 200

    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500
