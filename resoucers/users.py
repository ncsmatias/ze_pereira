import bcrypt
from flask import request, make_response, jsonify, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity
from model.user_model import UserModel
from blocklist import BLOCKLIST

user_bp = Blueprint('user', __name__)

@user_bp.route('/user', methods=['POST'])
@jwt_required()
def create_user():
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response(jsonify({'message': 'Unauthorized: Only administrators can create a new user.'}), 401)
    
    data = request.get_json()
    password = data.pop('password')
    password_bytes = password.encode('utf-8')
    hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    hash_decode = hash.decode('utf-8')
    new_user = UserModel(**data, password=hash_decode)
    new_user.save_user()

    return make_response(jsonify({'message': 'user created'}), 201)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error creating user', 'error': str(e)}), 500)

@user_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response(jsonify({'message': 'Unauthorized: Only administrators can list all users.'}), 401)
    
    data = [user.json() for user in UserModel.query.all()]
    return make_response(jsonify(data), 200)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error getting user', 'error': str(e)}), 500)

@user_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user_by_id():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
        return make_response(jsonify({'message': 'user not find'}), 404)
    
    return make_response(jsonify(data.json()), 200)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error getting user', 'error': str(e)}), 500)

@user_bp.route('/user', methods=['PUT'])
@jwt_required()
def update_user():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response(jsonify({'message': 'user not find'}), 404)
    
    body = request.get_json()
    data.update_user(**body)
    data.save_user()

    return make_response(jsonify(data.json()), 200)

  except Exception as e:
    return make_response(jsonify({'message': 'error updating user', 'error': str(e)}), 500)

@user_bp.route('/user', methods=['DELETE'])
@jwt_required()
def delete_user():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response(jsonify({'message': 'user not find'}), 404)

    data.delete_user()
    return make_response(jsonify({'message': 'user deleted'}), 200)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error deleting user', 'error': str(e)}), 500)

@user_bp.route('/user/admin/<string:id>', methods=['PUT'])
@jwt_required()
def turn_user_admin(id):
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response(jsonify({'message': 'Unauthorized: Only administrators can create a admin user.'}), 401)
    
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response(jsonify({'message': 'user not find'}), 404)
    
    data.turn_admin_user()
    data.save_user()

    return make_response(jsonify(data.json()), 200)
  except Exception as e:
    return make_response(jsonify({'message': 'error turning user admin', 'error': str(e)}), 500)
  
@user_bp.route('/login', methods=['POST'])
def login():
  try:
    body = request.get_json()
    email = body['email']
    password = body['password']

    data = UserModel.find_user_by_email(email)

    if data is None:
      return make_response(jsonify({'message': 'email or password incorrect'}), 404)
    
    password_bytes = password.encode('utf-8')
    password_hash = data.password.encode('utf-8')

    result = bcrypt.checkpw(password_bytes, password_hash) 

    if not result:
      return make_response(jsonify({'message': 'email or password incorrect'}), 401)
    
    return make_response(jsonify({'access_token': create_access_token(identity=data.id, additional_claims={'admin': data.admin})}), 200)
  except Exception as e:
    return make_response(jsonify({'message': 'error login user', 'error': str(e)}), 500)

@user_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
  try:
    jwt = get_jwt()
    id = jwt.get('jti')
    BLOCKLIST.add(id)
    return {'message': 'Logged out successfully'}, 200
  except Exception as e:
    return make_response(jsonify({'message': 'error logout user', 'error': str(e)}), 500)