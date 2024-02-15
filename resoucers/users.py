import bcrypt
from flask import request, jsonify, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity
from model.user_model import UserModel
from blocklist import BLOCKLIST
from utils import hash, make_response

user_bp = Blueprint('user', __name__)

@user_bp.route('/user', methods=['POST'])
@jwt_required()
def create_user():
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response.create_response({'message': 'Only administrators can create a new user.'}, 401)
    
    data = request.get_json()
    password = data.pop('password')
    hash_password = hash.hash_password(password=password)
    new_user = UserModel(**data, password=hash_password)
    new_user.save_user()

    return make_response.create_response({'message': 'User created successfully.'}, 201)
  
  except Exception as e:
    return make_response.create_response({'message': 'Failed to create user. Please check your input and try again later.', 'error': str(e)}, 500)

@user_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response.create_response({'message': 'Only administrators are authorized to list all users.'}, 401)
    
    data = [user.json() for user in UserModel.query.all()]
    return make_response.create_response(data, 200)
  
  except Exception as e:
    return make_response.create_response({'message': 'Internal server error occurred while retrieving user information.', 'error': str(e)}, 500)

@user_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user_by_id():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
        return make_response.create_response({'message': 'User not found.'}, 404)
    
    return make_response.create_response(data.json(), 200)
  
  except Exception as e:
    return make_response.create_response({'message': 'Internal server error occurred while retrieving user information.', 'error': str(e)}, 500)

@user_bp.route('/user', methods=['PUT'])
@jwt_required()
def update_user():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response.create_response({'message': 'User not found.'}, 404)
    
    body = request.get_json()
    data.update_user(**body)
    data.save_user()

    return make_response.create_response(data.json(), 200)

  except Exception as e:
    return make_response.create_response({'message': 'Failed to update user information due to an internal server error.', 'error': str(e)}, 500)

@user_bp.route('/user', methods=['DELETE'])
@jwt_required()
def delete_user():
  try:
    id = get_jwt_identity()
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response.create_response({'message': 'User not found.'}, 404)

    data.delete_user()
    return make_response.create_response({'message': 'User deleted successfully.'}, 200)
  
  except Exception as e:
    return make_response.create_response({'message': 'Failed to delete user due to an internal server error.', 'error': str(e)}, 500)

@user_bp.route('/user/admin/<string:id>', methods=['PUT'])
@jwt_required()
def turn_user_admin(id):
  try:
    jwt = get_jwt()
    admin = jwt.get('admin')
    if not admin:
      return make_response.create_response({'message': 'Only administrators have permission to create an admin user.'}, 401)
    
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response.create_response({'message': 'User not found.'}, 404)
    
    data.turn_admin_user()
    data.save_user()

    return make_response(data.json(), 200)
  except Exception as e:
    return make_response.create_response({'message': 'Failed to grant admin privileges to the user due to an internal server error.', 'error': str(e)}, 500)
  
@user_bp.route('/login', methods=['POST'])
def login():
  try:
    body = request.get_json()
    email = body['email']
    password = body['password']

    data = UserModel.find_user_by_email(email)

    if data is None:
      return make_response.create_response({'message': 'Invalid email or password. Please double-check your credentials.'}, 404)
    
    password_bytes = password.encode('utf-8')
    password_hash = data.password.encode('utf-8')

    result = bcrypt.checkpw(password_bytes, password_hash) 

    if not result:
      return make_response.create_response({'message': 'Invalid email or password. Please double-check your credentials.'}, 404)
    
    return make_response.create_response({'access_token': create_access_token(identity=data.id, additional_claims={'admin': data.admin})}, 200)
  except Exception as e:
    return make_response.create_response({'message': 'Failed to login due to an internal server error. Please try again later.', 'error': str(e)}, 500)

@user_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
  try:
    jwt = get_jwt()
    id = jwt.get('jti')
    BLOCKLIST.add(id)
    
    return make_response.create_response({'message': 'Logout successful. You have been successfully logged out.'}, 200)
  except Exception as e:
    return make_response.create_response({'message': 'Failed to logout user due to an internal server error.', 'error': str(e)}, 500)