from flask import request, make_response, jsonify, Blueprint
import bcrypt 
from model.user_model import UserModel

user_bp = Blueprint('user', __name__)

@user_bp.route('/user', methods=['POST'])
def create_user():
  try:
    data = request.get_json()
    password = data.pop('password')
    password_bytes = password.encode('utf-8')
    hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt()) 
    new_user = UserModel(**data, password=hash)
    new_user.save_user()
    return make_response(jsonify({'message': 'user created'}), 201)
  except Exception as e:
    return make_response(jsonify({'message': 'error creating user', 'error': str(e)}), 500)

@user_bp.route('/user', methods=['GET'])
def get_users():
  try:
    data = [user.json() for user in UserModel.query.all()]
    return make_response(jsonify(data), 200)
  except Exception as e:
    return make_response(jsonify({'message': 'error getting user', 'error': str(e)}), 500)

@user_bp.route('/user/<string:id>', methods=['GET'])
def get_user_by_id(id):
  try:
    data = UserModel.find_user_by_id(id)

    if data is None:
        return make_response(jsonify({'message': 'user not find'}), 404)
    
    return make_response(jsonify(data.json()), 200)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error getting user', 'error': str(e)}), 500)

@user_bp.route('/user/<string:id>', methods=['PUT'])
def update_user(id):
  try:
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response(jsonify({'message': 'user not find'}), 404)
    
    body = request.get_json()
    data.update_user(**body)
    data.save_user()

    return make_response(jsonify(data.json()), 200)

  except Exception as e:
    return make_response(jsonify({'message': 'error updating user', 'error': str(e)}), 500)

@user_bp.route('/user/<string:id>', methods=['DELETE'])
def delete_user(id):
  try:
    data = UserModel.find_user_by_id(id)

    if data is None:
      return make_response(jsonify({'message': 'user not find'}), 404)

    data.delete_user()
    return make_response(jsonify({'message': 'user deleted'}), 200)
  
  except Exception as e:
    return make_response(jsonify({'message': 'error deleting user', 'error': str(e)}), 500)