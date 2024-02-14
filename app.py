import os
from flask import Flask, jsonify, make_response
from dotenv import load_dotenv
from database import db
from flask_migrate import Migrate
from model import user_model
from resoucers.users import user_bp
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from blocklist import BLOCKLIST

load_dotenv()

app = Flask(__name__)
app.register_blueprint(user_bp) 
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URL')
app.config["JWT_SECRET_KEY"] = os.environ.get('MD5_HASH')
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def verify_blocklist(self,token):
  return token['jti'] in BLOCKLIST

@jwt.revoked_token_loader
def token_de_acesso_invalidao(jwt_header, jwt_payload):
  return jsonify({'message': 'You have been logged out'}), 401

db.init_app(app)

migrate = Migrate(app, db)

@app.route('/app-status', methods=['GET'])
def test():
    return make_response(jsonify({'message': 'okay'}), 200)

if __name__ == '__main__':
    print('-----initialize app-----')
    app.run(debug=True)
