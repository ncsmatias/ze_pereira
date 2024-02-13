from flask import Flask, jsonify, make_response
from dotenv import load_dotenv
from database import db
from flask_migrate import Migrate
from model import user_model
from resoucers.users import user_bp
import os

load_dotenv()

app = Flask(__name__)
app.register_blueprint(user_bp) 
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URL')

db.init_app(app)

migrate = Migrate(app, db)

@app.route('/app-status', methods=['GET'])
def test():
    return make_response(jsonify({'message': 'okay'}), 200)

if __name__ == '__main__':
    print('-----initialize app-----')
    app.run(debug=True)
