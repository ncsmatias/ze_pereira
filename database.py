from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_app(app):
    print('-----initialize sqlalchemy-----')
    db.create_all()
    db.init_app(app)
