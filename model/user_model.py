import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from database import db

class UserModel(db.Model):
  __tablename__ = 'users'

  id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
  username = db.Column(db.String)
  name = db.Column(db.String)
  email = db.Column(db.String, unique=True)
  password = db.Column(db.String(255))
  entry_year = db.Column(db.DateTime, nullable=True)
  exit_year = db.Column(db.DateTime, default=None)
  admin = db.Column(db.Boolean, default=False)

  def __init__(self, username, name, email, password, entry_year, admin):
    self.username = username
    self.name = name
    self.email = email
    self.password = password
    self.entry_year = datetime.strptime(str(entry_year), '%Y')
    self.admin = admin
  
  def json(self):
    return {
      'id': self.id,
      'username': self.username,
      'name': self.name,
      'email': self.email,
      'entry_year': self.entry_year,
      'exit_year': self.exit_year,
      'admin': self.admin
    }
  
  @classmethod
  def find_user_by_id(cls, id):
    user = cls.query.filter_by(id=id).first()
    return user if user else None
  
  @classmethod
  def find_user_by_username(cls, username):
    user = cls.query.filter_by(username=username).first()
    return user if user else None

  @classmethod
  def find_user_by_email(cls, email):
    user = cls.query.filter_by(email=email).first()
    return user if user else None
  
  def save_user(self):
    db.session.add(self)
    db.session.commit()
  
  def update_user(self, username, name, email, entry_year, exit_year, admin):
    self.username = username
    self.name = name
    self.email = email
    self.entry_year = entry_year
    self.exit_year = exit_year
    self.admin = admin
  
  def delete_user(self):
    db.session.delete(self)
    db.session.commit()