from flask_login import UserMixin
from .extensions import db
from datetime import datetime
import uuid
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(250))
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    questions = db.relationship('Question', backref='form', lazy='dynamic')
    responses = db.relationship('Response', backref='form', lazy='dynamic')
    public_token = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid.uuid4))

    def generate_unique_token(self):
        while True:
            self.public_token = str(uuid.uuid4())
            try:
                db.session.add(self)
                db.session.commit()
                break 
            except IntegrityError:
                db.session.rollback() 
    
    def __repr__(self):
        return f"<Form {self.name}>"

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'), nullable=False)
    question_text = db.Column(db.String(255), nullable=False)
    question_type = db.Column(db.String(50), nullable=False)
    options = db.Column(db.Text)

    def __repr__(self):
        return f"<Question {self.question_text}>"

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'))
    responses = db.Column(db.Text) 
    submitted_on = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Response {self.id}>"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(16), nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    email_notifications = db.Column(db.Boolean, default=True)

    def set_reset_token(self, token):
        self.password_reset_token = generate_password_hash(token)

    def verify_reset_token(self, token):
        return check_password_hash(self.password_reset_token, token)
