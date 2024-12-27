from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    remember = SubmitField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    confirm_password = StringField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ResetPasswordForm(FlaskForm):
    password = StringField('Password', validators=[DataRequired()])
    confirm_password = StringField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class ChangePasswordForm(FlaskForm):
    old_password = StringField('Old Password', validators=[DataRequired()])
    new_password = StringField('New Password', validators=[DataRequired()])
    confirm_password = StringField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

class DeleteAccountForm(FlaskForm):
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Delete Account')

class LogoutForm(FlaskForm):
    submit = SubmitField('Logout')
