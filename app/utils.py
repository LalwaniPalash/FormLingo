import qrcode
from io import BytesIO
from flask import send_file, current_app, url_for
from flask_mail import Message
import os
import secrets
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db, mail

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffer = BytesIO()
    img.save(buffer, 'PNG')
    buffer.seek(0)
    return buffer

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def generate_reset_token(user):
    """Generate a reset token and store it securely."""
    token = secrets.token_urlsafe(16)
    hashed_token = generate_password_hash(token)
    user.password_reset_token = hashed_token
    print(f"Raw Token: {token}, Hashed Token: {hashed_token}")
    db.session.commit()
    return token

def verify_reset_token(token, user):
    """Verify the reset token against the stored hashed version."""
    if not user.password_reset_token:
        return False
    return check_password_hash(user.password_reset_token, token)

def send_notification_email(user, subject, body):
    if user.email_notifications:  # Check if notifications are enabled
        msg = Message(
            subject=subject,
            recipients=[user.email],
            body=body,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        try:
            mail.send(msg)
            current_app.logger.info(f"Notification sent to {user.email}")
        except Exception as e:
            current_app.logger.error(f"Failed to send notification: {e}")

def send_password_reset_email(user):
    """Send password reset email to the user."""
    token = generate_reset_token(user)  # Generate and store the token
    reset_url = url_for('main.reset_password', token=token, _external=True)

    subject = "Password Reset Request"
    sender = "grag.tung@gmail.com"
    recipients = [user.email]
    body = f"""
    Hi {user.username},

    You requested a password reset. Click the link below to reset your password:
    {reset_url}

    If you did not request a password reset, please ignore this email.
    """

    msg = Message(subject=subject, sender=sender, recipients=recipients, body=body)

    try:
        mail.send(msg)
        current_app.logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {e}")