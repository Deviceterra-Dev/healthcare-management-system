from flask_jwt_extended import create_access_token
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app
from flask_mail import Message
import logging
from app import mail

def generate_token(username):
    """
    Generate a JWT token for the given username.
    """
    try:
        token = create_access_token(identity=username)
        logging.info(f"Generated JWT token for user: {username}")
        return token
    except Exception as e:
        logging.error(f"Error generating JWT token for user {username}: {e}")
        return None

def generate_confirmation_token(email):
    """
    Generate a confirmation token for email verification.
    """
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = serializer.dumps(email, salt=current_app.config['JWT_SECRET_KEY'])
        logging.info(f"Generated confirmation token for email: {email}")
        return token
    except Exception as e:
        logging.error(f"Error generating confirmation token for email {email}: {e}")
        return None

def confirm_token(token, expiration=3600):
    """
    Confirm the token and extract the email.
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['JWT_SECRET_KEY'], max_age=expiration)
        logging.info(f"Token confirmed for email: {email}")
        return email
    except SignatureExpired:
        logging.warning(f"Token expired for token: {token}")
        return False
    except BadSignature:
        logging.warning(f"Bad signature for token: {token}")
        return False
    except Exception as e:
        logging.error(f"Error confirming token {token}: {e}")
        return False

def send_email(subject, recipients, text_body, html_body):
    """
    Send an email using Flask-Mail.
    """
    try:
        msg = Message(subject, recipients=recipients)
        msg.body = text_body
        msg.html = html_body
        mail.send(msg)
        logging.info(f"Email sent to {recipients}")
    except Exception as e:
        logging.error(f"Error sending email to {recipients}: {e}")

def send_confirmation_email(user_email, confirmation_token):
    """
    Send a confirmation email to the user.
    """
    subject = "Email Confirmation"
    recipients = [user_email]
    confirm_url = f"{current_app.config['FRONTEND_URL']}/confirm/{confirmation_token}"
    text_body = f"Please click the link to confirm your email: {confirm_url}"
    html_body = f"<p>Please click the link to confirm your email: <a href='{confirm_url}'>{confirm_url}</a></p>"
    send_email(subject, recipients, text_body, html_body)

def send_password_reset_email(user_email, reset_token):
    """
    Send a password reset email to the user.
    """
    subject = "Password Reset Request"
    recipients = [user_email]
    reset_url = f"{current_app.config['FRONTEND_URL']}/reset/{reset_token}"
    text_body = f"Please click the link to reset your password: {reset_url}"
    html_body = f"<p>Please click the link to reset your password: <a href='{reset_url}'>{reset_url}</a></p>"
    send_email(subject, recipients, text_body, html_body)
