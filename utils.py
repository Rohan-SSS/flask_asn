from flask import request
from flask_mail import Message
from werkzeug.utils import secure_filename
import secrets
import os


def generate_verification_token():
    return secrets.token_urlsafe(30)

def send_verification_email(user, mail):
    verification_link = f"{request.url_root}verify_email?token={user.verification_token}"

    msg = Message('Email Verification', sender='heheguilty@gmail.com', recipients=[user.email])
    msg.body = f'Please click the following link to verify your email: {verification_link}'

    mail.send(msg)

def get_files_for_client(app):
    uploads_directory = os.path.join(app.root_path, 'uploads')
    files = [file for file in os.listdir(uploads_directory) if os.path.isfile(os.path.join(uploads_directory, file))]
    return files

def upload_file(file, app):
    uploads_directory = os.path.join(app.root_path, 'uploads')
    if not os.path.exists(uploads_directory):
        os.makedirs(uploads_directory)

    file.save(os.path.join(uploads_directory, secure_filename(file.filename)))

def generate_download_link(filename, user_email, serializer):
    token = serializer.dumps({"filename": filename, "user_email": user_email})
    download_link = f"{request.url_root}download_secure_file/{token}"
    return download_link

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



