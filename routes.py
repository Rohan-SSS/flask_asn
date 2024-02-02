from app import app, db, serializer
from flask import render_template, redirect, request, session, send_file, jsonify
import os
from models import User
from utils import (
generate_verification_token,
send_verification_email,
get_files_for_client,
upload_file,
generate_download_link,
allowed_file
)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('auth/signup.html', error='Email is already registered. Please login with it.')

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        verification_token = generate_verification_token()
        new_user.verification_token = verification_token
        db.session.commit()

        send_verification_email(new_user)

        return redirect('/login')

    return render_template('auth/signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password) and user.verification_token is None:
            session['email'] = user.email
            if user.role == 'client':
                return redirect('/client_dashboard')
            elif user.role == 'operations':
                return redirect('/operations_dashboard')
        else:
            return render_template('auth/login.html', error='Invalid user or email not verified')

    return render_template('auth/login.html')


@app.route('/client_dashboard')
def client_dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        if user and user.role == 'client':
            files = get_files_for_client()
            return render_template('dashboard/client_dashboard.html', user=user, files=files)

    return redirect('/login')

@app.route('/operations_dashboard')
def operations_dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        if user and user.role == 'operations':
            return render_template('dashboard/operations_dashboard.html', user=user)

    return redirect('/login')


@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/')


@app.route('/verify_email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    user = User.query.filter_by(verification_token=token).first()

    if user:
        user.verification_token = None
        db.session.commit()
        return redirect('/login')
    else:
        return "Verification failed"

@app.route('/upload_file', methods=['POST'])
def upload_file_route():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        if user and user.role == 'operations':
            if 'file' in request.files:
                file = request.files['file']
                if file.filename != '' and allowed_file(file.filename):
                    upload_file(file)
            return redirect('/operations_dashboard')
    return redirect('/login')


@app.route('/download_file/<filename>')
def download_file_route(filename):
    if session.get('email'):
        user = User.query.filter_by(email=session['email']).first()
        if user and user.role == 'client':
            uploads_directory = os.path.join(app.root_path, 'uploads')
            file_path = os.path.abspath(os.path.join(uploads_directory, filename))

            if os.path.commonprefix([file_path, uploads_directory]) == uploads_directory and os.path.exists(file_path):
                download_link = generate_download_link(filename, user.email)
                return jsonify({"download-link": download_link, "message": "success"})
                # return render_template('download.html', download_link=download_link)

    return jsonify({"error": "Access denied"}), 403

@app.route('/download_secure_file/<token>')
def download_secure_file(token):
    try:
        data = serializer.loads(token, max_age=900)
        user_email = data.get("user_email")
        filename = data.get("filename")

        if user_email and filename:
            user = User.query.filter_by(email=user_email).first()

            if user and user.role == 'client':
                uploads_directory = os.path.join(app.root_path, 'uploads')
                file_path = os.path.abspath(os.path.join(uploads_directory, filename))

                if os.path.commonprefix([file_path, uploads_directory]) == uploads_directory and os.path.exists(file_path):
                    return send_file(file_path, as_attachment=True)

    except Exception as e:
        print(e)

    return jsonify({"error": "Access denied"}), 403
