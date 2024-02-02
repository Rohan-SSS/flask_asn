from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, session, send_file, jsonify
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import os
import secrets
from models import db, User

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
db.init_app(app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

serializer = URLSafeTimedSerializer(os.environ.get('SERIALIZER_KEY'))

ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}

with app.app_context():
    db.create_all()


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


def generate_verification_token():
    return secrets.token_urlsafe(30)

def send_verification_email(user):
    verification_link = f"{request.url_root}verify_email?token={user.verification_token}"

    msg = Message('Email Verification', sender='heheguilty@gmail.com', recipients=[user.email])
    msg.body = f'Please click the following link to verify your email: {verification_link}'

    mail.send(msg)

def get_files_for_client():
    uploads_directory = os.path.join(app.root_path, 'uploads')
    files = [file for file in os.listdir(uploads_directory) if os.path.isfile(os.path.join(uploads_directory, file))]
    return files

def upload_file(file):
    uploads_directory = os.path.join(app.root_path, 'uploads')
    if not os.path.exists(uploads_directory):
        os.makedirs(uploads_directory)

    file.save(os.path.join(uploads_directory, secure_filename(file.filename)))

def generate_download_link(filename, user_email):
    token = serializer.dumps({"filename": filename, "user_email": user_email})
    download_link = f"{request.url_root}download_secure_file/{token}"
    return download_link

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == "__main__":
    app.run(debug=True)