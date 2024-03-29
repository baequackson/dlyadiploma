import hashlib
import os
import random

from flask import render_template

from emailchik import send_confirmation_email
from flask import Flask, jsonify, request, send_file
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from rsa import *
from aes import *

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your_secret_key'
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)


def generate_confirmation_code():
    return str(random.randint(100000, 999999))


class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmed_code = db.Column(db.String(6))
    public_key = db.Column(db.Text)


class Files(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(255))
    code = db.Column(db.String(6))


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    plain_password = data.get('password')  # Отримати незахешований пароль

    # Хешування пароля
    hashed_password = hashlib.sha256(plain_password.encode()).hexdigest()

    email = data.get('email')

    if Users.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    if Users.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    code = generate_confirmation_code()
    new_user = Users(username=username, password=hashed_password, email=email, email_confirmed_code=code)
    db.session.add(new_user)
    db.session.commit()

    send_confirmation_email(email, username, code)

    return jsonify({'message': 'Registration successful'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = Users.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    if not user.email_confirmed:
        return jsonify({'error': 'Email not confirmed'}), 401
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if hashed_password != user.password:
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route('/confirm_email', methods=['GET'])
def confirm_email():
    code = request.args.get('code')
    user = Users.query.filter_by(email_confirmed_code=code).first()

    if user and not user.email_confirmed:
        user.email_confirmed = True
        db.session.commit()
        return 'Successful confirmed', 200
    else:
        return 'Error code', 404


@app.route('/generate_key', methods=['POST'])
@jwt_required()
def generate_key():
    current_user = get_jwt_identity()
    data = request.get_json()
    public_key = data.get('public_key')
    aes_key = aes_generate_key()
    encrypted_aes_key = rsa_encrypt_text(public_key, aes_key)
    user = Users.query.filter_by(username=current_user).first()
    user.public_key = aes_key
    db.session.commit()

    return jsonify({'encrypted_aes_key': encrypted_aes_key}), 200


@app.route('/files/<username>', methods=['GET'])
@jwt_required()
def get_user_files(username):
    current_user = get_jwt_identity()
    if current_user != username:
        return jsonify({'error': 'Unauthorized access to user files'}), 403

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    user_files = [file.split('_', 1)[1] for file in files if file.startswith(f"{user.id}_")]

    return jsonify({'files': user_files}), 200


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file_otp():
    current_user = get_jwt_identity()
    user = Users.query.filter_by(username=current_user).first()
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], f'{user.id}_{filename}'))

        new_file = Files(user_id=user.id, filename=filename.split("-")[-1], code=generate_confirmation_code())
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400


@app.route('/download/<filename>', methods=['POST'])
@jwt_required()
def download_file_otp(filename):
    current_user = get_jwt_identity()
    user = Users.query.filter_by(username=current_user).first()
    user_id = user.id

    data = request.get_json()

    public_key = data.get('public_key')
    code = data.get('code')
    aes_key = user.public_key
    db.session.commit()
    encrypted_aes_key = rsa_encrypt_text(public_key, aes_key)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_{filename}')

    file = Files.query.filter_by(filename=filename, user_id=user_id).first()
    if os.path.exists(file_path) and file is not None and code == file.code:
        response = send_file(file_path, as_attachment=True)
        response.headers['encrypted_aes_key'] = encrypted_aes_key
        return response
    else:
        db.session.commit()
        return jsonify({'error': 'File not found'}), 404


@app.route('/api/login', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = Users.query.filter_by(username=username).first()
    if user and user.password == password:

        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:

        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/otp_codes', methods=['GET'])
@jwt_required()
def otp_codes():
    current_user = get_jwt_identity()
    user = Users.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    files = Files.query.filter_by(user_id=user.id).all()

    return render_template('otp_codes.html', user=user, files=files)


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    user = Users.query.filter_by(username=current_user).first()
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], f'{user.id}_{filename}'))
        new_file = Files(user_id=user.id, filename=filename.split("-")[-1], code=generate_confirmation_code())
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400


@app.route('/download/<filename>', methods=['POST'])
@jwt_required()
def download_file(filename):
    current_user = get_jwt_identity()
    user = Users.query.filter_by(username=current_user).first()
    user_id = user.id

    data = request.get_json()
    public_key = data.get('public_key')
    code = data.get('code')
    aes_key = user.public_key
    db.session.commit()
    encrypted_aes_key = rsa_encrypt_text(public_key, aes_key)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_{filename}')
    file = Files.query.filter_by(filename=filename, user_id=user_id).first()
    if os.path.exists(file_path) and file is not None and code == file.code:
        response = send_file(file_path, as_attachment=True)
        response.headers['encrypted_aes_key'] = encrypted_aes_key
        return response
    else:
        db.session.commit()
        return jsonify({'error': 'File not found'}), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
