import os
import random

from emailchik import send_confirmation_email
from flask import Flask, jsonify, request, send_file
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from ecc import *
from aes import *

app = Flask(__name__)

# Настройки JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Измените на свой секретный ключ в реальном проекте
jwt = JWTManager(app)

# Настройки базы данных (используется SQLite в данном примере)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)


def generate_confirmation_code():
    return str(random.randint(100000, 999999))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmed_code = db.Column(db.String(6))
    public_key = db.Column(db.Text)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    code = generate_confirmation_code()
    new_user = User(username=username, password=password, email=email, email_confirmed_code=code)
    db.session.add(new_user)
    db.session.commit()

    send_confirmation_email(email, username, code)

    return jsonify({'message': 'Registration successful'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    if not user.email_confirmed:
        return jsonify({'error': 'Email not confirmed'}), 401

    if password != user.password:
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_resource():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/confirm_email', methods=['POST'])
def confirm_email():
    code = request.get_json().get('code')
    user = User.query.filter_by(email_confirmed_code=code).first()

    if user:
        user.email_confirmed = True
        db.session.commit()
        return jsonify({'message': 'Email confirmed successfully'}), 200
    else:
        return jsonify({'error': 'Invalid or expired code'}), 400


@app.route('/generate_key', methods=['POST'])
@jwt_required()
def generate_key():
    current_user = get_jwt_identity()
    data = request.get_json()
    public_key = data.get('public_key')
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_data(public_key, aes_key)


    user = User.query.filter_by(username=current_user).first()
    user.public_key = aes_key
    db.session.commit()

    return jsonify({'public_key': public_key_hex}), 200


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400


@app.route('/download/<filename>', methods=['GET'])
@jwt_required()
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
