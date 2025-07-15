from flask import Flask, request, jsonify, render_template, send_from_directory, session
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
import random
import string
from functools import wraps
import bcrypt
import re
from security import (
    sanitize_input, validate_email, validate_username, validate_name,
    rate_limit, brute_force_protection, add_security_headers,
    sanitize_mongo_query, generate_csrf_token, validate_csrf_token
)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES')))

# Initialize extensions
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)

# MongoDB setup
client = MongoClient(os.getenv('MONGO_URI'))
db = client.auth_db
users = db.users

# Password validation regex
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')

# Add security headers to all responses
@app.after_request
def add_security_headers_after_request(response):
    return add_security_headers(response)

# Token required decorator with CSRF protection
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not validate_csrf_token():
            return jsonify({'message': 'Invalid CSRF token'}), 403
            
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = users.find_one({'_id': data['user_id']})
            if not current_user:
                return jsonify({'message': 'Invalid token!'}), 401
        except:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Helper functions
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    try:
        msg = Message('Your OTP for Email Verification',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def check_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def check_password_history(user, new_password):
    """Check if the new password was used in the last 3 passwords"""
    if 'password_history' not in user:
        return True
    
    for old_hash in user['password_history'][-3:]:  # Check last 3 passwords
        if bcrypt.check_password_hash(old_hash, new_password):
            return False
    return True

def update_password_history(user, new_password_hash):
    """Update the password history with the new password hash"""
    if 'password_history' not in user:
        user['password_history'] = []
    
    user['password_history'].append(new_password_hash)
    if len(user['password_history']) > 5:  # Keep only last 5 passwords
        user['password_history'] = user['password_history'][-5:]
    
    users.update_one(
        {'_id': user['_id']},
        {'$set': {'password_history': user['password_history']}}
    )

# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard_data')
@jwt_required()
def get_dashboard_data():
    current_user_id = get_jwt_identity()
    user = users.find_one({'_id': current_user_id})
    if user:
        username = user.get('username', 'User')
        return jsonify({'username': username}), 200
    return jsonify({'message': 'User not found'}), 404

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/verify-otp')
def verify_otp_page():
    return render_template('verify_otp.html')

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/register', methods=['POST'])
@rate_limit(limit=5, window=60)
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['firstName', 'lastName', 'email', 'username', 'password', 'confirmPassword', 'captcha']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Sanitize and validate input
    data['firstName'] = sanitize_input(data['firstName'])
    data['lastName'] = sanitize_input(data['lastName'])
    data['email'] = sanitize_input(data['email'])
    data['username'] = sanitize_input(data['username'])
    
    if not validate_name(data['firstName']) or not validate_name(data['lastName']):
        return jsonify({'error': 'Invalid name format'}), 400
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    if not validate_username(data['username']):
        return jsonify({'error': 'Invalid username format'}), 400
    
    # Validate password match
    if data['password'] != data['confirmPassword']:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    # Check password strength
    is_strong, message = check_password_strength(data['password'])
    if not is_strong:
        return jsonify({'error': message}), 400
    
    # Check if user already exists (with sanitized query)
    query = sanitize_mongo_query({
        '$or': [
            {'email': data['email']},
            {'username': data['username']}
        ]
    })
    if users.find_one(query):
        return jsonify({'error': 'User already exists'}), 400
    
    # Generate OTP
    otp = generate_otp()
    
    # Hash the password
    password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Create user document
    user = {
        'firstName': data['firstName'],
        'lastName': data['lastName'],
        'email': data['email'],
        'username': data['username'],
        'password': password_hash,
        'otp': otp,
        'is_verified': False,
        'created_at': datetime.utcnow(),
        'password_changed_at': datetime.utcnow(),
        'password_history': [password_hash]  # Initialize password history
    }
    
    # Insert user and send OTP
    try:
        users.insert_one(user)
        if not send_otp_email(data['email'], otp):
            # If email fails, delete the user and return error
            users.delete_one({'email': data['email']})
            return jsonify({'error': 'Failed to send verification email'}), 500
        
        return jsonify({'message': 'Registration successful. Please check your email for verification.'}), 201
    except Exception as e:
        print(f"Error during registration: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/verify-email', methods=['POST'])
@rate_limit(limit=5, window=60)
def verify_email():
    data = request.get_json()
    
    if not all(k in data for k in ['email', 'otp']):
        return jsonify({'error': 'Missing email or OTP'}), 400
    
    # Sanitize input
    data['email'] = sanitize_input(data['email'])
    data['otp'] = sanitize_input(data['otp'])
    
    # Sanitize query
    query = sanitize_mongo_query({
        'email': data['email'],
        'otp': data['otp']
    })
    
    user = users.find_one(query)
    
    if not user:
        return jsonify({'error': 'Invalid OTP'}), 400
    
    # Update user verification status
    try:
        users.update_one(
            {'_id': user['_id']},
            {
                '$set': {'is_verified': True},
                '$unset': {'otp': 1}
            }
        )
        return jsonify({'message': 'Email verified successfully'}), 200
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@app.route('/login', methods=['POST'])
@rate_limit(limit=5, window=60)
@brute_force_protection(max_attempts=5, window=600)
def login():
    data = request.get_json()
    
    if not all(k in data for k in ['username', 'password', 'captcha']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Sanitize input
    data['username'] = sanitize_input(data['username'])
    
    # Sanitize query
    query = sanitize_mongo_query({
        '$or': [
            {'username': data['username']},
            {'email': data['username']}
        ]
    })
    
    user = users.find_one(query)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.get('is_verified'):
        return jsonify({'error': 'Please verify your email first'}), 401
    
    if not bcrypt.check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid password'}), 401
    
    # Check password expiry
    password_age = datetime.utcnow() - user['password_changed_at']
    if password_age.days > int(os.getenv('PASSWORD_EXPIRY_DAYS', 90)):
        return jsonify({'error': 'Password expired. Please reset your password.'}), 401
    
    # Generate OTP for login verification
    otp = generate_otp()
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'otp': otp,
                'otpExpiry': datetime.utcnow() + timedelta(minutes=10),
                'lastOtpSent': datetime.utcnow()
            }
        }
    )
    send_otp_email(user['email'], otp)
    
    return jsonify({'message': 'OTP sent to your email. Please verify to complete login.', 'email': user['email']}), 200

@app.route('/login-verify', methods=['POST'])
@rate_limit(limit=5, window=60)
def login_verify():
    data = request.get_json()
    if not all(k in data for k in ['email', 'otp']):
        return jsonify({'error': 'Missing email or OTP'}), 400
    
    # Sanitize input
    email = sanitize_input(data['email'])
    otp = sanitize_input(data['otp'])
    
    # Sanitize query
    query = sanitize_mongo_query({'email': email})
    user = users.find_one(query)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Check OTP and expiry
    if not user.get('otp') or user.get('otp') != otp:
        return jsonify({'error': 'Invalid OTP'}), 400
    if 'otpExpiry' in user and datetime.utcnow() > user['otpExpiry']:
        return jsonify({'error': 'OTP expired'}), 400
    
    # OTP is valid, clear it and log in
    users.update_one(
        {'_id': user['_id']},
        {'$unset': {'otp': 1, 'otpExpiry': 1}}
    )
    # Generate JWT token
    token = create_access_token(identity=str(user['_id']))
    # Update last login
    users.update_one(
        {'_id': user['_id']},
        {'$set': {'last_login': datetime.utcnow()}}
    )
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'csrf_token': generate_csrf_token()
    }), 200

@app.route('/forgot-password', methods=['POST'])
@rate_limit(limit=10, window=3600)  # 10 attempts per hour
def forgot_password():
    data = request.get_json()
    
    if 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    # Sanitize input
    data['email'] = sanitize_input(data['email'])
    
    # Sanitize query
    query = sanitize_mongo_query({'email': data['email']})
    
    user = users.find_one(query)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    otp = generate_otp()
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'otp': otp,
                'otpExpiry': datetime.utcnow() + timedelta(minutes=10)
            }
        }
    )
    
    send_otp_email(data['email'], otp)
    
    return jsonify({'message': 'OTP sent to your email'}), 200

@app.route('/reset-password', methods=['POST'])
@rate_limit(limit=10, window=3600)  # 10 attempts per hour
def reset_password():
    data = request.get_json()
    email = sanitize_input(data.get('email'))
    otp = sanitize_input(data.get('otp'))
    new_password = data.get('newPassword')

    if not all([email, otp, new_password]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Sanitize query
    query = sanitize_mongo_query({'email': email})
    
    user = users.find_one(query)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.get('otp') or user.get('otp') != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    # Check if the new password is in the password history
    if not check_password_history(user, new_password):
        return jsonify({'error': 'Cannot reuse any of your last 3 passwords'}), 400

    # Hash the new password
    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    # Update password and clear OTP
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'password': password_hash,
                'password_changed_at': datetime.utcnow()
            },
            '$unset': {'otp': 1}
        }
    )

    # Update password history
    update_password_history(user, password_hash)

    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/resend-otp', methods=['GET'])
@rate_limit(limit=3, window=3600)  # 3 attempts per hour
def resend_otp():
    email = sanitize_input(request.args.get('email'))
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Sanitize query
    query = sanitize_mongo_query({'email': email})
    
    user = users.find_one(query)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Check cooldown
    if 'lastOtpSent' in user and (datetime.utcnow() - user['lastOtpSent']).total_seconds() < 60:
        return jsonify({'error': 'Please wait 60 seconds before requesting a new OTP'}), 429
    
    otp = generate_otp()
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'otp': otp,
                'otpExpiry': datetime.utcnow() + timedelta(minutes=10),
                'lastOtpSent': datetime.utcnow()
            }
        }
    )
    
    send_otp_email(email, otp)
    
    return jsonify({'message': 'OTP resent successfully'}), 200

@app.route('/test')
def test_route():
    return "Test route is working!", 200

if __name__ == '__main__':
    app.run(debug=False)  # Set debug=False in production 