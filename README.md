# Secure User Authentication System

A secure user authentication system built with Flask and MongoDB, featuring robust security controls such as email verification, password strength enforcement, CAPTCHA, JWT authentication, CSRF protection, and more.

## Features

- User registration with email verification (OTP)
- Secure password hashing with bcrypt
- Password strength enforcement (min 8 chars, upper/lower/number/special)
- Password history and 90-day expiry
- JWT-based stateless authentication
- CSRF protection (custom tokens and JWT double-submit)
- CAPTCHA on registration and login
- Rate limiting and brute force protection
- Input sanitization (XSS/NoSQL injection prevention)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Password reset via OTP (email-based)
- MongoDB integration
- Gmail SMTP for email delivery

## Prerequisites

- Python 3.8+
- MongoDB
- Gmail account (for SMTP)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
MONGO_URI=mongodb://localhost:27017/auth_db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_EXPIRES=3600
PASSWORD_EXPIRY_DAYS=90
MAX_PASSWORD_HISTORY=5
```

Note: For Gmail, you'll need to:
1. Enable 2-factor authentication
2. Generate an App Password
3. Use the App Password in MAIL_PASSWORD

## Running the Application

1. Start MongoDB:
```bash
mongod
```

2. Run the Flask application:
```bash
flask run
```

The application will be available at `http://localhost:5000`

## API Endpoints

- `POST /register` - Register a new user (sends OTP to email)
- `POST /verify-email` - Verify email with OTP
- `POST /login` - Login user (sends OTP to email for 2FA)
- `POST /login-verify` - Verify login OTP and issue JWT
- `POST /forgot-password` - Request password reset (sends OTP)
- `POST /reset-password` - Reset password with OTP
- `GET /resend-otp` - Resend OTP (rate-limited)

## Security Features (with File Locations)

1. **Password Hashing**  
   - Bcrypt used for secure password storage  
   - *File: `app.py`*  
   - Example:  
     ```python
     password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
     ```

2. **Password Strength, History, and Expiry**  
   - Enforced via regex and logic (min 8 chars, complexity, no reuse of last 3–5, 90-day expiry)  
   - *File: `app.py`*  
   - Example:  
     ```python
     if not check_password_history(user, new_password):
         return jsonify({'error': 'Cannot reuse any of your last 3 passwords'}), 400
     ```

3. **Email Verification with OTP**  
   - 6-digit OTP sent to email, expires in 10 minutes, 60s resend cooldown  
   - *File: `app.py`, `templates/verify_otp.html`*  
   - Example:  
     ```python
     otp = generate_otp()
     send_otp_email(data['email'], otp)
     ```

4. **JWT Authentication**  
   - Stateless authentication, token expiry, CSRF double-submit  
   - *File: `app.py`*  
   - Example:  
     ```python
     token = create_access_token(identity=str(user['_id']))
     ```

5. **CSRF Protection**  
   - Custom CSRF tokens and JWT double-submit  
   - *File: `security.py`, `app.py`*  
   - Example:  
     ```python
     def generate_csrf_token(): ...
     def validate_csrf_token(): ...
     ```

6. **CAPTCHA**  
   - Arithmetic CAPTCHA on registration and login forms  
   - *File: `templates/register.html`, `templates/login.html`*  
   - Example:  
     ```javascript
     function generateCaptcha() { ... }
     ```

7. **Rate Limiting & Brute Force Protection**  
   - Per-IP rate limits and failed login attempt tracking  
   - *File: `security.py`, used in `app.py`*  
   - Example:  
     ```python
     @rate_limit(limit=5, window=60)
     @brute_force_protection(max_attempts=5, window=600)
     ```

8. **Input Sanitization**  
   - Prevents XSS and NoSQL injection using `html.escape` and `bleach`  
   - *File: `security.py`*  
   - Example:  
     ```python
     def sanitize_input(text): ...
     ```

9. **Security Headers**  
   - Adds CSP, HSTS, X-Frame-Options, etc. to all responses  
   - *File: `security.py`, used in `app.py`*  
   - Example:  
     ```python
     def add_security_headers(response): ...
     ```

10. **Password Reset via OTP**  
    - Secure password reset with email OTP verification  
    - *File: `app.py`*  
    - Example:  
      ```python
      send_otp_email(data['email'], otp)
      ```

## Frontend Pages

- `/register.html` - User registration (with CAPTCHA, sends OTP)
- `/login.html` - User login (with CAPTCHA, sends OTP)
- `/verify_otp.html` - Email verification (OTP input)
- `/forgot_password.html` - Password reset (OTP input)
- `/dashboard.html` - User dashboard (JWT-protected)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. # Secure-Authentication-System
