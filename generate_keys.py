import secrets
import base64

# Generate Flask Secret Key
flask_secret = secrets.token_hex(32)
print("\nFlask Secret Key (SECRET_KEY):")
print(flask_secret)

# Generate JWT Secret Key
jwt_secret = secrets.token_hex(32)
print("\nJWT Secret Key (JWT_SECRET_KEY):")
print(jwt_secret)

# Generate a random string for MongoDB URI (if needed)
mongo_uri = f"mongodb://localhost:27017/auth_db"
print("\nMongoDB URI (MONGO_URI):")
print(mongo_uri)

print("\nCopy these values to your .env file:")
print(f"""
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY={flask_secret}
MONGO_URI={mongo_uri}
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
JWT_SECRET_KEY={jwt_secret}
JWT_ACCESS_TOKEN_EXPIRES=3600
PASSWORD_EXPIRY_DAYS=90
MAX_PASSWORD_HISTORY=5
""") 