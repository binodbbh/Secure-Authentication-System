import re
import time
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime, timedelta
import html
import bleach
from collections import defaultdict

# In-memory storage for rate limiting and brute force protection
ip_requests = defaultdict(list)
failed_attempts = defaultdict(list)
blocked_ips = set()

# Input sanitization patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
NAME_PATTERN = re.compile(r'^[a-zA-Z\s]{2,50}$')

def sanitize_input(text):
    """Sanitize user input to prevent XSS and injection attacks"""
    if not text:
        return text
    # First escape HTML
    text = html.escape(text)
    # Then use bleach to clean any remaining HTML
    text = bleach.clean(text, strip=True)
    return text

def validate_email(email):
    """Validate email format"""
    return bool(EMAIL_PATTERN.match(email))

def validate_username(username):
    """Validate username format"""
    return bool(USERNAME_PATTERN.match(username))

def validate_name(name):
    """Validate name format"""
    return bool(NAME_PATTERN.match(name))

def rate_limit(limit=5, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            
            # Check if IP is blocked
            if ip in blocked_ips:
                return jsonify({'error': 'Too many requests. Please try again later.'}), 429
            
            # Clean old requests
            current_time = time.time()
            ip_requests[ip] = [t for t in ip_requests[ip] if current_time - t < window]
            
            # Check rate limit
            if len(ip_requests[ip]) >= limit:
                blocked_ips.add(ip)
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            ip_requests[ip].append(current_time)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def brute_force_protection(max_attempts=5, window=600):
    """Brute force protection decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            current_time = time.time()
            
            # Clean old attempts
            failed_attempts[ip] = [t for t in failed_attempts[ip] if current_time - t < window]
            
            # Check if too many failed attempts
            if len(failed_attempts[ip]) >= max_attempts:
                return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 429
            
            # Add current attempt
            failed_attempts[ip].append(current_time)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def add_security_headers(response):
    """Add security headers to response"""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def sanitize_mongo_query(query):
    """Sanitize MongoDB query to prevent NoSQL injection"""
    if isinstance(query, dict):
        return {k: sanitize_mongo_query(v) for k, v in query.items()}
    elif isinstance(query, list):
        return [sanitize_mongo_query(item) for item in query]
    elif isinstance(query, str):
        return str(query)  # Convert to string to prevent operator injection
    return query

def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = ''.join([chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)] + [str(i) for i in range(10)])
    return session['csrf_token']

def validate_csrf_token():
    """Validate CSRF token"""
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return False
    return True 