import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-change-this-in-production')
app.config['JWT_EXPIRES_DELTA'] = timedelta(hours=int(os.environ.get('JWT_EXPIRES_HOURS', 24)))
app.config['JWT_ALGORITHM'] = 'HS256'

# Initialize extensions
jwt = JWTManager(app)
CORS(app, origins=os.environ.get('CORS_ORIGIN', '*').split(','))

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get('REDIS_URL', 'memory://')
)

# In-memory user storage (replace with database in production)
users = {}

# Helper functions
def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed_password):
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def validate_email(email):
    """Basic email validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength."""
    return len(password) >= 6

def validate_name(name):
    """Validate name."""
    return len(name.strip()) >= 1

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'message': 'Bad request'
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'success': False,
        'message': 'Unauthorized'
    }), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'message': 'Endpoint not found',
        'available_endpoints': [
            'GET /',
            'GET /health',
            'POST /register',
            'POST /login',
            'POST /verify'
        ]
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'success': False,
        'message': 'Rate limit exceeded. Please try again later.'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'success': False,
        'message': 'Token has expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'success': False,
        'message': 'Invalid token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'success': False,
        'message': 'Token is required'
    }), 401

# Documentation endpoint
@app.route('/', methods=['GET'])
def documentation():
    """API documentation endpoint."""
    host = request.host_url.rstrip('/')
    
    documentation = {
        'service': 'OpenJWT - Open Source JWT Auth-as-a-Service',
        'version': '1.0.0',
        'description': 'A minimal JWT authentication service for frontend developers',
        'implementation': 'Python Flask',
        'endpoints': {
            'register': {
                'method': 'POST',
                'path': '/register',
                'description': 'Register a new user account',
                'body': {
                    'email': 'string (required)',
                    'password': 'string (required, min 6 chars)',
                    'name': 'string (required)'
                },
                'response': {
                    'success': 'boolean',
                    'message': 'string',
                    'token': 'string (JWT)',
                    'user': {
                        'id': 'string',
                        'email': 'string',
                        'name': 'string'
                    }
                }
            },
            'login': {
                'method': 'POST',
                'path': '/login',
                'description': 'Authenticate existing user',
                'body': {
                    'email': 'string (required)',
                    'password': 'string (required)'
                },
                'response': {
                    'success': 'boolean',
                    'message': 'string',
                    'token': 'string (JWT)',
                    'user': {
                        'id': 'string',
                        'email': 'string',
                        'name': 'string'
                    }
                }
            },
            'verify': {
                'method': 'POST',
                'path': '/verify',
                'description': 'Verify JWT token validity',
                'body': {
                    'token': 'string (required)'
                },
                'response': {
                    'success': 'boolean',
                    'message': 'string',
                    'user': {
                        'id': 'string',
                        'email': 'string',
                        'name': 'string'
                    }
                }
            }
        },
        'examples': {
            'curl_register': f'curl -X POST {host}/register -H "Content-Type: application/json" -d \'{{"email":"test@example.com","password":"test123","name":"Test User"}}\'',
            'curl_login': f'curl -X POST {host}/login -H "Content-Type: application/json" -d \'{{"email":"test@example.com","password":"test123"}}\'',
            'curl_verify': f'curl -X POST {host}/verify -H "Content-Type: application/json" -d \'{{"token":"YOUR_JWT_TOKEN_HERE"}}\''
        },
        'security': {
            'password_hashing': 'bcrypt with salt',
            'jwt_algorithm': 'HS256',
            'token_expiration': f'{app.config["JWT_EXPIRES_DELTA"].total_seconds() / 3600} hours',
            'rate_limiting': 'Enabled (200 requests per day, 50 per hour)'
        },
        'cors': 'Enabled for configured origins',
        'github': 'https://github.com/yourusername/OpenJWT',
        'license': 'MIT'
    }
    
    return jsonify(documentation)

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'success': True,
        'message': 'Service is healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': '1.0.0'
    })

# Register endpoint
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user."""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Request body is required'
            }), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        # Validate input
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Please provide a valid email address'
            }), 400
        
        if not validate_password(password):
            return jsonify({
                'success': False,
                'message': 'Password must be at least 6 characters long'
            }), 400
        
        if not validate_name(name):
            return jsonify({
                'success': False,
                'message': 'Name is required'
            }), 400
        
        # Check if user already exists
        if email in users:
            return jsonify({
                'success': False,
                'message': 'User with this email already exists'
            }), 409
        
        # Hash password
        hashed_password = hash_password(password)
        
        # Create user
        user_id = str(uuid.uuid4())
        user = {
            'id': user_id,
            'email': email,
            'name': name,
            'password': hashed_password,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Store user
        users[email] = user
        
        # Create access token
        additional_claims = {
            'user_id': user_id,
            'email': email,
            'name': name
        }
        token = create_access_token(identity=email, additional_claims=additional_claims)
        
        # Return success response
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user_id,
                'email': email,
                'name': name
            }
        }), 201
        
    except Exception as e:
        app.logger.error(f'Registration error: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500

# Login endpoint
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Authenticate existing user."""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Request body is required'
            }), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validate input
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Please provide a valid email address'
            }), 400
        
        if not password:
            return jsonify({
                'success': False,
                'message': 'Password is required'
            }), 400
        
        # Find user
        user = users.get(email)
        if not user:
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        # Verify password
        if not verify_password(password, user['password']):
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        # Create access token
        additional_claims = {
            'user_id': user['id'],
            'email': user['email'],
            'name': user['name']
        }
        token = create_access_token(identity=email, additional_claims=additional_claims)
        
        # Return success response
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name']
            }
        })
        
    except Exception as e:
        app.logger.error(f'Login error: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500

# Verify endpoint
@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify_token():
    """Verify JWT token validity."""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Request body is required'
            }), 400
        
        token = data.get('token', '').strip()
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Token is required'
            }), 400
        
        # Verify token manually using Flask-JWT-Extended
        from flask_jwt_extended import decode_token
        
        try:
            decoded_token = decode_token(token)
            email = decoded_token['sub']  # 'sub' contains the identity
            claims = decoded_token
            
            # Check if user still exists
            user = users.get(email)
            if not user:
                return jsonify({
                    'success': False,
                    'message': 'Token is valid but user no longer exists'
                }), 401
            
            # Return success response
            return jsonify({
                'success': True,
                'message': 'Token is valid',
                'user': {
                    'id': claims.get('user_id', user['id']),
                    'email': claims.get('email', user['email']),
                    'name': claims.get('name', user['name'])
                }
            })
            
        except Exception as token_error:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired token'
            }), 401
        
    except Exception as e:
        app.logger.error(f'Token verification error: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f'🚀 OpenJWT Server is running on port {port}')
    print(f'📖 Documentation: http://localhost:{port}/')
    print(f'🏥 Health check: http://localhost:{port}/health')
    
    app.run(host='0.0.0.0', port=port, debug=debug)
