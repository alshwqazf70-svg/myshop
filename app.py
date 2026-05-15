import os
import re
import sys
import json
import uuid
import time
import secrets
import logging
import requests
import statistics
import sqlite3
from math import radians, cos, sin, asin, sqrt, atan2, degrees
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from functools import wraps
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

# ====== التحقق من البيئة والتوافق ======
print("=" * 60)
print("🌟 GeoLegend Ultimate 3D System - Starting...")
print("=" * 60)

# ====== إصلاح eventlet لـ Gunicorn ======
GUNICORN = os.environ.get('GUNICORN', 'false').lower() == 'true'
if not GUNICORN:
    try:
        import eventlet
        eventlet.monkey_patch()
        print("✅ eventlet monkey patch applied")
    except ImportError:
        print("⚠️ eventlet not installed, using threading mode")

# ====== استيراد المكتبات الرئيسية ======
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_caching import Cache
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ====== إعدادات التطبيق الأساسية ======
app = Flask(__name__, static_folder='static', template_folder='templates')

# تصحيح الـ Proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ====== إعدادات الأمان ======
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

# ====== إعدادات قاعدة البيانات ======
basedir = os.path.abspath(os.path.dirname(__file__))

# إنشاء مجلد data إذا لم يكن موجوداً
data_dir = os.path.join(basedir, 'data')
if not os.path.exists(data_dir):
    os.makedirs(data_dir)
    print(f"📁 Created data directory: {data_dir}")

# دعم SQLite و PostgreSQL
database_url = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(data_dir, "geo_legend.db")}')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ====== إعدادات JWT ======
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

# ====== إعدادات الجلسة ======
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ====== CORS - تقييد النطاقات المسموحة ======
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000,https://*.onrender.com,https://*.railway.app').split(',')

# إزالة القيم الفارغة وتنظيفها
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS if o.strip()]
print(f"🔒 Allowed origins: {ALLOWED_ORIGINS}")

# تكوين CORS
if '*' in ALLOWED_ORIGINS:
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/socket.io/*": {"origins": "*"}})
    print("⚠️ CORS: All origins allowed (development mode)")
else:
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}, r"/socket.io/*": {"origins": ALLOWED_ORIGINS}})
    print("✅ CORS: Restricted to specific origins")

# ====== تهيئة SQLAlchemy ======
db = SQLAlchemy(app)

# ====== تهيئة JWT ======
jwt = JWTManager(app)

# ====== تهيئة Limiter ======
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# ====== تهيئة Cache ======
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_THRESHOLD': 500
})

# ====== تهيئة SocketIO ======
if GUNICORN:
    # مع Gunicorn، نستخدم وضع eventlet
    socketio = SocketIO(
        app,
        cors_allowed_origins=ALLOWED_ORIGINS if '*' not in ALLOWED_ORIGINS else "*",
        async_mode='eventlet',
        ping_timeout=60,
        ping_interval=25,
        logger=False,
        engineio_logger=False,
        max_http_buffer_size=1000000
    )
else:
    socketio = SocketIO(
        app,
        cors_allowed_origins=ALLOWED_ORIGINS if '*' not in ALLOWED_ORIGINS else "*",
        async_mode='eventlet',
        ping_timeout=60,
        ping_interval=25,
        logger=False,
        engineio_logger=False,
        max_http_buffer_size=1000000
    )

print(f"✅ SocketIO initialized with async_mode={socketio.async_mode}")

# ====== إعدادات التسجيل (Logging) ======
logs_dir = os.path.join(basedir, 'logs')
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# إعداد معالج للملفات
file_handler = RotatingFileHandler(
    os.path.join(logs_dir, 'geolegend.log'),
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)

error_handler = RotatingFileHandler(
    os.path.join(logs_dir, 'errors.log'),
    maxBytes=10 * 1024 * 1024,
    backupCount=5
)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
error_handler.setLevel(logging.ERROR)

app.logger.addHandler(file_handler)
app.logger.addHandler(error_handler)
app.logger.setLevel(logging.INFO)

# ====== إنشاء المجلدات المطلوبة ======
def ensure_directories():
    """إنشاء جميع المجلدات المطلوبة للتطبيق"""
    directories = ['templates', 'static', 'static/icons', 'data', 'logs']
    for d in directories:
        d_path = os.path.join(basedir, d)
        if not os.path.exists(d_path):
            os.makedirs(d_path)
            print(f'📁 Created directory: {d}')
    
    # إنشاء ملف index.html في مجلد templates إذا لم يكن موجوداً
    index_path = os.path.join(basedir, 'templates', 'index.html')
    if not os.path.exists(index_path):
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(get_default_html())
        print('📄 Created default index.html')
    
    # إنشاء أيقونات افتراضية
    icons_dir = os.path.join(basedir, 'static', 'icons')
    icon_192 = os.path.join(icons_dir, 'icon-192.png')
    icon_512 = os.path.join(icons_dir, 'icon-512.png')
    
    if not os.path.exists(icon_192):
        create_default_icon(icon_192, 192)
    if not os.path.exists(icon_512):
        create_default_icon(icon_512, 512)

def create_default_icon(path, size):
    """إنشاء أيقونة افتراضية"""
    try:
        from PIL import Image, ImageDraw
        
        img = Image.new('RGB', (size, size), color='#0a0a1a')
        draw = ImageDraw.Draw(img)
        
        # رسم دائرة خارجية
        draw.ellipse([5, 5, size-5, size-5], outline='#00ffff', width=5)
        
        # رسم دائرة داخلية
        draw.ellipse([size//4, size//4, size*3//4, size*3//4], fill='#00ffff')
        
        # رسم نقطة مركزية
        center = size // 2
        draw.ellipse([center-5, center-5, center+5, center+5], fill='white')
        
        img.save(path)
        print(f'✅ Created icon: {os.path.basename(path)}')
    except ImportError:
        # PIL غير مثبت
        with open(path, 'wb') as f:
            f.write(b'')
        print(f'⚠️ PIL not installed, created empty icon: {os.path.basename(path)}')
    except Exception as e:
        print(f'❌ Failed to create icon: {str(e)}')
        with open(path, 'wb') as f:
            f.write(b'')

def get_default_html():
    """إرجاع الـ HTML الأساسي للتطبيق"""
    return """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GeoLegend - نظام التتبع المباشر</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Cairo', 'Tahoma', sans-serif; background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { text-align: center; padding: 40px; background: rgba(10, 10, 30, 0.8); backdrop-filter: blur(10px); border-radius: 24px; border: 1px solid rgba(0, 255, 255, 0.3); max-width: 500px; margin: 20px; }
        h1 { color: #00ffff; font-size: 2rem; margin-bottom: 10px; }
        .subtitle { color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        .status { background: rgba(0, 255, 136, 0.2); border: 1px solid #00ff88; border-radius: 12px; padding: 15px; margin: 20px 0; }
        .status h3 { color: #00ff88; margin-bottom: 10px; }
        .features { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; margin: 20px 0; }
        .feature { background: rgba(255,255,255,0.1); border-radius: 20px; padding: 8px 16px; font-size: 12px; }
        .footer { margin-top: 30px; font-size: 11px; color: rgba(255,255,255,0.4); }
        .loading { display: inline-block; width: 20px; height: 20px; border: 2px solid #00ffff; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 10px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌟 GeoLegend Ultimate 3D</h1>
        <p class="subtitle">أقوى نظام تتبع مباشر ثلاثي الأبعاد</p>
        <div class="status">
            <h3>✅ الخادم يعمل بشكل طبيعي</h3>
            <p>جاري تحميل التطبيق...</p>
            <div style="margin-top: 15px;"><span class="loading"></span> يرجى الانتظار</div>
        </div>
        <div class="features">
            <span class="feature">📍 تتبع مباشر</span>
            <span class="feature">🗺️ خريطة 3D واقعية</span>
            <span class="feature">👨‍👩‍👧‍👦 مشاركة العائلة</span>
            <span class="feature">🚨 SOS طوارئ</span>
            <span class="feature">🔗 مشاركة الموقع</span>
            <span class="feature">🚗 تسجيل الرحلات</span>
        </div>
        <div class="footer">
            GeoLegend v3.0 | جميع الحقوق محفوظة
        </div>
    </div>
    <script>
        // إعادة التوجيه إلى التطبيق الكامل بعد 2 ثانية
        setTimeout(function() {
            if (window.location.pathname === '/') {
                window.location.reload();
            }
        }, 2000);
    </script>
</body>
</html>"""

# تنفيذ إنشاء المجلدات
ensure_directories()

# ====== وقت بدء التشغيل ======
app.start_time = time.time()

print(f"✅ Python version: {sys.version}")
print(f"✅ Database URL: {database_url}")
print(f"✅ Debug mode: {app.debug}")
print(f"✅ Gunicorn mode: {GUNICORN}")

# ====== نماذج قاعدة البيانات ======

class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_created', 'created_at'),
        db.Index('idx_user_name', 'name'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(200), default='default.png')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # العلاقات
    current_location = db.relationship('CurrentLocation', backref='user', uselist=False, cascade='all, delete-orphan')
    location_history = db.relationship('LocationHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    rooms = db.relationship('Room', backref='creator', lazy=True, foreign_keys='Room.creator_id')
    trips = db.relationship('Trip', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    geofences = db.relationship('Geofence', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    family_memberships = db.relationship('FamilyMember', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'avatar': self.avatar,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<User {self.email}>'

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    __table_args__ = (
        db.Index('idx_token_jti', 'jti'),
        db.Index('idx_token_created', 'created_at'),
        db.Index('idx_token_user', 'user_id'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    token_type = db.Column(db.String(16), nullable=False, default='access')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f'<TokenBlocklist {self.jti}>'

class CurrentLocation(db.Model):
    __tablename__ = 'current_locations'
    __table_args__ = (
        db.Index('idx_current_user', 'user_id'),
        db.Index('idx_current_updated', 'updated_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, default=0.0)
    heading = db.Column(db.Float, default=0.0)
    accuracy = db.Column(db.Float, default=0.0)
    battery_level = db.Column(db.Float, default=100.0)
    device_type = db.Column(db.String(50), default='unknown')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    def to_dict(self):
        return {
            'lat': self.lat,
            'lng': self.lng,
            'speed': self.speed,
            'heading': self.heading,
            'accuracy': self.accuracy,
            'battery_level': self.battery_level,
            'device_type': self.device_type,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class LocationHistory(db.Model):
    __tablename__ = 'location_history'
    __table_args__ = (
        db.Index('idx_history_user_time', 'user_id', 'timestamp'),
        db.Index('idx_history_coords', 'lat', 'lng'),
        db.Index('idx_history_speed', 'speed'),
        db.Index('idx_history_timestamp', 'timestamp'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, default=0.0)
    heading = db.Column(db.Float, default=0.0)
    accuracy = db.Column(db.Float, default=0.0)
    battery_level = db.Column(db.Float, default=100.0)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    def to_dict(self):
        return {
            'lat': self.lat,
            'lng': self.lng,
            'speed': self.speed,
            'heading': self.heading,
            'accuracy': self.accuracy,
            'battery_level': self.battery_level,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class Room(db.Model):
    __tablename__ = 'rooms'
    __table_args__ = (
        db.Index('idx_room_id', 'room_id'),
        db.Index('idx_room_creator', 'creator_id'),
        db.Index('idx_room_active', 'is_active'),
        db.Index('idx_room_expiry', 'expiry'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    participants = db.Column(db.Text, default='')
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id', ondelete='SET NULL'), nullable=True)
    family_id = db.Column(db.Integer, db.ForeignKey('families.id', ondelete='SET NULL'), nullable=True)
    is_private = db.Column(db.Boolean, default=False)
    share_pin = db.Column(db.String(6), nullable=True)
    expiry = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def is_expired(self):
        if not self.expiry:
            return False
        return datetime.now(timezone.utc) > self.expiry
    
    def to_dict(self):
        return {
            'id': self.id,
            'room_id': self.room_id,
            'creator_id': self.creator_id,
            'is_private': self.is_private,
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SOSAlert(db.Model):
    __tablename__ = 'sos_alerts'
    __table_args__ = (
        db.Index('idx_sos_user', 'user_id'),
        db.Index('idx_sos_resolved', 'resolved'),
        db.Index('idx_sos_timestamp', 'timestamp'),
        db.Index('idx_sos_time_resolved', 'timestamp', 'resolved'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    message = db.Column(db.String(500), default='🚨 طلب مساعدة عاجل')
    responder_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='sos_alerts')
    responder = db.relationship('User', foreign_keys=[responder_id], backref='responded_sos')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'lat': self.lat,
            'lng': self.lng,
            'message': self.message,
            'resolved': self.resolved,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class Friendship(db.Model):
    __tablename__ = 'friendships'
    __table_args__ = (
        db.Index('idx_friendship_users', 'requester_id', 'addressee_id'),
        db.Index('idx_friendship_status', 'status'),
        db.Index('idx_friendship_created', 'created_at'),
        db.UniqueConstraint('requester_id', 'addressee_id', name='unique_friendship'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    addressee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    requester = db.relationship('User', foreign_keys=[requester_id], backref='sent_requests')
    addressee = db.relationship('User', foreign_keys=[addressee_id], backref='received_requests')
    
    def to_dict(self):
        return {
            'id': self.id,
            'requester_id': self.requester_id,
            'addressee_id': self.addressee_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Group(db.Model):
    __tablename__ = 'groups'
    __table_args__ = (
        db.Index('idx_group_creator', 'creator_id'),
        db.Index('idx_group_active', 'is_active'),
        db.Index('idx_group_name', 'name'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    description = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', backref='created_groups')
    members = db.relationship('GroupMember', backref='group', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'creator_id': self.creator_id,
            'description': self.description,
            'member_count': self.members.count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    __table_args__ = (
        db.Index('idx_group_member', 'group_id', 'user_id'),
        db.UniqueConstraint('group_id', 'user_id', name='unique_group_member'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref='group_memberships')
    
    def to_dict(self):
        return {
            'group_id': self.group_id,
            'user_id': self.user_id,
            'role': self.role,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None
        }

class Family(db.Model):
    __tablename__ = 'families'
    __table_args__ = (
        db.Index('idx_family_creator', 'creator_id'),
        db.Index('idx_family_code', 'join_code'),
        db.Index('idx_family_active', 'is_active'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    join_code = db.Column(db.String(10), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', backref='created_families')
    members = db.relationship('FamilyMember', backref='family', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'join_code': self.join_code,
            'member_count': self.members.count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class FamilyMember(db.Model):
    __tablename__ = 'family_members'
    __table_args__ = (
        db.Index('idx_family_member', 'family_id', 'user_id'),
        db.UniqueConstraint('family_id', 'user_id', name='unique_family_member'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    family_id = db.Column(db.Integer, db.ForeignKey('families.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref='family_memberships')
    
    def to_dict(self):
        return {
            'family_id': self.family_id,
            'user_id': self.user_id,
            'role': self.role,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None
        }

class Trip(db.Model):
    __tablename__ = 'trips'
    __table_args__ = (
        db.Index('idx_trip_user', 'user_id'),
        db.Index('idx_trip_active', 'is_active'),
        db.Index('idx_trip_date', 'started_at'),
        db.Index('idx_trip_user_active', 'user_id', 'is_active'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(200), default='رحلة جديدة')
    start_lat = db.Column(db.Float, nullable=False)
    start_lng = db.Column(db.Float, nullable=False)
    end_lat = db.Column(db.Float, nullable=True)
    end_lng = db.Column(db.Float, nullable=True)
    total_distance = db.Column(db.Float, default=0.0)
    avg_speed = db.Column(db.Float, default=0.0)
    max_speed = db.Column(db.Float, default=0.0)
    duration_minutes = db.Column(db.Float, default=0.0)
    trip_type = db.Column(db.String(50), default='car')
    notes = db.Column(db.Text, default='')
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ended_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    path_data = db.Column(db.Text, default='[]')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'total_distance': round(self.total_distance, 2),
            'avg_speed': round(self.avg_speed, 1),
            'max_speed': round(self.max_speed, 1),
            'duration_minutes': round(self.duration_minutes, 1),
            'trip_type': self.trip_type,
            'is_active': self.is_active,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None
        }

class Geofence(db.Model):
    __tablename__ = 'geofences'
    __table_args__ = (
        db.Index('idx_geofence_user', 'user_id'),
        db.Index('idx_geofence_active', 'is_active'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, default=100.0)
    is_active = db.Column(db.Boolean, default=True)
    notify_on_enter = db.Column(db.Boolean, default=True)
    notify_on_exit = db.Column(db.Boolean, default=True)
    geofence_type = db.Column(db.String(50), default='circle')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'lat': self.lat,
            'lng': self.lng,
            'radius': self.radius,
            'is_active': self.is_active,
            'notify_on_enter': self.notify_on_enter,
            'notify_on_exit': self.notify_on_exit,
            'geofence_type': self.geofence_type,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class GeofenceEvent(db.Model):
    __tablename__ = 'geofence_events'
    __table_args__ = (
        db.Index('idx_geofence_event_time', 'timestamp'),
        db.Index('idx_geofence_event_user', 'user_id', 'geofence_id'),
        db.Index('idx_geofence_event_entering', 'entering'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    geofence_id = db.Column(db.Integer, db.ForeignKey('geofences.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    entering = db.Column(db.Boolean, default=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'geofence_id': self.geofence_id,
            'user_id': self.user_id,
            'entering': self.entering,
            'lat': self.lat,
            'lng': self.lng,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class Notification(db.Model):
    __tablename__ = 'notifications'
    __table_args__ = (
        db.Index('idx_notif_user', 'user_id', 'is_read'),
        db.Index('idx_notif_created', 'created_at'),
        db.Index('idx_notif_user_unread', 'user_id', 'is_read', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    data = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'is_read': self.is_read,
            'data': json.loads(self.data) if self.data else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None
        }

class AnalyticsSnapshot(db.Model):
    __tablename__ = 'analytics_snapshots'
    __table_args__ = (
        db.Index('idx_analytics_user_date', 'user_id', 'date'),
        db.Index('idx_analytics_date', 'date'),
        db.UniqueConstraint('user_id', 'date', name='unique_user_date'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    date = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    total_distance = db.Column(db.Float, default=0.0)
    total_time_minutes = db.Column(db.Float, default=0.0)
    locations_count = db.Column(db.Integer, default=0)
    trips_count = db.Column(db.Integer, default=0)
    avg_speed = db.Column(db.Float, default=0.0)
    max_speed = db.Column(db.Float, default=0.0)
    sos_count = db.Column(db.Integer, default=0)
    geofence_events_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'date': self.date.isoformat() if self.date else None,
            'total_distance': round(self.total_distance, 2),
            'total_time_minutes': round(self.total_time_minutes, 1),
            'locations_count': self.locations_count,
            'trips_count': self.trips_count,
            'avg_speed': round(self.avg_speed, 1),
            'max_speed': round(self.max_speed, 1),
            'sos_count': self.sos_count,
            'geofence_events_count': self.geofence_events_count
        }

# ====== دوال مساعدة ======

def make_aware(dt):
    """تحويل التاريخ إلى timezone-aware"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def is_valid_email(email):
    """التحقق من صحة البريد الإلكتروني"""
    if not email or not isinstance(email, str):
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_coordinates(lat, lng):
    """التحقق من صحة الإحداثيات"""
    try:
        lat_float = float(lat)
        lng_float = float(lng)
        return -90 <= lat_float <= 90 and -180 <= lng_float <= 180
    except (ValueError, TypeError):
        return False

def sanitize_input(text, max_length=1000):
    """تطهير النصوص من XSS"""
    if not text or not isinstance(text, str):
        return ''
    # إزالة علامات HTML
    text = re.sub(r'<[^>]*>', '', text)
    # إزالة الأقواس المعقوفة
    text = re.sub(r'[<>{}]', '', text)
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text

def sanitize_email(email):
    """تطهير البريد الإلكتروني"""
    if not email or not isinstance(email, str):
        return ''
    return email.lower().strip()[:120]

def haversine_distance(lat1, lng1, lat2, lng2):
    """حساب المسافة بين نقطتين بالكيلومترات"""
    try:
        if None in [lat1, lng1, lat2, lng2]:
            return 0.0
        
        lat1_rad = radians(float(lat1))
        lng1_rad = radians(float(lng1))
        lat2_rad = radians(float(lat2))
        lng2_rad = radians(float(lng2))
        
        dlat = lat2_rad - lat1_rad
        dlng = lng2_rad - lng1_rad
        
        a = sin(dlat/2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlng/2)**2
        a = min(1.0, max(0.0, a))
        c = 2 * asin(sqrt(a))
        
        return 6371.0 * c
    except Exception as e:
        app.logger.error(f'Error in haversine_distance: {str(e)}')
        return 0.0

def calculate_bearing(lat1, lng1, lat2, lng2):
    """حساب الاتجاه بين نقطتين"""
    try:
        if None in [lat1, lng1, lat2, lng2]:
            return 0.0
        
        lat1_rad = radians(float(lat1))
        lng1_rad = radians(float(lng1))
        lat2_rad = radians(float(lat2))
        lng2_rad = radians(float(lng2))
        
        dlng = lng2_rad - lng1_rad
        x = sin(dlng) * cos(lat2_rad)
        y = cos(lat1_rad) * sin(lat2_rad) - sin(lat1_rad) * cos(lat2_rad) * cos(dlng)
        brng = atan2(x, y)
        
        return (degrees(brng) + 360) % 360
    except Exception as e:
        app.logger.error(f'Error in calculate_bearing: {str(e)}')
        return 0.0

def calculate_speed(pos1, pos2):
    """حساب السرعة بين موقعين (كم/ساعة)"""
    if not pos1 or not pos2:
        return 0.0
    
    try:
        # استخراج الإحداثيات بأمان
        if isinstance(pos1, dict):
            lat1 = pos1.get('lat')
            lng1 = pos1.get('lng')
            ts1 = pos1.get('timestamp')
        else:
            lat1 = getattr(pos1, 'lat', None)
            lng1 = getattr(pos1, 'lng', None)
            ts1 = getattr(pos1, 'timestamp', None)
        
        if isinstance(pos2, dict):
            lat2 = pos2.get('lat')
            lng2 = pos2.get('lng')
            ts2 = pos2.get('timestamp')
        else:
            lat2 = getattr(pos2, 'lat', None)
            lng2 = getattr(pos2, 'lng', None)
            ts2 = getattr(pos2, 'timestamp', None)
        
        if None in [lat1, lng1, lat2, lng2, ts1, ts2]:
            return 0.0
        
        distance = haversine_distance(lat1, lng1, lat2, lng2)
        
        # تحويل الطوابع الزمنية
        if hasattr(ts1, 'timestamp'):
            time1 = ts1.timestamp()
        elif isinstance(ts1, (int, float)):
            time1 = ts1
        else:
            try:
                time1 = datetime.fromisoformat(str(ts1)).timestamp()
            except:
                return 0.0
        
        if hasattr(ts2, 'timestamp'):
            time2 = ts2.timestamp()
        elif isinstance(ts2, (int, float)):
            time2 = ts2
        else:
            try:
                time2 = datetime.fromisoformat(str(ts2)).timestamp()
            except:
                return 0.0
        
        time_diff = abs(time2 - time1)
        if time_diff <= 0:
            return 0.0
        
        return (distance / time_diff) * 3600.0
    except Exception as e:
        app.logger.error(f'Error in calculate_speed: {str(e)}')
        return 0.0

def analyze_movement(locations):
    """تحليل نمط الحركة"""
    if not locations or len(locations) < 5:
        return {'pattern': 'غير كاف', 'confidence': 0, 'message': 'لا توجد بيانات كافية'}
    
    try:
        patterns = {'stationary': 0, 'walking': 0, 'running': 0, 'driving': 0, 'unknown': 0}
        speeds = []
        total_distance = 0.0
        
        for i in range(1, len(locations)):
            loc1 = locations[i-1]
            loc2 = locations[i]
            
            # استخراج الإحداثيات بأمان
            if isinstance(loc1, dict):
                lat1 = loc1.get('lat')
                lng1 = loc1.get('lng')
                speed1 = loc1.get('speed', 0)
            else:
                lat1 = getattr(loc1, 'lat', None)
                lng1 = getattr(loc1, 'lng', None)
                speed1 = getattr(loc1, 'speed', 0)
            
            if isinstance(loc2, dict):
                lat2 = loc2.get('lat')
                lng2 = loc2.get('lng')
                speed2 = loc2.get('speed', 0)
            else:
                lat2 = getattr(loc2, 'lat', None)
                lng2 = getattr(loc2, 'lng', None)
                speed2 = getattr(loc2, 'speed', 0)
            
            if None in [lat1, lng1, lat2, lng2]:
                continue
            
            distance = haversine_distance(lat1, lng1, lat2, lng2)
            total_distance += distance
            
            # استخدام السرعة المحسوبة أو المخزنة
            if speed1 > 0:
                spd = speed1
            else:
                spd = calculate_speed(loc1, loc2)
            
            if spd < 200:  # تصفية القيم الشاذة
                speeds.append(spd)
                
                if spd < 2:
                    patterns['stationary'] += 1
                elif spd < 8:
                    patterns['walking'] += 1
                elif spd < 15:
                    patterns['running'] += 1
                elif spd > 15:
                    patterns['driving'] += 1
                else:
                    patterns['unknown'] += 1
        
        if not speeds:
            return {'pattern': 'غير كاف', 'confidence': 0, 'message': 'لا توجد سرعات صالحة'}
        
        dominant = max(patterns, key=patterns.get)
        avg_speed = statistics.mean(speeds) if speeds else 0.0
        max_speed = max(speeds) if speeds else 0.0
        
        # اكتشاف الحوادث (توقف مفاجئ بعد سرعة عالية)
        accident_detected = False
        if len(speeds) >= 3:
            for i in range(len(speeds)-1):
                if speeds[i] > 30 and speeds[i+1] < 3:
                    accident_detected = True
                    break
        
        total_locations = len(locations)
        confidence = round(patterns[dominant] / total_locations * 100, 1) if total_locations > 0 else 0
        
        return {
            'pattern': dominant,
            'confidence': confidence,
            'average_speed': round(avg_speed, 1),
            'max_speed': round(max_speed, 1),
            'total_distance': round(total_distance, 2),
            'accident_detected': accident_detected,
            'details': patterns
        }
    except Exception as e:
        app.logger.error(f'Error in analyze_movement: {str(e)}')
        return {'pattern': 'خطأ', 'confidence': 0, 'message': str(e)}

def create_notification(user_id, title, message, n_type='info', data=None):
    """إنشاء إشعار جديد"""
    if not user_id or not title or not message:
        return None
    
    try:
        title = sanitize_input(title, 200)
        message = sanitize_input(message, 500)
        n_type = sanitize_input(n_type, 50)
        
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            type=n_type,
            data=json.dumps(data) if data else '{}'
        )
        db.session.add(notif)
        db.session.commit()
        
        notification_dict = notif.to_dict()
        socketio.emit('new_notification', notification_dict, room=f'user_{user_id}')
        
        return notif
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in create_notification: {str(e)}')
        return None

def notify_family_members(user_id, message, limit_per_minute=True):
    """إشعار أفراد العائلة"""
    if not user_id or not message:
        return
    
    try:
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        now = datetime.now(timezone.utc)
        
        for fam in families:
            family_members = FamilyMember.query.filter_by(family_id=fam.family_id).all()
            
            for member in family_members:
                if member.user_id == user_id:
                    continue
                
                # التحقق من تكرار الإشعارات
                if limit_per_minute:
                    cache_key = f'last_family_notification_{member.user_id}'
                    last_time = cache.get(cache_key)
                    
                    if last_time and isinstance(last_time, datetime):
                        if (now - last_time).total_seconds() < 60:
                            continue
                    
                    cache.set(cache_key, now, timeout=65)
                
                create_notification(
                    member.user_id,
                    '👨‍👩‍👧‍👦 العائلة',
                    message,
                    'family'
                )
                
                socketio.emit('new_notification', {
                    'title': '👨‍👩‍👧‍👦 العائلة',
                    'message': message,
                    'type': 'family'
                }, room=f'user_{member.user_id}')
    except Exception as e:
        app.logger.error(f'Error in notify_family_members: {str(e)}')

def detect_geofence_events(user_id, lat, lng):
    """كشف أحداث الأسوار الجغرافية"""
    events = []
    
    try:
        # الأسوار التي أنشأها المستخدم نفسه
        user_geofences = Geofence.query.filter_by(user_id=user_id, is_active=True).all()
        
        # الأسوار التي أنشأتها عائلة المستخدم
        family_geofences = []
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        for fam in families:
            family_geofences.extend(Geofence.query.filter_by(user_id=fam.family.creator_id, is_active=True).all())
        
        # دمج الأسوار بدون تكرار باستخدام قاموس
        geofence_dict = {}
        for g in user_geofences:
            geofence_dict[g.id] = g
        for g in family_geofences:
            if g.id not in geofence_dict:
                geofence_dict[g.id] = g
        
        all_geofences = list(geofence_dict.values())
        
        for geo in all_geofences:
            distance = haversine_distance(lat, lng, geo.lat, geo.lng) * 1000  # تحويل إلى متر
            
            cache_key = f'geofence_last_event_{geo.id}_{user_id}'
            last_event_data = cache.get(cache_key)
            
            if last_event_data is None:
                last_event = GeofenceEvent.query.filter_by(
                    geofence_id=geo.id,
                    user_id=user_id
                ).order_by(GeofenceEvent.timestamp.desc()).first()
                
                last_event_data = {
                    'entering': last_event.entering if last_event else False,
                    'timestamp': last_event.timestamp.isoformat() if last_event else None
                }
                cache.set(cache_key, last_event_data, timeout=60)
            
            currently_inside = distance <= geo.radius
            was_inside = last_event_data.get('entering', False) if isinstance(last_event_data, dict) else False
            
            if currently_inside and not was_inside:
                if geo.notify_on_enter:
                    event = GeofenceEvent(
                        geofence_id=geo.id,
                        user_id=user_id,
                        entering=True,
                        lat=lat,
                        lng=lng
                    )
                    db.session.add(event)
                    events.append({'type': 'enter', 'geofence': geo.name, 'distance': round(distance, 1)})
                    
                    cache.set(cache_key, {'entering': True, 'timestamp': datetime.now(timezone.utc).isoformat()}, timeout=60)
                    
                    create_notification(
                        user_id,
                        f'📍 {geo.name}',
                        f'تم الدخول إلى منطقة {geo.name}',
                        'geofence_enter'
                    )
                    
                    user = User.query.get(user_id)
                    if user:
                        notify_family_members(
                            user_id,
                            f'📍 دخل {user.name} منطقة {geo.name}',
                            limit_per_minute=True
                        )
                    
            elif not currently_inside and was_inside:
                if geo.notify_on_exit:
                    event = GeofenceEvent(
                        geofence_id=geo.id,
                        user_id=user_id,
                        entering=False,
                        lat=lat,
                        lng=lng
                    )
                    db.session.add(event)
                    events.append({'type': 'exit', 'geofence': geo.name, 'distance': round(distance, 1)})
                    
                    cache.set(cache_key, {'entering': False, 'timestamp': datetime.now(timezone.utc).isoformat()}, timeout=60)
                    
                    create_notification(
                        user_id,
                        f'📍 {geo.name}',
                        f'تم الخروج من منطقة {geo.name}',
                        'geofence_exit'
                    )
                    
                    user = User.query.get(user_id)
                    if user:
                        notify_family_members(
                            user_id,
                            f'📍 خرج {user.name} من منطقة {geo.name}',
                            limit_per_minute=True
                        )
        
        if events:
            db.session.commit()
        
        return events
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in detect_geofence_events: {str(e)}')
        return []

# ====== ديكوريتور التحقق من الإحداثيات ======
def validate_coordinates(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT'] and request.is_json:
            data = request.get_json()
            if data:
                lat = data.get('lat')
                lng = data.get('lng')
                if lat is not None and lng is not None:
                    if not is_valid_coordinates(lat, lng):
                        return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        return f(*args, **kwargs)
    return decorated_function

# ====== حماية Brute Force ======
class BruteForceProtection:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.max_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
        self.window_seconds = int(os.getenv('LOGIN_WINDOW_SECONDS', '300'))
    
    def check_ip(self, ip):
        now = datetime.now(timezone.utc)
        self.attempts[ip] = [
            t for t in self.attempts[ip] 
            if (now - t).total_seconds() < self.window_seconds
        ]
        
        if len(self.attempts[ip]) >= self.max_attempts:
            if self.attempts[ip]:
                first_attempt = self.attempts[ip][0]
                remaining_time = int(self.window_seconds - (now - first_attempt).total_seconds())
                if remaining_time < 0:
                    remaining_time = 0
                app.logger.warning(f'Brute force attempt blocked for IP: {ip}')
                return False, max(remaining_time, 0)
            return False, self.window_seconds
        
        self.attempts[ip].append(now)
        return True, 0
    
    def reset_ip(self, ip):
        self.attempts[ip] = []

brute_force = BruteForceProtection()

# ====== JWT Blocklist ======
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    try:
        jti = jwt_payload.get('jti')
        if not jti:
            return True
        
        cache_key = f'blocked_token_{jti}'
        if cache.get(cache_key):
            return True
        
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).first()
        if token:
            cache.set(cache_key, True, timeout=3600)
            return True
        
        return False
    except Exception as e:
        app.logger.error(f'Error checking token blocklist: {str(e)}')
        return True

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error': 'انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مجدداً.',
        'code': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'error': 'توكن غير صالح. الرجاء تسجيل الدخول.',
        'code': 'token_invalid'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'error': 'التوكن مطلوب. الرجاء تسجيل الدخول.',
        'code': 'token_missing'
    }), 401

# ====== Middleware ======
@app.before_request
def before_request():
    request.start_time = time.time()
    
    # السماح للمسارات العامة
    public_paths = ['/share/', '/api/share/', '/api/navigation/', '/health', '/manifest.json', '/sw.js']
    for path in public_paths:
        if request.path.startswith(path):
            return
    
    # التحقق من User-Agent (تخطي لبعض الطلبات)
    if request.path.startswith('/api/'):
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent and request.method not in ['OPTIONS']:
            app.logger.warning(f'Request without User-Agent from {request.remote_addr}')
            return jsonify({'error': 'User-Agent مطلوب'}), 400

@app.after_request
def after_request(response):
    # إضافة رؤوس الأمان
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # السماح بـ CORS للـ static files
    if request.path.startswith('/static/'):
        response.headers['Access-Control-Allow-Origin'] = '*'
    
    # إزالة معلومات الخادم
    response.headers.pop('Server', None)
    
    # تسجيل وقت الاستجابة للـ APIs
    if hasattr(request, 'start_time') and request.path.startswith('/api/'):
        elapsed = time.time() - request.start_time
        if elapsed > 1.0:
            app.logger.warning(f'Slow request: {request.method} {request.path} - {elapsed:.3f}s')
        elif app.debug:
            app.logger.debug(f'{request.method} {request.path} - {elapsed:.3f}s - {response.status_code}')
    
    return response

@app.teardown_appcontext
def shutdown_session(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()

# ====== الصفحات الأمامية ======
@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f'Error rendering index: {str(e)}')
        return get_default_html(), 200

@app.route('/share/<room_id>')
def share_view(room_id):
    try:
        room = Room.query.filter_by(room_id=room_id, is_active=True).first()
        if not room:
            return render_template('index.html', error='رابط المشاركة غير صالح')
        
        if room.is_expired():
            room.is_active = False
            db.session.commit()
            return render_template('index.html', error='انتهت صلاحية رابط المشاركة')
        
        return render_template('index.html', room_id=room_id, is_guest=True)
    except Exception as e:
        app.logger.error(f'Error in share_view: {str(e)}')
        return get_default_html(), 200

@app.route('/health')
def health_check():
    # التحقق من اتصال قاعدة البيانات
    db_status = 'connected'
    try:
        db.session.execute('SELECT 1')
    except Exception as e:
        db_status = f'disconnected: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '3.0.0',
        'uptime': round(time.time() - app.start_time, 2),
        'database': db_status,
        'gunicorn_mode': GUNICORN
    })

# ====== API عامة (بدون JWT) ======
@app.route('/api/share/<room_id>/location', methods=['GET'])
@limiter.limit("30 per minute")
def get_shared_location(room_id):
    """جلب موقع المشاركة - لا يحتاج تسجيل دخول"""
    app.logger.info(f'📍 Shared location request for room: {room_id}')
    
    try:
        room = Room.query.filter_by(room_id=room_id, is_active=True).first()
        if not room:
            return jsonify({'error': 'رابط غير صالح'}), 404
        
        if room.is_expired():
            room.is_active = False
            db.session.commit()
            return jsonify({'error': 'انتهت صلاحية رابط المشاركة'}), 410
        
        current_location = CurrentLocation.query.filter_by(user_id=room.creator_id).first()
        user = User.query.get(room.creator_id)
        
        if current_location and user:
            updated_at = make_aware(current_location.updated_at)
            now = datetime.now(timezone.utc)
            seconds_ago = int((now - updated_at).total_seconds()) if updated_at else 999
            is_online = seconds_ago < 60
            
            app.logger.info(f'✅ Sending location for user: {user.name}')
            
            return jsonify({
                'status': 'success',
                'location': {
                    'lat': current_location.lat,
                    'lng': current_location.lng,
                    'speed': current_location.speed,
                    'heading': current_location.heading,
                    'accuracy': current_location.accuracy,
                    'name': user.name,
                    'is_online': is_online,
                    'seconds_ago': seconds_ago,
                    'updated_at': current_location.updated_at.isoformat() if current_location.updated_at else None
                }
            })
        
        app.logger.warning(f'⚠️ No location found for user {room.creator_id}')
        return jsonify({'status': 'no_data', 'message': 'لا يوجد موقع حالي'}), 404
        
    except Exception as e:
        app.logger.error(f'Error in get_shared_location: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء جلب الموقع'}), 500

@app.route('/api/navigation/public', methods=['POST'])
@limiter.limit("20 per minute")
def get_public_route():
    """حساب مسارات متعددة - لا يحتاج تسجيل دخول"""
    try:
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        start_lat = data.get('start_lat')
        start_lng = data.get('start_lng')
        end_lat = data.get('end_lat')
        end_lng = data.get('end_lng')
        
        if None in [start_lat, start_lng, end_lat, end_lng]:
            return jsonify({'error': 'جميع الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(start_lat, start_lng):
            return jsonify({'error': 'إحداثيات البداية غير صالحة'}), 400
        
        if not is_valid_coordinates(end_lat, end_lng):
            return jsonify({'error': 'إحداثيات النهاية غير صالحة'}), 400
        
        # استخدام OSRM API
        routes = []
        url = f"https://router.project-osrm.org/route/v1/driving/{start_lng},{start_lat};{end_lng},{end_lat}"
        url += "?overview=full&geometries=geojson&steps=true&alternatives=true"
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'GeoLegend/3.0'})
            
            if response.status_code == 200:
                route_data = response.json()
                if route_data.get('code') == 'Ok' and route_data.get('routes'):
                    for i, route in enumerate(route_data['routes']):
                        route_name = 'أسرع طريق' if i == 0 else f'طريق بديل {i}'
                        
                        routes.append({
                            'id': i,
                            'name': route_name,
                            'distance_km': round(route['distance'] / 1000, 2),
                            'duration_minutes': round(route['duration'] / 60, 1),
                            'geometry': route.get('geometry'),
                            'source': 'osrm'
                        })
        except requests.exceptions.Timeout:
            app.logger.warning('OSRM API timeout, using fallback')
        except Exception as e:
            app.logger.error(f'OSRM API error: {str(e)}')
        
        # Fallback إذا فشل OSRM
        if not routes:
            distance = haversine_distance(start_lat, start_lng, end_lat, end_lng)
            duration = (distance / 50) * 60  # افتراض سرعة 50 كم/ساعة
            
            routes.append({
                'id': 0,
                'name': 'المسار المباشر',
                'distance_km': round(distance, 2),
                'duration_minutes': round(duration, 1),
                'geometry': None,
                'source': 'local'
            })
        
        return jsonify({'status': 'success', 'routes': routes})
        
    except Exception as e:
        app.logger.error(f'Error in get_public_route: {str(e)}')
        return jsonify({'error': 'حدث خطأ في حساب المسار'}), 500

# ====== API المصادقة ======
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    """تسجيل مستخدم جديد"""
    try:
        # طباعة معلومات الطلب للتشخيص
        app.logger.info(f'📝 Register request from IP: {request.remote_addr}')
        app.logger.info(f'📝 Content-Type: {request.headers.get("Content-Type")}')
        
        # التحقق من وجود بيانات
        if not request.is_json:
            app.logger.warning('Register request not JSON')
            return jsonify({'error': 'يجب إرسال البيانات بتنسيق JSON'}), 400
        
        data = request.get_json()
        if not data:
            app.logger.warning('Register request with empty data')
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        # استخراج البيانات
        name = sanitize_input(data.get('name', ''))
        email = sanitize_email(data.get('email', ''))
        password = data.get('password', '')
        
        app.logger.info(f'📝 Register attempt - Email: {email}, Name: {name}')
        
        # التحقق من صحة البيانات
        errors = []
        if not name or len(name) < 2:
            errors.append('الاسم يجب أن يكون حرفين على الأقل')
        if not email or not is_valid_email(email):
            errors.append('البريد الإلكتروني غير صالح')
        if not password or len(password) < 6:
            errors.append('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
        
        if errors:
            app.logger.warning(f'Register validation failed: {errors}')
            return jsonify({'error': '. '.join(errors)}), 400
        
        # التحقق من عدم وجود البريد
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            app.logger.warning(f'Register failed - email already exists: {email}')
            return jsonify({'error': 'البريد الإلكتروني مستخدم بالفعل'}), 409
        
        # إنشاء المستخدم
        try:
            user = User(
                name=name,
                email=email,
                password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(user)
            db.session.commit()
            app.logger.info(f'✅ User created successfully: {email}')
        except Exception as db_err:
            db.session.rollback()
            app.logger.error(f'Database error during user creation: {str(db_err)}')
            return jsonify({'error': 'خطأ في قاعدة البيانات. الرجاء المحاولة لاحقاً'}), 500
        
        # إنشاء التوكنات
        try:
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims={'name': user.name, 'email': user.email}
            )
            refresh_token = create_refresh_token(identity=str(user.id))
            app.logger.info(f'✅ Tokens created for user: {email}')
        except Exception as token_err:
            app.logger.error(f'Token creation error: {str(token_err)}')
            return jsonify({'error': 'خطأ في إنشاء جلسة الدخول'}), 500
        
        return jsonify({
            'status': 'success',
            'message': 'تم إنشاء الحساب بنجاح',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Register error: {str(e)}', exc_info=True)
        return jsonify({'error': 'حدث خطأ أثناء التسجيل. الرجاء المحاولة لاحقاً'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")
def login():
    """تسجيل الدخول"""
    try:
        ip = request.remote_addr
        allowed, remaining = brute_force.check_ip(ip)
        if not allowed:
            return jsonify({
                'error': f'محاولات كثيرة جداً. حاول مرة أخرى بعد {remaining} ثانية',
                'retry_after': remaining
            }), 429
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        email = sanitize_email(data.get('email', ''))
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'جميع الحقول مطلوبة'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401
        
        if not user.password_hash or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'الحساب معطل. الرجاء التواصل مع الدعم'}), 403
        
        # تحديث آخر تسجيل دخول
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        
        # إنشاء التوكنات
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'name': user.name, 'email': user.email}
        )
        refresh_token = create_refresh_token(identity=str(user.id))
        
        # إعادة تعيين محاولات الـ brute force
        brute_force.reset_ip(ip)
        
        app.logger.info(f'✅ User logged in: {email}')
        
        return jsonify({
            'status': 'success',
            'message': 'تم تسجيل الدخول بنجاح',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تسجيل الدخول'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))
        
        if not user or not user.is_active:
            return jsonify({'error': 'المستخدم غير موجود أو معطل'}), 401
        
        access_token = create_access_token(
            identity=current_user_id,
            additional_claims={'name': user.name, 'email': user.email}
        )
        
        return jsonify({'access_token': access_token})
        
    except Exception as e:
        app.logger.error(f'Token refresh error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تحديث التوكن'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        user_id = int(get_jwt_identity())
        
        now = datetime.now(timezone.utc)
        token_block = TokenBlocklist(
            jti=jti,
            token_type='access',
            user_id=user_id,
            created_at=now,
            expires_at=now + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        )
        db.session.add(token_block)
        db.session.commit()
        
        # حذف من cache
        cache_key = f'blocked_token_{jti}'
        cache.delete(cache_key)
        
        app.logger.info(f'✅ User {user_id} logged out')
        
        return jsonify({
            'status': 'success',
            'message': 'تم تسجيل الخروج بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Logout error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تسجيل الخروج'}), 500

# ====== API الموقع ======
@app.route('/api/location/update', methods=['POST'])
@jwt_required()
@limiter.limit("300 per minute")
@validate_coordinates
def update_location():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        lat = data.get('lat')
        lng = data.get('lng')
        speed_raw = data.get('speed')
        heading_raw = data.get('heading')
        accuracy_raw = data.get('accuracy')
        battery_level_raw = data.get('battery_level', 100)
        device_type = sanitize_input(data.get('device_type', 'unknown'), 50)
        
        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        # تعيين القيم الافتراضية وتنظيفها
        try:
            lat = round(float(lat), 6)
            lng = round(float(lng), 6)
            speed = float(speed_raw) if speed_raw is not None else 0.0
            heading = float(heading_raw) if heading_raw is not None else 0.0
            accuracy = float(accuracy_raw) if accuracy_raw is not None else 0.0
            battery_level = float(battery_level_raw) if battery_level_raw is not None else 100.0
        except (ValueError, TypeError):
            return jsonify({'error': 'قيم غير صالحة'}), 400
        
        # التحقق من القيم
        speed = min(max(speed, 0.0), 300.0)
        heading = min(max(heading, 0.0), 359.0) % 360.0
        accuracy = min(max(accuracy, 0.0), 500.0)
        battery_level = min(max(battery_level, 0.0), 100.0)
        
        now = datetime.now(timezone.utc)
        
        # تحديث أو إنشاء الموقع الحالي
        current_loc = CurrentLocation.query.filter_by(user_id=user_id).first()
        if current_loc:
            current_loc.lat = lat
            current_loc.lng = lng
            current_loc.speed = speed
            current_loc.heading = heading
            current_loc.accuracy = accuracy
            current_loc.battery_level = battery_level
            current_loc.device_type = device_type
            current_loc.updated_at = now
        else:
            current_loc = CurrentLocation(
                user_id=user_id,
                lat=lat,
                lng=lng,
                speed=speed,
                heading=heading,
                accuracy=accuracy,
                battery_level=battery_level,
                device_type=device_type,
                updated_at=now
            )
            db.session.add(current_loc)
        
        # تخزين في cache
        cache_key = f'user_location_{user_id}'
        cache.set(cache_key, current_loc.to_dict(), timeout=30)
        
        # حفظ في تاريخ المواقع (كل 30 ثانية أو 10 أمتار)
        should_save = True
        last_history = cache.get(f'last_history_{user_id}')
        if last_history is None:
            last_history = LocationHistory.query.filter_by(user_id=user_id)\
                .order_by(LocationHistory.timestamp.desc()).first()
            cache.set(f'last_history_{user_id}', last_history, timeout=30)
        
        if last_history:
            last_time = make_aware(last_history.timestamp)
            time_diff = (now - last_time).total_seconds()
            distance = haversine_distance(last_history.lat, last_history.lng, lat, lng)
            should_save = time_diff >= 30 or distance > 0.01
        
        if should_save:
            history = LocationHistory(
                user_id=user_id,
                lat=lat,
                lng=lng,
                speed=speed,
                heading=heading,
                accuracy=accuracy,
                battery_level=battery_level,
                timestamp=now
            )
            db.session.add(history)
            cache.set(f'last_history_{user_id}', history, timeout=30)
        
        # تحديث الرحلة النشطة
        active_trip = Trip.query.filter_by(user_id=user_id, is_active=True).first()
        if active_trip:
            recent_locations = LocationHistory.query.filter_by(user_id=user_id)\
                .filter(LocationHistory.timestamp >= active_trip.started_at)\
                .order_by(LocationHistory.timestamp.asc()).all()
            
            if len(recent_locations) >= 2:
                total_dist = 0.0
                speeds_list = []
                
                for i in range(1, len(recent_locations)):
                    dist = haversine_distance(
                        recent_locations[i-1].lat, recent_locations[i-1].lng,
                        recent_locations[i].lat, recent_locations[i].lng
                    )
                    total_dist += dist
                    if recent_locations[i].speed > 0:
                        speeds_list.append(recent_locations[i].speed)
                
                active_trip.total_distance = round(total_dist, 2)
                active_trip.max_speed = round(max(speeds_list), 1) if speeds_list else 0
                active_trip.avg_speed = round(sum(speeds_list) / len(speeds_list), 1) if speeds_list else 0
                active_trip.end_lat = lat
                active_trip.end_lng = lng
                
                started = make_aware(active_trip.started_at)
                active_trip.duration_minutes = round((now - started).total_seconds() / 60, 1)
        
        # كشف أحداث الأسوار الجغرافية
        geofence_events = detect_geofence_events(user_id, lat, lng)
        
        # تحديث الإحصائيات اليومية
        today = datetime.now(timezone.utc).date()
        snapshot = AnalyticsSnapshot.query.filter_by(user_id=user_id, date=today).first()
        if snapshot:
            snapshot.locations_count += 1
        else:
            db.session.add(AnalyticsSnapshot(
                user_id=user_id,
                date=today,
                locations_count=1
            ))
        
        # تحليل نمط الحركة واكتشاف الحوادث (كل 5 دقائق فقط)
        last_analysis = cache.get(f'last_analysis_{user_id}')
        if not last_analysis or (now - last_analysis).total_seconds() > 300:
            recent_locations_for_analysis = LocationHistory.query.filter_by(user_id=user_id)\
                .order_by(LocationHistory.timestamp.desc()).limit(20).all()
            
            if len(recent_locations_for_analysis) >= 5:
                locs_dict = [
                    {
                        'lat': loc.lat,
                        'lng': loc.lng,
                        'speed': loc.speed,
                        'timestamp': make_aware(loc.timestamp)
                    } for loc in reversed(recent_locations_for_analysis)
                ]
                analysis = analyze_movement(locs_dict)
                
                if analysis.get('accident_detected'):
                    five_min_ago = now - timedelta(minutes=5)
                    recent_alert = Notification.query.filter_by(
                        user_id=user_id,
                        type='accident_alert'
                    ).filter(Notification.created_at >= five_min_ago).first()
                    
                    if not recent_alert:
                        create_notification(
                            user_id,
                            '🚨 تنبيه حادث محتمل',
                            'تم اكتشاف توقف مفاجئ. هل أنت بخير؟',
                            'accident_alert'
                        )
                        
                        user = User.query.get(user_id)
                        if user:
                            notify_family_members(
                                user_id,
                                f'⚠️ تنبيه: توقف مفاجئ لـ {user.name}',
                                limit_per_minute=True
                            )
            
            cache.set(f'last_analysis_{user_id}', now, timeout=300)
        
        db.session.commit()
        
        # تجهيز بيانات البث
        user = cache.get(f'user_{user_id}')
        if not user:
            user = User.query.get(user_id)
            cache.set(f'user_{user_id}', user, timeout=300)
        
        broadcast_data = {
            'user_id': user_id,
            'lat': lat,
            'lng': lng,
            'speed': speed,
            'heading': heading,
            'accuracy': accuracy,
            'battery_level': battery_level,
            'device_type': device_type,
            'name': user.name if user else 'مستخدم',
            'is_online': True,
            'seconds_ago': 0,
            'timestamp': now.isoformat()
        }
        
        # بث للمستخدم نفسه
        socketio.emit('location_update', broadcast_data, room=f'user_{user_id}')
        
        # بث للعائلة
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        for fam in families:
            socketio.emit(
                'family_location_update',
                broadcast_data,
                room=f'family_{fam.family_id}'
            )
        
        # بث لغرف المشاركة النشطة
        active_rooms = Room.query.filter_by(creator_id=user_id, is_active=True).all()
        for room in active_rooms:
            if not room.is_expired():
                socketio.emit(
                    'location_update',
                    broadcast_data,
                    room=f'share_{room.room_id}'
                )
        
        return jsonify({
            'status': 'success',
            'message': 'تم تحديث الموقع بنجاح',
            'geofence_events': geofence_events if geofence_events else None,
            'save_to_history': should_save
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Location update error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تحديث الموقع'}), 500

@app.route('/api/location/current', methods=['GET'])
@jwt_required()
@cache.cached(timeout=5, query_string=True)
def get_my_current_location():
    try:
        user_id = int(get_jwt_identity())
        location = CurrentLocation.query.filter_by(user_id=user_id).first()
        
        if not location:
            return jsonify({'status': 'no_data', 'location': None})
        
        updated_at = make_aware(location.updated_at)
        now = datetime.now(timezone.utc)
        time_diff = (now - updated_at).total_seconds()
        
        status = 'offline' if time_diff > 60 else 'online'
        
        return jsonify({
            'status': status,
            'location': location.to_dict(),
            'last_update_seconds_ago': int(time_diff),
            'is_stale': time_diff > 300
        })
        
    except Exception as e:
        app.logger.error(f'Get current location error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الملاحة ======
@app.route('/api/navigation/route', methods=['POST'])
@jwt_required()
@cache.cached(timeout=300, query_string=True)
def get_navigation_route():
    try:
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        start_lat = data.get('start_lat')
        start_lng = data.get('start_lng')
        end_lat = data.get('end_lat')
        end_lng = data.get('end_lng')
        mode = sanitize_input(data.get('mode', 'driving'), 20)
        
        if None in [start_lat, start_lng, end_lat, end_lng]:
            return jsonify({'error': 'جميع الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(start_lat, start_lng):
            return jsonify({'error': 'إحداثيات البداية غير صالحة'}), 400
        
        if not is_valid_coordinates(end_lat, end_lng):
            return jsonify({'error': 'إحداثيات النهاية غير صالحة'}), 400
        
        profile_map = {'driving': 'driving', 'walking': 'walking', 'cycling': 'cycling'}
        profile = profile_map.get(mode, 'driving')
        
        routes = []
        url = f"https://router.project-osrm.org/route/v1/{profile}/{start_lng},{start_lat};{end_lng},{end_lat}"
        url += "?overview=full&geometries=geojson&steps=true&alternatives=true"
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'GeoLegend/3.0'})
            
            if response.status_code == 200:
                route_data = response.json()
                if route_data.get('code') == 'Ok' and route_data.get('routes'):
                    for i, route in enumerate(route_data['routes']):
                        route_name = 'أسرع طريق' if i == 0 else f'طريق بديل {i}'
                        
                        routes.append({
                            'id': i,
                            'name': route_name,
                            'distance_km': round(route['distance'] / 1000, 2),
                            'duration_minutes': round(route['duration'] / 60, 1),
                            'geometry': route.get('geometry'),
                            'source': 'osrm'
                        })
        except Exception as e:
            app.logger.error(f'OSRM API error: {str(e)}')
        
        if not routes:
            distance = haversine_distance(start_lat, start_lng, end_lat, end_lng)
            speed = 5 if mode == 'walking' else (15 if mode == 'cycling' else 50)
            duration = (distance / speed) * 60
            
            routes.append({
                'id': 0,
                'name': 'المسار المباشر',
                'distance_km': round(distance, 2),
                'duration_minutes': round(duration, 1),
                'geometry': None,
                'source': 'local'
            })
        
        return jsonify({'status': 'success', 'routes': routes})
        
    except Exception as e:
        app.logger.error(f'Navigation error: {str(e)}')
        return jsonify({'error': 'حدث خطأ في حساب المسار'}), 500

# ====== API الأصدقاء ======
@app.route('/api/friends/send-request', methods=['POST'])
@jwt_required()
@limiter.limit("30 per minute")
def send_friend_request():
    try:
        requester_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        email = sanitize_email(data.get('email', ''))
        
        if not email:
            return jsonify({'error': 'البريد الإلكتروني مطلوب'}), 400
        
        addressee = User.query.filter_by(email=email).first()
        if not addressee:
            return jsonify({'error': 'المستخدم غير موجود'}), 404
        
        if addressee.id == requester_id:
            return jsonify({'error': 'لا يمكنك إرسال طلب لنفسك'}), 400
        
        # التحقق من وجود طلب سابق
        existing = Friendship.query.filter(
            ((Friendship.requester_id == requester_id) & (Friendship.addressee_id == addressee.id)) |
            ((Friendship.requester_id == addressee.id) & (Friendship.addressee_id == requester_id))
        ).first()
        
        if existing:
            if existing.status == 'pending':
                return jsonify({'error': 'يوجد طلب معلق بالفعل'}), 409
            elif existing.status == 'accepted':
                return jsonify({'error': 'أنتما أصدقاء بالفعل'}), 409
        
        friendship = Friendship(
            requester_id=requester_id,
            addressee_id=addressee.id,
            status='pending'
        )
        db.session.add(friendship)
        db.session.commit()
        
        requester = User.query.get(requester_id)
        create_notification(
            addressee.id,
            '👥 طلب صداقة',
            f'طلب صداقة من {requester.name}',
            'friend_request',
            {'requester_id': requester_id, 'requester_name': requester.name}
        )
        
        return jsonify({'status': 'success', 'message': 'تم إرسال طلب الصداقة'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Send friend request error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/requests', methods=['GET'])
@jwt_required()
def get_friend_requests():
    try:
        user_id = int(get_jwt_identity())
        
        requests = Friendship.query.filter_by(
            addressee_id=user_id,
            status='pending'
        ).all()
        
        result = []
        for r in requests:
            requester = User.query.get(r.requester_id)
            if requester:
                result.append({
                    'id': r.id,
                    'requester_id': r.requester_id,
                    'requester_name': requester.name,
                    'requester_email': requester.email,
                    'created_at': r.created_at.isoformat() if r.created_at else None
                })
        
        return jsonify({'status': 'success', 'requests': result})
        
    except Exception as e:
        app.logger.error(f'Get friend requests error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/respond/<int:request_id>', methods=['POST'])
@jwt_required()
def respond_friend_request(request_id):
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        action = sanitize_input(data.get('action', 'accept'), 20)
        
        friendship = Friendship.query.get(request_id)
        if not friendship:
            return jsonify({'error': 'الطلب غير موجود'}), 404
        
        if friendship.addressee_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        if action not in ['accept', 'reject']:
            return jsonify({'error': 'إجراء غير صالح'}), 400
        
        if action == 'accept':
            friendship.status = 'accepted'
            message = 'تم قبول طلب الصداقة'
            
            requester = User.query.get(friendship.requester_id)
            if requester:
                create_notification(
                    friendship.requester_id,
                    '👥 صداقة جديدة',
                    f'قبل {User.query.get(user_id).name} طلب صداقتك',
                    'friend_accepted'
                )
        else:
            friendship.status = 'rejected'
            message = 'تم رفض طلب الصداقة'
        
        friendship.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Respond friend request error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/list', methods=['GET'])
@jwt_required()
def get_friends_list():
    try:
        user_id = int(get_jwt_identity())
        
        friendships = Friendship.query.filter(
            ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)),
            Friendship.status == 'accepted'
        ).all()
        
        friends = []
        for f in friendships:
            friend_id = f.addressee_id if f.requester_id == user_id else f.requester_id
            friend = User.query.get(friend_id)
            
            if friend:
                location = CurrentLocation.query.filter_by(user_id=friend_id).first()
                is_online = False
                location_data = None
                
                if location:
                    updated_at = make_aware(location.updated_at)
                    now = datetime.now(timezone.utc)
                    is_online = (now - updated_at).total_seconds() < 60
                    location_data = location.to_dict()
                    location_data['is_online'] = is_online
                
                friends.append({
                    'friendship_id': f.id,
                    'friend': friend.to_dict(),
                    'location': location_data,
                    'is_online': is_online
                })
        
        return jsonify({'status': 'success', 'friends': friends})
        
    except Exception as e:
        app.logger.error(f'Get friends list error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/remove/<int:friendship_id>', methods=['DELETE'])
@jwt_required()
def remove_friend(friendship_id):
    try:
        user_id = int(get_jwt_identity())
        
        friendship = Friendship.query.get(friendship_id)
        if not friendship:
            return jsonify({'error': 'الصداقة غير موجودة'}), 404
        
        if friendship.requester_id != user_id and friendship.addressee_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        db.session.delete(friendship)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'تم حذف الصديق'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Remove friend error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API العائلة ======
@app.route('/api/family/create', methods=['POST'])
@jwt_required()
def create_family():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        name = sanitize_input(data.get('name', 'عائلتي'), 100)
        
        if not name:
            return jsonify({'error': 'اسم العائلة مطلوب'}), 400
        
        # إنشاء رمز انضمام فريد
        import random
        import string
        
        join_code = ''
        for _ in range(10):
            join_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Family.query.filter_by(join_code=join_code).first():
                break
        
        family = Family(
            name=name,
            creator_id=user_id,
            join_code=join_code,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(family)
        db.session.flush()
        
        member = FamilyMember(
            family_id=family.id,
            user_id=user_id,
            role='admin',
            joined_at=datetime.now(timezone.utc)
        )
        db.session.add(member)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'family': {
                'id': family.id,
                'name': family.name,
                'join_code': family.join_code,
                'created_at': family.created_at.isoformat() if family.created_at else None
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Create family error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/family/join', methods=['POST'])
@jwt_required()
def join_family():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        join_code = sanitize_input(data.get('code', ''), 10).strip().upper()
        
        if not join_code:
            return jsonify({'error': 'رمز الانضمام مطلوب'}), 400
        
        family = Family.query.filter_by(join_code=join_code, is_active=True).first()
        if not family:
            return jsonify({'error': 'رمز الانضمام غير صحيح'}), 404
        
        existing = FamilyMember.query.filter_by(family_id=family.id, user_id=user_id).first()
        if existing:
            return jsonify({'error': 'أنت بالفعل عضو في هذه العائلة'}), 409
        
        member = FamilyMember(
            family_id=family.id,
            user_id=user_id,
            role='member',
            joined_at=datetime.now(timezone.utc)
        )
        db.session.add(member)
        db.session.commit()
        
        user = User.query.get(user_id)
        create_notification(
            family.creator_id,
            '👨‍👩‍👧‍👦 عضو جديد',
            f'انضم {user.name} إلى العائلة',
            'family'
        )
        
        return jsonify({'status': 'success', 'message': 'تم الانضمام إلى العائلة'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Join family error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/family/list', methods=['GET'])
@jwt_required()
def list_families():
    try:
        user_id = int(get_jwt_identity())
        
        memberships = FamilyMember.query.filter_by(user_id=user_id).all()
        
        families = []
        for m in memberships:
            family = Family.query.get(m.family_id)
            if family:
                members = FamilyMember.query.filter_by(family_id=family.id).all()
                members_list = []
                
                for mem in members:
                    user = User.query.get(mem.user_id)
                    location = CurrentLocation.query.filter_by(user_id=mem.user_id).first()
                    
                    is_online = False
                    location_data = None
                    if location:
                        updated_at = make_aware(location.updated_at)
                        now = datetime.now(timezone.utc)
                        is_online = (now - updated_at).total_seconds() < 60
                        location_data = location.to_dict()
                        location_data['is_online'] = is_online
                    
                    if user:
                        members_list.append({
                            'user_id': user.id,
                            'user': user.to_dict(),
                            'role': mem.role,
                            'location': location_data,
                            'is_online': is_online,
                            'joined_at': mem.joined_at.isoformat() if mem.joined_at else None
                        })
                
                families.append({
                    'id': family.id,
                    'name': family.name,
                    'join_code': family.join_code,
                    'my_role': m.role,
                    'member_count': len(members_list),
                    'members': members_list,
                    'created_at': family.created_at.isoformat() if family.created_at else None
                })
        
        return jsonify({'status': 'success', 'families': families})
        
    except Exception as e:
        app.logger.error(f'List families error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API المشاركة ======
@app.route('/api/share/create', methods=['POST'])
@jwt_required()
@limiter.limit("20 per minute")
def create_share():
    try:
        user_id = int(get_jwt_identity())
        
        data = request.get_json() if request.is_json else {}
        minutes = data.get('minutes')
        is_private = data.get('is_private', False)
        share_pin = data.get('pin', None) if is_private else None
        
        expiry = None
        if minutes:
            try:
                minutes_int = int(minutes)
                if 1 <= minutes_int <= 1440:
                    expiry = datetime.now(timezone.utc) + timedelta(minutes=minutes_int)
            except (ValueError, TypeError):
                pass
        
        room = Room(
            creator_id=user_id,
            participants=str(user_id),
            expiry=expiry,
            is_private=is_private,
            share_pin=share_pin,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(room)
        db.session.commit()
        
        # بث الموقع الحالي إلى غرفة المشاركة
        current_location = CurrentLocation.query.filter_by(user_id=user_id).first()
        user = User.query.get(user_id)
        
        if current_location and user:
            updated_at = make_aware(current_location.updated_at)
            now = datetime.now(timezone.utc)
            seconds_ago = int((now - updated_at).total_seconds()) if updated_at else 0
            is_online = seconds_ago < 60
            
            socketio.emit('location_update', {
                'user_id': user_id,
                'lat': current_location.lat,
                'lng': current_location.lng,
                'speed': current_location.speed,
                'heading': current_location.heading,
                'accuracy': current_location.accuracy,
                'name': user.name,
                'is_online': is_online,
                'seconds_ago': seconds_ago,
                'timestamp': now.isoformat()
            }, room=f'share_{room.room_id}')
        
        # استخدام BASE_URL إذا كان متاحاً
        base_url = os.getenv('BASE_URL', request.host_url.rstrip('/'))
        full_url = f"{base_url}/share/{room.room_id}"
        
        return jsonify({
            'status': 'success',
            'room_id': room.room_id,
            'full_url': full_url,
            'expires_at': room.expiry.isoformat() if room.expiry else None
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Create share error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الرحلات ======
@app.route('/api/trips/start', methods=['POST'])
@jwt_required()
def start_trip():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        name = sanitize_input(data.get('name', 'رحلة جديدة'), 200)
        lat = data.get('lat')
        lng = data.get('lng')
        
        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        # إنهاء أي رحلة نشطة حالياً
        Trip.query.filter_by(user_id=user_id, is_active=True).update({
            'is_active': False,
            'ended_at': datetime.now(timezone.utc)
        })
        
        trip = Trip(
            user_id=user_id,
            name=name,
            start_lat=float(lat),
            start_lng=float(lng),
            started_at=datetime.now(timezone.utc),
            is_active=True
        )
        db.session.add(trip)
        db.session.commit()
        
        return jsonify({'status': 'success', 'trip': trip.to_dict()})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Start trip error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/trips/end', methods=['POST'])
@jwt_required()
def end_trip():
    try:
        user_id = int(get_jwt_identity())
        
        trip = Trip.query.filter_by(user_id=user_id, is_active=True).first()
        if not trip:
            return jsonify({'error': 'لا توجد رحلة نشطة'}), 404
        
        trip.is_active = False
        trip.ended_at = datetime.now(timezone.utc)
        
        started = make_aware(trip.started_at)
        ended = make_aware(trip.ended_at)
        trip.duration_minutes = round((ended - started).total_seconds() / 60, 1)
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'trip': trip.to_dict()})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'End trip error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/trips/list', methods=['GET'])
@jwt_required()
def list_trips():
    try:
        user_id = int(get_jwt_identity())
        
        trips = Trip.query.filter_by(user_id=user_id)\
            .order_by(Trip.started_at.desc())\
            .limit(50)\
            .all()
        
        return jsonify({'status': 'success', 'trips': [t.to_dict() for t in trips]})
        
    except Exception as e:
        app.logger.error(f'List trips error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الأسوار الجغرافية ======
@app.route('/api/geofences/create', methods=['POST'])
@jwt_required()
def create_geofence():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        name = sanitize_input(data.get('name', ''), 200)
        lat = data.get('lat')
        lng = data.get('lng')
        radius = data.get('radius', 100)
        
        if not name:
            return jsonify({'error': 'اسم السور مطلوب'}), 400
        
        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        radius = min(max(float(radius), 10), 5000)  # بين 10 و 5000 متر
        
        geofence = Geofence(
            user_id=user_id,
            name=name,
            lat=float(lat),
            lng=float(lng),
            radius=radius,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(geofence)
        db.session.commit()
        
        return jsonify({'status': 'success', 'geofence': geofence.to_dict()})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Create geofence error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/geofences/list', methods=['GET'])
@jwt_required()
def list_geofences():
    try:
        user_id = int(get_jwt_identity())
        
        geofences = Geofence.query.filter_by(user_id=user_id).all()
        
        return jsonify({'status': 'success', 'geofences': [g.to_dict() for g in geofences]})
        
    except Exception as e:
        app.logger.error(f'List geofences error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/geofences/delete/<int:geofence_id>', methods=['DELETE'])
@jwt_required()
def delete_geofence(geofence_id):
    try:
        user_id = int(get_jwt_identity())
        
        geofence = Geofence.query.get(geofence_id)
        if not geofence:
            return jsonify({'error': 'السور غير موجود'}), 404
        
        if geofence.user_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        db.session.delete(geofence)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'تم حذف السور'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Delete geofence error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الإشعارات ======
@app.route('/api/notifications/list', methods=['GET'])
@jwt_required()
def list_notifications():
    try:
        user_id = int(get_jwt_identity())
        
        notifs = Notification.query.filter_by(user_id=user_id)\
            .order_by(Notification.created_at.desc())\
            .limit(50)\
            .all()
        
        return jsonify({'status': 'success', 'notifications': [n.to_dict() for n in notifs]})
        
    except Exception as e:
        app.logger.error(f'List notifications error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/notifications/mark-read/<int:notification_id>', methods=['POST'])
@jwt_required()
def mark_notification_read(notification_id):
    try:
        user_id = int(get_jwt_identity())
        
        notif = Notification.query.get(notification_id)
        if not notif:
            return jsonify({'error': 'الإشعار غير موجود'}), 404
        
        if notif.user_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        notif.is_read = True
        notif.read_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'تم تعليم الإشعار كمقروء'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Mark notification read error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/notifications/unread-count', methods=['GET'])
@jwt_required()
def unread_notifications_count():
    try:
        user_id = int(get_jwt_identity())
        
        count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        
        return jsonify({'status': 'success', 'count': count})
        
    except Exception as e:
        app.logger.error(f'Unread count error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الإحصائيات والتحليلات ======
@app.route('/api/dashboard/stats', methods=['GET'])
@cache.cached(timeout=60)
def dashboard_stats():
    try:
        five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        
        online_users = CurrentLocation.query.filter(
            CurrentLocation.updated_at >= five_min_ago
        ).count()
        
        total_users = User.query.count()
        active_rooms = Room.query.filter_by(is_active=True).count()
        pending_sos = SOSAlert.query.filter_by(resolved=False).count()
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_users': total_users,
                'online_users': online_users,
                'active_rooms': active_rooms,
                'pending_sos': pending_sos,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        })
        
    except Exception as e:
        app.logger.error(f'Dashboard stats error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/analytics/daily', methods=['GET'])
@jwt_required()
def daily_analytics():
    try:
        user_id = int(get_jwt_identity())
        today = datetime.now(timezone.utc).date()
        
        snapshot = AnalyticsSnapshot.query.filter_by(user_id=user_id, date=today).first()
        
        if not snapshot:
            return jsonify({'status': 'success', 'analytics': {
                'total_distance': 0,
                'total_time_minutes': 0,
                'locations_count': 0,
                'trips_count': 0,
                'avg_speed': 0,
                'max_speed': 0,
                'sos_count': 0,
                'geofence_events_count': 0
            }})
        
        return jsonify({'status': 'success', 'analytics': snapshot.to_dict()})
        
    except Exception as e:
        app.logger.error(f'Daily analytics error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/analytics/movement-pattern', methods=['GET'])
@jwt_required()
def movement_pattern_analysis():
    try:
        user_id = int(get_jwt_identity())
        
        recent_locations = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc())\
            .limit(50)\
            .all()
        
        if len(recent_locations) < 5:
            return jsonify({'status': 'success', 'analysis': {
                'pattern': 'غير كاف',
                'confidence': 0,
                'message': 'لا توجد بيانات كافية للتحليل'
            }})
        
        locs_dict = [
            {
                'lat': loc.lat,
                'lng': loc.lng,
                'speed': loc.speed,
                'timestamp': make_aware(loc.timestamp)
            } for loc in reversed(recent_locations)
        ]
        
        analysis = analyze_movement(locs_dict)
        
        return jsonify({'status': 'success', 'analysis': analysis})
        
    except Exception as e:
        app.logger.error(f'Movement pattern error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API SOS ======
@app.route('/api/sos', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
@validate_coordinates
def send_sos():
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        lat = data.get('lat')
        lng = data.get('lng')
        message = sanitize_input(data.get('message', '🚨 طلب مساعدة عاجل'), 500)
        
        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        # التحقق من وجود SOS نشط خلال 5 دقائق
        five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_sos = SOSAlert.query.filter_by(
            user_id=user_id,
            resolved=False
        ).filter(SOSAlert.timestamp >= five_min_ago).first()
        
        if recent_sos:
            return jsonify({'error': 'لديك إشارة SOS نشطة حالياً'}), 429
        
        sos = SOSAlert(
            user_id=user_id,
            lat=float(lat),
            lng=float(lng),
            message=message,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(sos)
        db.session.commit()
        
        # تحديث الإحصائيات
        today = datetime.now(timezone.utc).date()
        snapshot = AnalyticsSnapshot.query.filter_by(user_id=user_id, date=today).first()
        if snapshot:
            snapshot.sos_count += 1
        else:
            db.session.add(AnalyticsSnapshot(
                user_id=user_id,
                date=today,
                sos_count=1
            ))
        db.session.commit()
        
        # جمع أفراد العائلة والأصدقاء للإشعار
        user = User.query.get(user_id)
        notified_users = set()
        
        # إشعار الأصدقاء
        friendships = Friendship.query.filter(
            ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)),
            Friendship.status == 'accepted'
        ).all()
        
        for f in friendships:
            friend_id = f.addressee_id if f.requester_id == user_id else f.requester_id
            if friend_id not in notified_users:
                notified_users.add(friend_id)
                create_notification(
                    friend_id,
                    '🚨 SOS!',
                    f'إشارة طوارئ من {user.name if user else "مستخدم"}',
                    'sos',
                    {'lat': float(lat), 'lng': float(lng), 'user_id': user_id}
                )
        
        # إشعار العائلة
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        for fam in families:
            family_members = FamilyMember.query.filter_by(family_id=fam.family_id).all()
            for member in family_members:
                if member.user_id != user_id and member.user_id not in notified_users:
                    notified_users.add(member.user_id)
                    create_notification(
                        member.user_id,
                        '🚨 SOS!',
                        f'إشارة طوارئ من {user.name if user else "مستخدم"} في العائلة',
                        'sos_family',
                        {'lat': float(lat), 'lng': float(lng), 'user_id': user_id}
                    )
        
        # بث SOS فقط للأصدقاء والعائلة (وليس لجميع المستخدمين)
        for uid in notified_users:
            socketio.emit('sos_alert', {
                'user_id': user_id,
                'lat': float(lat),
                'lng': float(lng),
                'message': message,
                'name': user.name if user else 'مستخدم',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room=f'user_{uid}')
        
        return jsonify({
            'status': 'success',
            'message': 'تم إرسال إشارة الطوارئ',
            'alert_id': sos.id,
            'notified_count': len(notified_users)
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'SOS error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/sos/resolve/<int:alert_id>', methods=['POST'])
@jwt_required()
def resolve_sos(alert_id):
    try:
        user_id = int(get_jwt_identity())
        
        sos = SOSAlert.query.get(alert_id)
        if not sos:
            return jsonify({'error': 'إشارة SOS غير موجودة'}), 404
        
        if sos.user_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        sos.resolved = True
        sos.resolved_at = datetime.now(timezone.utc)
        sos.responder_id = user_id
        db.session.commit()
        
        user = User.query.get(user_id)
        
        # إشعار الأصدقاء بأن SOS تم حلها
        friendships = Friendship.query.filter(
            ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)),
            Friendship.status == 'accepted'
        ).all()
        
        for f in friendships:
            friend_id = f.addressee_id if f.requester_id == user_id else f.requester_id
            create_notification(
                friend_id,
                '✅ تم حل SOS',
                f'تم حل إشارة الطوارئ لـ {user.name if user else "مستخدم"}',
                'sos_resolved'
            )
        
        return jsonify({'status': 'success', 'message': 'تم حل إشارة SOS'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Resolve SOS error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== خدمة الملفات ======
@app.route('/manifest.json')
@cache.cached(timeout=3600)
def manifest():
    return jsonify({
        "name": "GeoLegend Ultimate",
        "short_name": "GeoLegend",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a1a",
        "theme_color": "#00ffff",
        "description": "أقوى نظام تتبع مباشر ثلاثي الأبعاد",
        "icons": [
            {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    })

@app.route('/sw.js')
def service_worker():
    sw_code = '''const CACHE_NAME = 'geolegend-v8';
const urlsToCache = ['/', '/manifest.json'];

self.addEventListener('install', (event) => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache))
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        Promise.all([
            caches.keys().then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName.startsWith('geolegend-') && cacheName !== CACHE_NAME) {
                            return caches.delete(cacheName);
                        }
                    })
                );
            }),
            self.clients.claim()
        ])
    );
});

self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;
    
    const url = new URL(event.request.url);
    
    if (url.pathname.startsWith('/api/')) return;
    if (url.pathname.startsWith('/socket.io/')) return;
    if (url.origin !== location.origin) return;
    
    event.respondWith(
        fetch(event.request).then((response) => {
            if (!response || response.status !== 200) return response;
            
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
                cache.put(event.request, responseClone);
            });
            
            return response;
        }).catch(() => {
            return caches.match(event.request).then((cachedResponse) => {
                if (cachedResponse) return cachedResponse;
                return caches.match('/');
            });
        })
    );
});'''
    
    response = app.response_class(response=sw_code, status=200, mimetype='application/javascript')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/icons', 'icon-192.png')

@app.route('/static/<path:filename>')
def custom_static(filename):
    try:
        response = send_file(f'static/{filename}')
        
        if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp')):
            response.headers['Cache-Control'] = 'public, max-age=31536000'
        elif filename.endswith(('.css', '.js')):
            response.headers['Cache-Control'] = 'public, max-age=604800'
        else:
            response.headers['Cache-Control'] = 'public, max-age=86400'
        
        return response
    except FileNotFoundError:
        app.logger.warning(f'Static file not found: {filename}')
        return jsonify({'error': 'الملف غير موجود'}), 404

# ====== SocketIO Events ======
@socketio.on('connect')
def handle_connect():
    try:
        token = request.args.get('token')
        if token:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            user_id = decoded.get('sub')
            if user_id:
                join_room(f'user_{user_id}')
                app.logger.info(f'✅ User {user_id} connected via SocketIO')
                emit('connected', {'status': 'success', 'user_id': user_id})
    except Exception as e:
        app.logger.warning(f'SocketIO connection error: {str(e)}')

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.debug('Client disconnected')

@socketio.on('join_tracking')
def handle_join_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        emit('joined_tracking', {'status': 'success', 'user_id': user_id})

@socketio.on('leave_tracking')
def handle_leave_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        leave_room(f'user_{user_id}')
        emit('left_tracking', {'status': 'success', 'user_id': user_id})

@socketio.on('join_family')
def handle_join_family(data):
    family_id = data.get('family_id')
    if family_id:
        join_room(f'family_{family_id}')
        emit('joined_family', {'status': 'success', 'family_id': family_id})

@socketio.on('leave_family')
def handle_leave_family(data):
    family_id = data.get('family_id')
    if family_id:
        leave_room(f'family_{family_id}')
        emit('left_family', {'status': 'success', 'family_id': family_id})

@socketio.on('join_group')
def handle_join_group(data):
    group_id = data.get('group_id')
    if group_id:
        join_room(f'group_{group_id}')
        emit('joined_group', {'status': 'success', 'group_id': group_id})

@socketio.on('join_share_room')
def handle_join_share_room(data):
    room_id = data.get('room_id')
    app.logger.info(f'🔗 join_share_room called with room_id: {room_id}')
    
    if room_id:
        join_room(f'share_{room_id}')
        app.logger.info(f'🔗 Client joined share room: {room_id}')
        emit('joined_share_room', {'status': 'success', 'room_id': room_id})
        
        # إرسال آخر موقع متاح للمستخدم الجديد
        room = Room.query.filter_by(room_id=room_id, is_active=True).first()
        if room:
            current_location = CurrentLocation.query.filter_by(user_id=room.creator_id).first()
            user = User.query.get(room.creator_id)
            
            if current_location and user:
                now = datetime.now(timezone.utc)
                updated_at = make_aware(current_location.updated_at)
                seconds_ago = int((now - updated_at).total_seconds()) if updated_at else 999
                is_online = seconds_ago < 60
                
                emit('location_update', {
                    'user_id': room.creator_id,
                    'lat': current_location.lat,
                    'lng': current_location.lng,
                    'speed': current_location.speed,
                    'heading': current_location.heading,
                    'accuracy': current_location.accuracy,
                    'name': user.name,
                    'is_online': is_online,
                    'seconds_ago': seconds_ago,
                    'timestamp': current_location.updated_at.isoformat() if current_location.updated_at else None
                }, room=f'share_{room_id}')
                
                app.logger.info(f'✅ Sent initial location to share room {room_id}')

@socketio.on('leave_share_room')
def handle_leave_share_room(data):
    room_id = data.get('room_id')
    if room_id:
        leave_room(f'share_{room_id}')
        emit('left_share_room', {'status': 'success', 'room_id': room_id})

@socketio.on('ping_server')
def handle_ping():
    emit('pong_server', {'timestamp': datetime.now(timezone.utc).isoformat()})

# ====== معالجة الأخطاء ======
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'طلب غير صالح'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'غير مصرح. الرجاء تسجيل الدخول'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'غير مسموح'}), 403

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'المسار غير موجود'}), 404
    return render_template('index.html'), 200

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'حجم الملف كبير جداً'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'تجاوزت الحد المسموح من الطلبات. حاول لاحقاً'}), 429

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'خطأ داخلي في الخادم'}), 500

# ====== إنشاء قاعدة البيانات ======
def init_database():
    with app.app_context():
        try:
            db.create_all()
            app.logger.info('✅ Database tables created successfully')
            print('✅ Database tables created successfully')
        except Exception as e:
            app.logger.error(f'Database creation error: {str(e)}')
            print(f'❌ Database creation error: {str(e)}')

# ====== نقطة البداية ======
if __name__ == '__main__':
    init_database()
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     🌟🌟🌟   GeoLegend Ultimate 3D System   🌟🌟🌟              ║
    ║                                                                  ║
    ║  🚀 Server: http://{host}:{port}                                ║
    ║  📍 Default Location: سوق باب اليمن - صنعاء                       ║
    ║  🗺️ Default Map: Satellite + أسماء الأماكن                       ║
    ║                                                                  ║
    ║  ✅ Tracking      ✅ Share        ✅ Navigate                     ║
    ║  ✅ Guest Mode    ✅ SOS          ✅ Friends                      ║
    ║  ✅ Family        ✅ Trips        ✅ Geofence                     ║
    ║  ✅ Notifications ✅ Analytics    ✅ Real-time 3D                 ║
    ║                                                                  ║
    ║  🔒 Security: JWT | Rate Limit | CORS | Brute Force Protection   ║
    ║  📊 Database: {database_url.split('://')[0]}                          ║
    ║  🔄 Socket.IO: Real-time communication                           ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # التشغيل مع eventlet أو threading
    try:
        if GUNICORN:
            print("✅ Running under Gunicorn, skipping socketio.run()")
        else:
            socketio.run(app, debug=debug, host=host, port=port, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"❌ Failed to start server: {str(e)}")
        socketio.run(app, debug=debug, host=host, port=port, allow_unsafe_werkzeug=True)

# ====== للاستخدام مع Gunicorn ======
application = app
