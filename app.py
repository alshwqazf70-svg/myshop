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
from flask_talisman import Talisman
from flask_caching import Cache
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from math import radians, cos, sin, asin, sqrt, atan2, degrees
import os
import re
import uuid
import json
import requests
import statistics
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import time
import secrets
import sys

# ====== إعدادات التطبيق ======
app = Flask(__name__)

# تحسين الأمان - استخدام مفاتيح عشوائية قوية
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(basedir, "geo_legend.db")}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# إعدادات JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

# إعدادات الجلسة
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# تهيئة الملحقات
CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
jwt = JWTManager(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False
)

# إضافة التخزين المؤقت
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# إعداد سجل الأحداث (Logging)
if not app.debug and not app.testing:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler(
        'logs/geolegend.log',
        maxBytes=10240 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    # إضافة معالج الأخطاء الحرجة
    error_handler = RotatingFileHandler(
        'logs/errors.log',
        maxBytes=10240 * 1024,
        backupCount=5
    )
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    error_handler.setLevel(logging.ERROR)
    app.logger.addHandler(error_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('GeoLegend Ultimate startup')

# وقت بدء التشغيل للمراقبة
app.start_time = time.time()

# ====== طباعة معلومات التشخيص ======
print(f"Python version: {sys.version}")
print(f"Starting GeoLegend Ultimate...")
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# ====== حماية ضد هجمات القوة العمياء (Brute Force) ======
class BruteForceProtection:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.max_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
        self.window = int(os.getenv('LOGIN_WINDOW_SECONDS', 300))  # 5 دقائق
    
    def check_ip(self, ip):
        """التحقق من عدم تجاوز الحد المسموح"""
        now = datetime.now(timezone.utc)
        self.attempts[ip] = [
            t for t in self.attempts[ip] 
            if (now - t).total_seconds() < self.window
        ]
        
        if len(self.attempts[ip]) >= self.max_attempts:
            remaining_time = int(self.window - (now - self.attempts[ip][0]).total_seconds())
            app.logger.warning(f'Brute force attempt blocked for IP: {ip}')
            return False, remaining_time
        
        self.attempts[ip].append(now)
        return True, 0
    
    def reset_ip(self, ip):
        """إعادة تعيين عداد المحاولات"""
        self.attempts[ip] = []

brute_force = BruteForceProtection()

# ====== دوال المساعدة ======
def haversine(lat1, lng1, lat2, lng2):
    """حساب المسافة بين نقطتين بالكيلومتر بدقة محسنة"""
    try:
        # التحقق من صحة المدخلات
        if not all(isinstance(x, (int, float)) for x in [lat1, lng1, lat2, lng2]):
            return 0.0
        
        lat1, lng1, lat2, lng2 = map(radians, [float(lat1), float(lng1), float(lat2), float(lng2)])
        dlat, dlng = lat2 - lat1, lng2 - lng1
        
        # استخدام معادلة haversine المحسنة
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlng/2)**2
        
        # ضمان عدم تجاوز القيمة عن 1 بسبب أخطاء التقريب
        a = min(1.0, max(0.0, a))
        c = 2 * asin(sqrt(a))
        
        return 6371 * c  # نصف قطر الأرض بالكيلومتر
    except Exception as e:
        app.logger.error(f'Error in haversine: {str(e)}')
        return 0.0

def bearing(lat1, lng1, lat2, lng2):
    """حساب الاتجاه بين نقطتين"""
    try:
        lat1, lng1, lat2, lng2 = map(radians, [float(lat1), float(lng1), float(lat2), float(lng2)])
        dlng = lng2 - lng1
        x = sin(dlng) * cos(lat2)
        y = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dlng)
        brng = atan2(x, y)
        return (degrees(brng) + 360) % 360
    except Exception as e:
        app.logger.error(f'Error in bearing: {str(e)}')
        return 0.0

def calculate_speed(pos1, pos2):
    """حساب السرعة من موقعين"""
    if not pos1 or not pos2:
        return 0
    
    try:
        dist = haversine(pos1['lat'], pos1['lng'], pos2['lat'], pos2['lng'])
        
        # التحقق من وجود timestamp
        if hasattr(pos1['timestamp'], 'timestamp'):
            time1 = pos1['timestamp'].timestamp()
        else:
            time1 = pos1['timestamp']
        
        if hasattr(pos2['timestamp'], 'timestamp'):
            time2 = pos2['timestamp'].timestamp()
        else:
            time2 = pos2['timestamp']
        
        diff = abs(time2 - time1)
        return (dist / diff) * 3600 if diff > 0 else 0
    except Exception as e:
        app.logger.error(f'Error in calculate_speed: {str(e)}')
        return 0

def analyze_movement(locations):
    """تحليل نمط الحركة AI مع تحسينات"""
    if len(locations) < 5:
        return {'pattern': 'غير كاف', 'confidence': 0}
    
    try:
        patterns = {'stationary': 0, 'walking': 0, 'running': 0, 'driving': 0, 'unknown': 0}
        speeds = []
        total_dist = 0
        
        for i in range(1, len(locations)):
            loc1, loc2 = locations[i-1], locations[i]
            dist = haversine(loc1['lat'], loc1['lng'], loc2['lat'], loc2['lng'])
            total_dist += dist
            spd = calculate_speed(loc1, loc2)
            
            # تصفية السرعات غير المعقولة
            if spd < 200:  # تجاهل السرعات التي تتجاوز 200 كم/س
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
        
        dominant = max(patterns, key=patterns.get)
        avg_speed = statistics.mean(speeds) if speeds else 0
        max_speed = max(speeds) if speeds else 0
        
        # كشف الحوادث المحتملة مع تحسين الدقة
        accident_detected = False
        if len(speeds) >= 3:
            for i in range(len(speeds)-1):
                if speeds[i] > 30 and speeds[i+1] < 3:
                    accident_detected = True
                    app.logger.warning(f'Potential accident detected: speed dropped from {speeds[i]} to {speeds[i+1]}')
                    break
        
        # تحسين حساب الثقة
        confidence = round(patterns[dominant] / len(locations) * 100, 1) if len(locations) > 0 else 0
        
        return {
            'pattern': dominant,
            'confidence': confidence,
            'average_speed': round(avg_speed, 1),
            'max_speed': round(max_speed, 1),
            'total_distance': round(total_dist, 2),
            'accident_detected': accident_detected,
            'details': patterns
        }
    except Exception as e:
        app.logger.error(f'Error in analyze_movement: {str(e)}')
        return {'pattern': 'خطأ', 'confidence': 0}

def detect_geofence_events(user_id, lat, lng):
    """كشف دخول/خروج مناطق الأمان وإرسال إشعارات مع تحسينات"""
    try:
        geofences = Geofence.query.filter_by(user_id=user_id, is_active=True).all()
        events = []
        
        for geo in geofences:
            distance = haversine(lat, lng, geo.lat, geo.lng) * 1000  # تحويل إلى متر
            
            # استخدام التخزين المؤقت للحالة الأخيرة
            cache_key = f'geofence_last_event_{geo.id}'
            last_event_data = cache.get(cache_key)
            
            if not last_event_data:
                last_event = GeofenceEvent.query.filter_by(
                    geofence_id=geo.id
                ).order_by(GeofenceEvent.timestamp.desc()).first()
                
                last_event_data = {
                    'entering': last_event.entering if last_event else False,
                    'timestamp': last_event.timestamp.isoformat() if last_event else None
                }
                cache.set(cache_key, last_event_data, timeout=300)
            
            currently_inside = distance <= geo.radius
            was_inside = last_event_data['entering']
            
            if currently_inside and not was_inside:
                # دخل المنطقة
                event = GeofenceEvent(
                    geofence_id=geo.id,
                    user_id=user_id,
                    entering=True,
                    lat=lat,
                    lng=lng
                )
                db.session.add(event)
                events.append({'type': 'enter', 'geofence': geo.name, 'distance': round(distance, 1)})
                
                # تحديث التخزين المؤقت
                cache.set(cache_key, {'entering': True, 'timestamp': datetime.now(timezone.utc).isoformat()}, timeout=300)
                
                # إشعار
                create_notification(
                    user_id,
                    f'📍 {geo.name}',
                    f'تم الدخول إلى منطقة {geo.name}',
                    'geofence_enter'
                )
                
                # إشعار أفراد العائلة
                user = User.query.get(user_id)
                if user:
                    notify_family_members(
                        user_id,
                        f'دخل {user.name} منطقة {geo.name}'
                    )
                    
            elif not currently_inside and was_inside:
                # خرج من المنطقة
                event = GeofenceEvent(
                    geofence_id=geo.id,
                    user_id=user_id,
                    entering=False,
                    lat=lat,
                    lng=lng
                )
                db.session.add(event)
                events.append({'type': 'exit', 'geofence': geo.name, 'distance': round(distance, 1)})
                
                # تحديث التخزين المؤقت
                cache.set(cache_key, {'entering': False, 'timestamp': datetime.now(timezone.utc).isoformat()}, timeout=300)
                
                # إشعار
                create_notification(
                    user_id,
                    f'📍 {geo.name}',
                    f'تم الخروج من منطقة {geo.name}',
                    'geofence_exit'
                )
                
                # إشعار أفراد العائلة
                user = User.query.get(user_id)
                if user:
                    notify_family_members(
                        user_id,
                        f'خرج {user.name} من منطقة {geo.name}'
                    )
        
        return events
    except Exception as e:
        app.logger.error(f'Error in detect_geofence_events: {str(e)}')
        return []

def notify_family_members(user_id, message):
    """إرسال إشعار لأفراد العائلة مع معالجة أفضل للأخطاء"""
    try:
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        for fam in families:
            family_members = FamilyMember.query.filter_by(family_id=fam.family_id).all()
            for member in family_members:
                if member.user_id != user_id:
                    create_notification(
                        member.user_id,
                        '👨‍👩‍👧‍👦 العائلة',
                        message,
                        'family'
                    )
                    
                    # بث الإشعار عبر SocketIO بشكل فوري
                    socketio.emit('new_notification', {
                        'title': '👨‍👩‍👧‍👦 العائلة',
                        'message': message,
                        'type': 'family'
                    }, room=f'user_{member.user_id}')
    except Exception as e:
        app.logger.error(f'Error in notify_family_members: {str(e)}')

def create_notification(user_id, title, message, n_type='info', data=None):
    """إنشاء إشعار ذكي مع تحسينات"""
    try:
        # التحقق من صحة المدخلات
        if not user_id or not title or not message:
            return None
        
        # تنظيف البيانات
        title = sanitize_input(title)[:200]
        message = sanitize_input(message)[:500]
        n_type = sanitize_input(n_type).lower()[:50]
        
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            type=n_type,
            data=json.dumps(data) if data else '{}'
        )
        db.session.add(notif)
        db.session.commit()
        
        # بث الإشعار عبر SocketIO
        notification_dict = notif.to_dict()
        socketio.emit('new_notification', notification_dict, room=f'user_{user_id}')
        
        return notif
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in create_notification: {str(e)}')
        return None

# ====== نماذج قاعدة البيانات مع تحسينات ======
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_created', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200))
    avatar = db.Column(db.String(200), default='default.png')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
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

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    __table_args__ = (
        db.Index('idx_token_jti', 'jti'),
        db.Index('idx_token_created', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    token_type = db.Column(db.String(16), nullable=False, default='access')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)

class CurrentLocation(db.Model):
    __tablename__ = 'current_locations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, default=0.0)
    heading = db.Column(db.Float, default=0.0)
    accuracy = db.Column(db.Float, default=0.0)
    battery_level = db.Column(db.Float, default=100.0)
    device_type = db.Column(db.String(50))
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
        db.Index('idx_user_timestamp', 'user_id', 'timestamp'),
        db.Index('idx_location_coords', 'lat', 'lng'),
        db.Index('idx_location_speed', 'speed'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
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
    )
    
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
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
        """التحقق من انتهاء صلاحية الغرفة"""
        if not self.expiry:
            return False
        return datetime.now(timezone.utc) > self.expiry

class SOSAlert(db.Model):
    __tablename__ = 'sos_alerts'
    __table_args__ = (
        db.Index('idx_sos_user', 'user_id'),
        db.Index('idx_sos_resolved', 'resolved'),
        db.Index('idx_sos_timestamp', 'timestamp'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    message = db.Column(db.String(500))
    responder_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # العلاقات
    user = db.relationship('User', foreign_keys=[user_id], backref='sos_alerts')
    responder = db.relationship('User', foreign_keys=[responder_id], backref='responded_sos')

class Friendship(db.Model):
    __tablename__ = 'friendships'
    __table_args__ = (
        db.Index('idx_friendship_users', 'requester_id', 'addressee_id'),
        db.Index('idx_friendship_status', 'status'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    addressee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, accepted, rejected, blocked
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # العلاقات
    requester = db.relationship('User', foreign_keys=[requester_id], backref='sent_requests')
    addressee = db.relationship('User', foreign_keys=[addressee_id], backref='received_requests')

class Group(db.Model):
    __tablename__ = 'groups'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    description = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    
    # العلاقات
    creator = db.relationship('User', backref='created_groups')
    members = db.relationship('GroupMember', backref='group', lazy=True, cascade='all, delete-orphan')

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # العلاقات
    user = db.relationship('User', backref='group_memberships')

class Family(db.Model):
    """نظام العائلة"""
    __tablename__ = 'families'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    join_code = db.Column(db.String(10), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    
    # العلاقات
    creator = db.relationship('User', backref='created_families')
    members = db.relationship('FamilyMember', backref='family', lazy=True, cascade='all, delete-orphan')

class FamilyMember(db.Model):
    __tablename__ = 'family_members'
    
    id = db.Column(db.Integer, primary_key=True)
    family_id = db.Column(db.Integer, db.ForeignKey('families.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Trip(db.Model):
    __tablename__ = 'trips'
    __table_args__ = (
        db.Index('idx_trip_user', 'user_id'),
        db.Index('idx_trip_active', 'is_active'),
        db.Index('idx_trip_date', 'started_at'),
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
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, default=100)
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
    """سجل أحداث مناطق الأمان"""
    __tablename__ = 'geofence_events'
    __table_args__ = (
        db.Index('idx_geofence_event_time', 'timestamp'),
        db.Index('idx_geofence_event_user', 'user_id', 'geofence_id'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    geofence_id = db.Column(db.Integer, db.ForeignKey('geofences.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    entering = db.Column(db.Boolean, default=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Notification(db.Model):
    __tablename__ = 'notifications'
    __table_args__ = (
        db.Index('idx_notif_user', 'user_id', 'is_read'),
        db.Index('idx_notif_created', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500))
    type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    data = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
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
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    date = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date())
    total_distance = db.Column(db.Float, default=0.0)
    total_time_minutes = db.Column(db.Float, default=0.0)
    locations_count = db.Column(db.Integer, default=0)
    trips_count = db.Column(db.Integer, default=0)
    avg_speed = db.Column(db.Float, default=0.0)
    max_speed = db.Column(db.Float, default=0.0)
    sos_count = db.Column(db.Integer, default=0)
    geofence_events_count = db.Column(db.Integer, default=0)

# ====== JWT Blocklist محسن ======
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    try:
        jti = jwt_payload['jti']
        
        # التحقق من التخزين المؤقت أولاً
        cache_key = f'blocked_token_{jti}'
        if cache.get(cache_key):
            return True
        
        # التحقق من قاعدة البيانات
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).first()
        if token:
            cache.set(cache_key, True, timeout=3600)  # تخزين لمدة ساعة
            return True
        
        return False
    except Exception as e:
        app.logger.error(f'Error checking token blocklist: {str(e)}')
        return True  # رفض التوكن في حالة الخطأ للأمان

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

# ====== دوال التحقق ======
def is_valid_email(email):
    """التحقق من صحة البريد الإلكتروني"""
    if not email:
        return False
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def is_valid_coordinates(lat, lng):
    """التحقق من صحة الإحداثيات"""
    try:
        lat_float = float(lat)
        lng_float = float(lng)
        return -90 <= lat_float <= 90 and -180 <= lng_float <= 180
    except (ValueError, TypeError):
        return False

def sanitize_input(text):
    """تنظيف المدخلات من المحتوى الضار"""
    if not text:
        return ''
    # إزالة HTML tags
    text = re.sub(r'<[^>]*>', '', text)
    # إزالة الأحرف الخاصة الخطيرة
    text = re.sub(r'[<>{}]', '', text)
    # قص النص للطول المسموح
    return text.strip()[:1000]

def sanitize_email(email):
    """تنظيف البريد الإلكتروني"""
    if not email:
        return ''
    return email.lower().strip()[:120]

def calculate_distance_matrix(points):
    """حساب مصفوفة المسافات بين مجموعة نقاط"""
    n = len(points)
    matrix = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            dist = haversine(
                points[i]['lat'], points[i]['lng'],
                points[j]['lat'], points[j]['lng']
            )
            matrix[i][j] = round(dist, 2)
            matrix[j][i] = round(dist, 2)
    return matrix

# ====== SocketIO Events محسن ======
@socketio.on('connect')
def handle_connect():
    """معالجة اتصال SocketIO مع المصادقة"""
    try:
        token = request.args.get('token')
        if token:
            # التحقق من JWT token
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            user_id = decoded.get('sub')
            if user_id:
                join_room(f'user_{user_id}')
                app.logger.info(f'User {user_id} connected via SocketIO')
    except Exception as e:
        app.logger.warning(f'Invalid SocketIO token: {str(e)}')

@socketio.on('disconnect')
def handle_disconnect():
    """معالجة قطع الاتصال"""
    pass

@socketio.on('join_tracking')
def handle_join_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        app.logger.info(f'User {user_id} joined tracking room')

@socketio.on('leave_tracking')
def handle_leave_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        leave_room(f'user_{user_id}')

@socketio.on('join_family')
def handle_join_family(data):
    family_id = data.get('family_id')
    if family_id:
        join_room(f'family_{family_id}')

@socketio.on('join_group')
def handle_join_group(data):
    group_id = data.get('group_id')
    if group_id:
        join_room(f'group_{group_id}')

@socketio.on('join_share_room')
def handle_join_share(data):
    """انضمام مستخدم إلى غرفة مشاركة"""
    room_id = data.get('room_id')
    if room_id:
        join_room(f'share_{room_id}')
        app.logger.info(f'User joined share room: {room_id}')
        
        # إرسال الموقع الحالي للمنشئ إذا كان موجوداً
        room = Room.query.filter_by(room_id=room_id, is_active=True).first()
        if room:
            current_location = CurrentLocation.query.filter_by(user_id=room.creator_id).first()
            user = User.query.get(room.creator_id)
            if current_location and user:
                socketio.emit('location_update', {
                    'user_id': room.creator_id,
                    'lat': current_location.lat,
                    'lng': current_location.lng,
                    'speed': current_location.speed,
                    'heading': current_location.heading,
                    'name': user.name,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, room=f'share_{room_id}')

@socketio.on('ping_server')
def handle_ping():
    """للحفاظ على الاتصال نشطاً"""
    emit('pong_server', {'timestamp': datetime.now(timezone.utc).isoformat()})

# ====== Middleware ======
@app.before_request
def before_request():
    """تنفيذ قبل كل طلب"""
    # تسجيل وقت بدء الطلب
    request.start_time = time.time()
    
    # التحقق من User-Agent
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent:
        app.logger.warning(f'Request without User-Agent from {request.remote_addr}')
        return jsonify({'error': 'User-Agent مطلوب'}), 400

@app.after_request
def after_request(response):
    """تنفيذ بعد كل طلب"""
    # إضافة headers أمان
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # إزالة headers حساسة
    response.headers.pop('Server', None)
    
    # تسجيل وقت الاستجابة
    if hasattr(request, 'start_time'):
        elapsed = time.time() - request.start_time
        if request.path.startswith('/api/'):
            app.logger.debug(f'{request.method} {request.path} - {elapsed:.3f}s - {response.status_code}')
    
    return response

@app.teardown_appcontext
def shutdown_session(exception=None):
    """إغلاق الجلسة بشكل آمن"""
    if exception:
        db.session.rollback()
    db.session.remove()

# ====== الصفحات الأمامية ======
@app.route('/')
@cache.cached(timeout=300)  # تخزين مؤقت للصفحة الرئيسية
def index():
    return render_template('index.html')

@app.route('/share/<room_id>')
def share_view(room_id):
    """عرض صفحة المشاركة مع بيانات الغرفة"""
    room = Room.query.filter_by(room_id=room_id, is_active=True).first()
    if not room:
        return render_template('index.html', error='رابط المشاركة غير صالح أو منتهي')
    
    if room.is_expired():
        room.is_active = False
        db.session.commit()
        return render_template('index.html', error='انتهت صلاحية رابط المشاركة')
    
    creator = User.query.get(room.creator_id)
    
    return render_template('index.html', 
                         room_id=room_id,
                         creator_name=creator.name if creator else 'مستخدم')

@app.route('/health')
def health_check():
    """فحص صحة التطبيق"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '3.0.0',
        'uptime': round(time.time() - app.start_time, 2)
    })

# ====== API المصادقة محسن ======
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    try:
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400
        
        name = sanitize_input(data.get('name', ''))
        email = sanitize_email(data.get('email', ''))
        password = data.get('password', '')
        
        # التحقق من المدخلات
        errors = []
        if not name or len(name) < 2:
            errors.append('الاسم يجب أن يكون حرفين على الأقل')
        if not email or not is_valid_email(email):
            errors.append('البريد الإلكتروني غير صالح')
        if not password or len(password) < 6:
            errors.append('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
        
        if errors:
            return jsonify({'error': '. '.join(errors)}), 400
        
        # التحقق من عدم وجود المستخدم
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'البريد الإلكتروني مستخدم بالفعل'}), 409
        
        # إنشاء المستخدم
        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        
        # إنشاء التوكنات
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'name': user.name, 'email': user.email}
        )
        refresh_token = create_refresh_token(identity=str(user.id))
        
        app.logger.info(f'New user registered: {user.email}')
        
        return jsonify({
            'status': 'success',
            'message': 'تم إنشاء الحساب بنجاح',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Register error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء التسجيل'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")
def login():
    try:
        # التحقق من القوة العمياء
        ip = request.remote_addr
        allowed, remaining = brute_force.check_ip(ip)
        if not allowed:
            app.logger.warning(f'Brute force blocked for IP: {ip}')
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
        
        # البحث عن المستخدم
        user = User.query.filter_by(email=email).first()
        if not user:
            app.logger.warning(f'Login attempt for non-existent email: {email}')
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401
        
        if not user.password_hash or not check_password_hash(user.password_hash, password):
            app.logger.warning(f'Failed login attempt for: {email}')
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'الحساب معطل. الرجاء التواصل مع الدعم'}), 403
        
        # تحديث آخر دخول
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        
        # إنشاء التوكنات
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'name': user.name, 'email': user.email}
        )
        refresh_token = create_refresh_token(identity=str(user.id))
        
        # إعادة تعيين عداد المحاولات الخاطئة
        brute_force.reset_ip(ip)
        
        app.logger.info(f'User logged in: {email}')
        
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
        
        # إضافة التوكن للقائمة السوداء
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
        
        # مسح التخزين المؤقت
        cache.delete(f'blocked_token_{jti}')
        
        app.logger.info(f'User {user_id} logged out')
        
        return jsonify({
            'status': 'success',
            'message': 'تم تسجيل الخروج بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Logout error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تسجيل الخروج'}), 500

# ====== API الموقع محسن ======
@app.route('/api/location/update', methods=['POST'])
@jwt_required()
@limiter.limit("300 per minute")
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
        speed = data.get('speed', 0)
        heading = data.get('heading', 0)
        accuracy = data.get('accuracy', 0)
        battery_level = data.get('battery_level', 100)
        device_type = data.get('device_type', 'unknown')
        
        # التحقق من الإحداثيات
        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        # التحقق من السرعة المعقولة
        if float(speed) > 200:
            app.logger.warning(f'Unrealistic speed {speed} from user {user_id}')
            speed = 200  # تحديد السرعة القصوى
        
        now = datetime.now(timezone.utc)
        
        # تحديث الموقع الحالي مع التخزين المؤقت
        cache_key = f'user_location_{user_id}'
        
        current_loc = CurrentLocation.query.filter_by(user_id=user_id).first()
        if current_loc:
            current_loc.lat = float(lat)
            current_loc.lng = float(lng)
            current_loc.speed = float(speed) if speed else 0
            current_loc.heading = float(heading) if heading else 0
            current_loc.accuracy = float(accuracy) if accuracy else 0
            current_loc.battery_level = float(battery_level)
            current_loc.device_type = sanitize_input(device_type)
            current_loc.updated_at = now
        else:
            current_loc = CurrentLocation(
                user_id=user_id,
                lat=float(lat),
                lng=float(lng),
                speed=float(speed) if speed else 0,
                heading=float(heading) if heading else 0,
                accuracy=float(accuracy) if accuracy else 0,
                battery_level=float(battery_level),
                device_type=sanitize_input(device_type),
                updated_at=now
            )
            db.session.add(current_loc)
        
        # تحديث التخزين المؤقت
        cache.set(cache_key, current_loc.to_dict(), timeout=30)
        
        # حفظ في السجل (مع تحسين التحقق من التكرار)
        should_save = True
        last_history = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc()).first()
        
        if last_history:
            time_diff = (now - last_history.timestamp).total_seconds()
            distance = haversine(last_history.lat, last_history.lng, float(lat), float(lng))
            
            # حفظ إذا مر وقت كافٍ أو تغير الموقع بشكل كبير
            should_save = time_diff >= 30 or distance > 0.01
        
        if should_save:
            history = LocationHistory(
                user_id=user_id,
                lat=float(lat),
                lng=float(lng),
                speed=float(speed) if speed else 0,
                heading=float(heading) if heading else 0,
                accuracy=float(accuracy) if accuracy else 0,
                battery_level=float(battery_level),
                timestamp=now
            )
            db.session.add(history)
        
        # تحديث الرحلة النشطة
        active_trip = Trip.query.filter_by(user_id=user_id, is_active=True).first()
        if active_trip:
            recent = LocationHistory.query.filter_by(user_id=user_id)\
                .filter(LocationHistory.timestamp >= active_trip.started_at)\
                .order_by(LocationHistory.timestamp.asc()).all()
            
            if len(recent) >= 2:
                total_dist = sum(
                    haversine(
                        recent[i-1].lat, recent[i-1].lng,
                        recent[i].lat, recent[i].lng
                    ) for i in range(1, len(recent))
                )
                speeds = [loc.speed for loc in recent if loc.speed > 0]
                
                active_trip.total_distance = round(total_dist, 2)
                active_trip.max_speed = round(max(speeds), 1) if speeds else 0
                active_trip.avg_speed = round(sum(speeds) / len(speeds), 1) if speeds else 0
                active_trip.end_lat = float(lat)
                active_trip.end_lng = float(lng)
                active_trip.duration_minutes = round(
                    (now - active_trip.started_at).total_seconds() / 60, 1
                )
        
        # التحقق من Geofencing
        geofence_events = detect_geofence_events(user_id, float(lat), float(lng))
        
        # تحديث الإحصائيات اليومية
        today = now.date()
        snapshot = AnalyticsSnapshot.query.filter_by(user_id=user_id, date=today).first()
        if snapshot:
            snapshot.locations_count += 1
        else:
            db.session.add(AnalyticsSnapshot(
                user_id=user_id,
                date=today,
                locations_count=1
            ))
        
        # كشف الحوادث AI مع تحسين الدقة
        recent_locs = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc()).limit(15).all()
        
        if len(recent_locs) >= 5:
            locs_dict = [
                {
                    'lat': loc.lat,
                    'lng': loc.lng,
                    'speed': loc.speed,
                    'timestamp': loc.timestamp
                } for loc in reversed(recent_locs)
            ]
            analysis = analyze_movement(locs_dict)
            
            if analysis.get('accident_detected'):
                # التحقق من عدم وجود تنبيه حديث لتجنب التكرار
                recent_alert = Notification.query.filter_by(
                    user_id=user_id,
                    type='accident_alert'
                ).filter(
                    Notification.created_at >= now - timedelta(minutes=5)
                ).first()
                
                if not recent_alert:
                    create_notification(
                        user_id,
                        '🚨 تنبيه حادث محتمل',
                        'تم اكتشاف توقف مفاجئ. هل أنت بخير؟',
                        'accident_alert'
                    )
                    
                    # إشعار العائلة
                    user = User.query.get(user_id)
                    if user:
                        notify_family_members(
                            user_id,
                            f'⚠️ تنبيه: توقف مفاجئ لـ {user.name}'
                        )
        
        db.session.commit()
        
        # تجهيز بيانات البث
        user = User.query.get(user_id)
        broadcast_data = {
            'user_id': user_id,
            'lat': float(lat),
            'lng': float(lng),
            'speed': float(speed) if speed else 0,
            'heading': float(heading) if heading else 0,
            'accuracy': float(accuracy) if accuracy else 0,
            'battery_level': float(battery_level),
            'device_type': sanitize_input(device_type),
            'name': user.name if user else 'مستخدم',
            'timestamp': now.isoformat()
        }
        
        # بث الموقع للغرفة الشخصية
        socketio.emit('location_update', broadcast_data, room=f'user_{user_id}')
        
        # بث للعائلة
        families = FamilyMember.query.filter_by(user_id=user_id).all()
        for fam in families:
            socketio.emit(
                'family_location_update',
                broadcast_data,
                room=f'family_{fam.family_id}'
            )
        
        # ✅ بث لغرف المشاركة النشطة
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
        
        time_diff = datetime.now(timezone.utc) - location.updated_at
        status = 'offline' if time_diff > timedelta(seconds=30) else 'online'
        
        return jsonify({
            'status': status,
            'location': location.to_dict(),
            'last_update_seconds_ago': int(time_diff.total_seconds()),
            'is_stale': time_diff > timedelta(minutes=5)
        })
    except Exception as e:
        app.logger.error(f'Get current location error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/location/accuracy', methods=['GET'])
@jwt_required()
def get_location_accuracy():
    """دقة GPS"""
    try:
        user_id = int(get_jwt_identity())
        location = CurrentLocation.query.filter_by(user_id=user_id).first()
        
        if not location:
            return jsonify({'status': 'no_data'}), 404
        
        recent = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc()).limit(20).all()
        
        score = 100
        if len(recent) >= 2:
            dists = [
                haversine(
                    recent[i-1].lat, recent[i-1].lng,
                    recent[i].lat, recent[i].lng
                ) for i in range(1, len(recent))
            ]
            avg = sum(dists) / len(dists)
            if avg > 0.1:
                score = max(30, 100 - (avg * 1000))
            else:
                score = 95
        
        if score > 90:
            quality = 'ممتاز'
        elif score > 70:
            quality = 'جيد'
        elif score > 50:
            quality = 'مقبول'
        else:
            quality = 'ضعيف'
        
        return jsonify({
            'status': 'success',
            'accuracy_score': round(score, 1),
            'gps_quality': quality,
            'samples_count': len(recent),
            'device_accuracy': location.accuracy
        })
    except Exception as e:
        app.logger.error(f'Location accuracy error: {str(e)}')
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/location/batch', methods=['POST'])
@jwt_required()
@limiter.limit("50 per minute")
def batch_update_locations():
    """تحديث مجموعة مواقع دفعة واحدة لتوفير النطاق الترددي"""
    try:
        user_id = int(get_jwt_identity())
        
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400
        
        data = request.get_json()
        locations = data.get('locations', [])
        
        if not locations:
            return jsonify({'error': 'لا توجد بيانات للتحديث'}), 400
        
        if len(locations) > 100:
            return jsonify({'error': 'الحد الأقصى 100 موقع في الطلب الواحد'}), 400
        
        updated_count = 0
        now = datetime.now(timezone.utc)
        
        for loc in locations:
            lat = loc.get('lat')
            lng = loc.get('lng')
            
            if not lat or not lng:
                continue
            
            if not is_valid_coordinates(lat, lng):
                continue
            
            history = LocationHistory(
                user_id=user_id,
                lat=float(lat),
                lng=float(lng),
                speed=float(loc.get('speed', 0)),
                heading=float(loc.get('heading', 0)),
                accuracy=float(loc.get('accuracy', 0)),
                timestamp=datetime.fromisoformat(loc.get('timestamp', now.isoformat()))
            )
            db.session.add(history)
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'تم تحديث {updated_count} موقع',
            'updated_count': updated_count
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Batch location update error: {str(e)}')
        return jsonify({'error': 'حدث خطأ في التحديث الدفعي'}), 500

# ====== API الملاحة ======
@app.route('/api/navigation/route', methods=['POST'])
@jwt_required()
@cache.cached(timeout=300, query_string=True)
def get_navigation_route():
    """حساب المسار باستخدام OSRM"""
    try:
        data = request.get_json()
        start_lat = data.get('start_lat')
        start_lng = data.get('start_lng')
        end_lat = data.get('end_lat')
        end_lng = data.get('end_lng')
        mode = data.get('mode', 'driving')
        
        if not all([start_lat, start_lng, end_lat, end_lng]):
            return jsonify({'error': 'جميع الإحداثيات مطلوبة'}), 400
        
        if not is_valid_coordinates(start_lat, start_lng) or not is_valid_coordinates(end_lat, end_lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        profile_map = {
            'driving': 'driving',
            'walking': 'walking',
            'cycling': 'cycling'
        }
        profile = profile_map.get(mode, 'driving')
        
        url = f"https://router.project-osrm.org/route/v1/{profile}/{start_lng},{start_lat};{end_lng},{end_lat}"
        url += "?overview=full&geometries=geojson&steps=true&alternatives=false"
        
        response = requests.get(url, timeout=10, headers={'User-Agent': 'GeoLegend/3.0'})
        
        if response.status_code == 200:
            route_data = response.json()
            if route_data.get('code') == 'Ok' and route_data.get('routes'):
                route = route_data['routes'][0]
                return jsonify({
                    'status': 'success',
                    'distance_km': round(route['distance'] / 1000, 2),
                    'duration_minutes': round(route['duration'] / 60, 1),
                    'geometry': route.get('geometry'),
                    'source': 'osrm',
                    'mode': mode,
                    'steps': [
                        {
                            'instruction': step.get('name', ''),
                            'distance': round(step['distance'] / 1000, 2),
                            'duration': round(step['duration'] / 60, 1)
                        } for step in route.get('legs', [{}])[0].get('steps', [])[:5]
                    ]
                })
        
        distance = haversine(start_lat, start_lng, end_lat, end_lng)
        speed_estimates = {'driving': 50, 'walking': 5, 'cycling': 15}
        avg_speed = speed_estimates.get(mode, 50)
        duration = (distance / avg_speed) * 60
        
        return jsonify({
            'status': 'success',
            'distance_km': round(distance, 2),
            'duration_minutes': round(duration, 1),
            'geometry': None,
            'source': 'local_calculation',
            'mode': mode
        })
    except requests.Timeout:
        distance = haversine(start_lat, start_lng, end_lat, end_lng)
        return jsonify({
            'status': 'success',
            'distance_km': round(distance, 2),
            'duration_minutes': round((distance / 50) * 60, 1),
            'source': 'local_fallback'
        })
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
        data = request.get_json()
        email = sanitize_input(data.get('email', '')).lower().strip()
        if not email: return jsonify({'error': 'البريد الإلكتروني مطلوب'}), 400
        
        addressee = User.query.filter_by(email=email).first()
        if not addressee: return jsonify({'error': 'المستخدم غير موجود'}), 404
        if addressee.id == requester_id: return jsonify({'error': 'لا يمكنك إرسال طلب لنفسك'}), 400
        
        existing = Friendship.query.filter(
            ((Friendship.requester_id == requester_id) & (Friendship.addressee_id == addressee.id)) |
            ((Friendship.requester_id == addressee.id) & (Friendship.addressee_id == requester_id))
        ).first()
        if existing:
            if existing.status == 'pending': return jsonify({'error': 'يوجد طلب معلق بالفعل'}), 409
            elif existing.status == 'accepted': return jsonify({'error': 'أنتما أصدقاء بالفعل'}), 409
        
        friendship = Friendship(requester_id=requester_id, addressee_id=addressee.id)
        db.session.add(friendship)
        db.session.commit()
        
        create_notification(addressee.id, '👥 طلب صداقة', f'طلب صداقة من {User.query.get(requester_id).name}', 'friend_request')
        return jsonify({'status': 'success', 'message': 'تم إرسال الطلب'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/requests', methods=['GET'])
@jwt_required()
def get_friend_requests():
    try:
        user_id = int(get_jwt_identity())
        requests = Friendship.query.filter_by(addressee_id=user_id, status='pending').all()
        return jsonify({'status': 'success', 'requests': [
            {'id': r.id, 'sender': User.query.get(r.requester_id).to_dict()} for r in requests
        ]})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/respond/<int:request_id>', methods=['POST'])
@jwt_required()
def respond_friend_request(request_id):
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        action = data.get('action', 'accept')
        
        friendship = Friendship.query.get(request_id)
        if not friendship or friendship.addressee_id != user_id:
            return jsonify({'error': 'غير مصرح'}), 403
        
        friendship.status = 'accepted' if action == 'accept' else 'rejected'
        friendship.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم ' + ('قبول' if action == 'accept' else 'رفض') + ' الطلب'})
    except Exception as e:
        db.session.rollback()
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
            fid = f.addressee_id if f.requester_id == user_id else f.requester_id
            friend = User.query.get(fid)
            if friend:
                loc = CurrentLocation.query.filter_by(user_id=fid).first()
                friends.append({'friendship_id': f.id, 'friend': friend.to_dict(),
                               'location': loc.to_dict() if loc else None})
        return jsonify({'status': 'success', 'friends': friends})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/friends/remove/<int:friendship_id>', methods=['DELETE'])
@jwt_required()
def remove_friend(friendship_id):
    try:
        user_id = int(get_jwt_identity())
        friendship = Friendship.query.get(friendship_id)
        if not friendship or (friendship.requester_id != user_id and friendship.addressee_id != user_id):
            return jsonify({'error': 'غير مصرح'}), 403
        
        db.session.delete(friendship)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم حذف الصديق'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API العائلة ======
@app.route('/api/family/create', methods=['POST'])
@jwt_required()
def create_family():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        name = sanitize_input(data.get('name', 'عائلتي'))
        if not name: return jsonify({'error': 'اسم العائلة مطلوب'}), 400
        
        import random, string
        join_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        family = Family(name=name, creator_id=user_id, join_code=join_code)
        db.session.add(family)
        db.session.flush()
        
        member = FamilyMember(family_id=family.id, user_id=user_id, role='admin')
        db.session.add(member)
        db.session.commit()
        
        return jsonify({'status': 'success', 'family': {
            'id': family.id, 'name': family.name, 'join_code': family.join_code,
            'created_at': family.created_at.isoformat()
        }})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/family/join', methods=['POST'])
@jwt_required()
def join_family():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        join_code = data.get('code', '').strip().upper()
        if not join_code: return jsonify({'error': 'رمز الانضمام مطلوب'}), 400
        
        family = Family.query.filter_by(join_code=join_code, is_active=True).first()
        if not family: return jsonify({'error': 'رمز الانضمام غير صحيح'}), 404
        
        existing = FamilyMember.query.filter_by(family_id=family.id, user_id=user_id).first()
        if existing: return jsonify({'error': 'أنت بالفعل عضو في هذه العائلة'}), 409
        
        member = FamilyMember(family_id=family.id, user_id=user_id)
        db.session.add(member)
        db.session.commit()
        
        create_notification(family.creator_id, '👨‍👩‍👧‍👦 عضو جديد', f'انضم {User.query.get(user_id).name} إلى العائلة')
        return jsonify({'status': 'success', 'message': 'تم الانضمام إلى العائلة'})
    except Exception as e:
        db.session.rollback()
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
                member_count = FamilyMember.query.filter_by(family_id=family.id).count()
                members = FamilyMember.query.filter_by(family_id=family.id).all()
                members_list = []
                for mem in members:
                    u = User.query.get(mem.user_id)
                    loc = CurrentLocation.query.filter_by(user_id=mem.user_id).first()
                    members_list.append({
                        'user': u.to_dict() if u else None,
                        'role': mem.role,
                        'location': loc.to_dict() if loc else None
                    })
                families.append({
                    'id': family.id, 'name': family.name, 'join_code': family.join_code,
                    'my_role': m.role, 'member_count': member_count, 'members': members_list
                })
        return jsonify({'status': 'success', 'families': families})
    except Exception as e:
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
        share_pin = data.get('pin') if is_private else None
        
        expiry = None
        if minutes:
            try:
                minutes_int = int(minutes)
                if minutes_int < 1 or minutes_int > 1440:
                    return jsonify({'error': 'المدة بين 1 و 1440 دقيقة'}), 400
                expiry = datetime.now(timezone.utc) + timedelta(minutes=minutes_int)
            except: pass
        
        room = Room(creator_id=user_id, participants=str(user_id), expiry=expiry,
                   is_private=is_private, share_pin=share_pin)
        db.session.add(room)
        db.session.commit()
        
        # ✅ بث الموقع الحالي إلى غرفة المشاركة
        current_location = CurrentLocation.query.filter_by(user_id=user_id).first()
        user = User.query.get(user_id)
        
        if current_location and user:
            socketio.emit('location_update', {
                'user_id': user_id,
                'lat': current_location.lat,
                'lng': current_location.lng,
                'speed': current_location.speed,
                'heading': current_location.heading,
                'name': user.name,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room=f'share_{room.room_id}')
        
        return jsonify({
            'status': 'success',
            'room_id': room.room_id,
            'full_url': f'{request.host_url.rstrip("/")}/share/{room.room_id}',
            'expires_at': room.expiry.isoformat() if room.expiry else None
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الرحلات ======
@app.route('/api/trips/start', methods=['POST'])
@jwt_required()
def start_trip():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        name = sanitize_input(data.get('name', 'رحلة جديدة'))
        lat, lng = data.get('lat'), data.get('lng')
        if not lat or not lng: return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        
        Trip.query.filter_by(user_id=user_id, is_active=True).update({'is_active': False, 'ended_at': datetime.now(timezone.utc)})
        trip = Trip(user_id=user_id, name=name, start_lat=float(lat), start_lng=float(lng))
        db.session.add(trip)
        db.session.commit()
        return jsonify({'status': 'success', 'trip': trip.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/trips/end', methods=['POST'])
@jwt_required()
def end_trip():
    try:
        user_id = int(get_jwt_identity())
        trip = Trip.query.filter_by(user_id=user_id, is_active=True).first()
        if not trip: return jsonify({'error': 'لا توجد رحلة نشطة'}), 404
        
        trip.is_active = False
        trip.ended_at = datetime.now(timezone.utc)
        trip.duration_minutes = round((trip.ended_at - trip.started_at).total_seconds() / 60, 1)
        db.session.commit()
        return jsonify({'status': 'success', 'trip': trip.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/trips/list', methods=['GET'])
@jwt_required()
def list_trips():
    try:
        user_id = int(get_jwt_identity())
        trips = Trip.query.filter_by(user_id=user_id).order_by(Trip.started_at.desc()).limit(50).all()
        return jsonify({'status': 'success', 'trips': [t.to_dict() for t in trips]})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API Geofencing ======
@app.route('/api/geofences/create', methods=['POST'])
@jwt_required()
def create_geofence():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        name = sanitize_input(data.get('name', ''))
        lat, lng, radius = data.get('lat'), data.get('lng'), data.get('radius', 100)
        if not name or not lat or not lng: return jsonify({'error': 'جميع الحقول مطلوبة'}), 400
        
        geofence = Geofence(user_id=user_id, name=name, lat=float(lat), lng=float(lng), radius=float(radius))
        db.session.add(geofence)
        db.session.commit()
        return jsonify({'status': 'success', 'geofence': geofence.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/geofences/list', methods=['GET'])
@jwt_required()
def list_geofences():
    try:
        user_id = int(get_jwt_identity())
        geofences = Geofence.query.filter_by(user_id=user_id).all()
        return jsonify({'status': 'success', 'geofences': [g.to_dict() for g in geofences]})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الإشعارات ======
@app.route('/api/notifications/list', methods=['GET'])
@jwt_required()
def list_notifications():
    try:
        user_id = int(get_jwt_identity())
        notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(50).all()
        return jsonify({'status': 'success', 'notifications': [n.to_dict() for n in notifs]})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/notifications/unread-count', methods=['GET'])
@jwt_required()
def unread_count():
    try:
        user_id = int(get_jwt_identity())
        count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        return jsonify({'status': 'success', 'count': count})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API الإحصائيات والتحليلات ======
@app.route('/api/dashboard/stats', methods=['GET'])
@cache.cached(timeout=60)
def dashboard_stats():
    try:
        five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        return jsonify({'status': 'success', 'stats': {
            'total_users': User.query.count(),
            'online_users': CurrentLocation.query.filter(CurrentLocation.updated_at >= five_min_ago).count(),
            'active_rooms': Room.query.filter_by(is_active=True).count(),
            'pending_sos': SOSAlert.query.filter_by(resolved=False).count()
        }})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/analytics/daily', methods=['GET'])
@jwt_required()
def daily_analytics():
    try:
        user_id = int(get_jwt_identity())
        today = datetime.now(timezone.utc).date()
        snapshot = AnalyticsSnapshot.query.filter_by(user_id=user_id, date=today).first()
        if not snapshot:
            return jsonify({'status': 'success', 'analytics': {'total_distance': 0, 'total_time': 0, 'locations': 0, 'trips': 0}})
        return jsonify({'status': 'success', 'analytics': {
            'total_distance': round(snapshot.total_distance, 2),
            'total_time_minutes': round(snapshot.total_time_minutes, 1),
            'locations_count': snapshot.locations_count,
            'trips_count': snapshot.trips_count,
            'avg_speed': round(snapshot.avg_speed, 1)
        }})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

@app.route('/api/analytics/movement-pattern', methods=['GET'])
@jwt_required()
def movement_pattern():
    try:
        user_id = int(get_jwt_identity())
        recent = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc()).limit(50).all()
        if len(recent) < 5:
            return jsonify({'status': 'success', 'analysis': {'pattern': 'غير كاف', 'confidence': 0}})
        
        locs = [{'lat': l.lat, 'lng': l.lng, 'speed': l.speed, 'timestamp': l.timestamp} for l in reversed(recent)]
        analysis = analyze_movement(locs)
        return jsonify({'status': 'success', 'analysis': analysis})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== API SOS ======
@app.route('/api/sos', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def send_sos():
    try:
        user_id = int(get_jwt_identity())
        if not request.is_json: return jsonify({'error': 'يجب إرسال JSON'}), 400
        data = request.get_json()
        lat, lng = data.get('lat'), data.get('lng')
        message = sanitize_input(data.get('message', '🚨 طلب مساعدة عاجل'))
        
        if lat is None or lng is None: return jsonify({'error': 'الإحداثيات مطلوبة'}), 400
        if not is_valid_coordinates(lat, lng): return jsonify({'error': 'إحداثيات غير صالحة'}), 400
        
        sos = SOSAlert(user_id=user_id, lat=float(lat), lng=float(lng), message=message[:500])
        db.session.add(sos)
        db.session.commit()
        
        socketio.emit('sos_alert', {
            'user_id': user_id, 'lat': float(lat), 'lng': float(lng),
            'message': message[:500], 'timestamp': datetime.now(timezone.utc).isoformat()
        }, broadcast=True)
        
        # إشعار الأصدقاء والعائلة
        friendships = Friendship.query.filter(
            ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)),
            Friendship.status == 'accepted'
        ).all()
        for f in friendships:
            fid = f.addressee_id if f.requester_id == user_id else f.requester_id
            create_notification(fid, '🚨 SOS!', f'إشارة طوارئ من {User.query.get(user_id).name}', 'sos')
        
        notify_family_members(user_id, f'🚨 إشارة طوارئ من {User.query.get(user_id).name}!')
        
        return jsonify({'status': 'success', 'message': 'تم إرسال إشارة الطوارئ', 'alert_id': sos.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ'}), 500

# ====== خدمة الملفات محسنة ======
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
            {
                "src": "/static/icons/icon-192.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    })

@app.route('/sw.js')
def service_worker():

    sw_code = """
const CACHE_NAME = 'geolegend-v7';

// INSTALL - تخزين أولي للصفحة الرئيسية
self.addEventListener('install', (event) => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll([
                '/',
                '/manifest.json'
            ]);
        })
    );
});

// ACTIVATE
self.addEventListener('activate', (event) => {
    event.waitUntil(
        Promise.all([
            caches.keys().then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (
                            cacheName.startsWith('geolegend-') &&
                            cacheName !== CACHE_NAME
                        ) {
                            return caches.delete(cacheName);
                        }
                    })
                );
            }),
            self.clients.claim()
        ])
    );
});

// FETCH
self.addEventListener('fetch', (event) => {

    if (event.request.method !== 'GET') return;

    // تجاهل API
    if (event.request.url.includes('/api/')) {
        return;
    }

    // تجاهل الطلبات الخارجية
    const url = new URL(event.request.url);

    if (url.origin !== location.origin) {
        return;
    }

    event.respondWith(

        fetch(event.request)

            .then((response) => {

                // تجاهل الردود غير الناجحة
                if (!response || response.status !== 200) {
                    return response;
                }

                // تخزين فقط أنواع محددة
                const contentType = response.headers.get('content-type');

                if (
                    contentType &&
                    (
                        contentType.includes('text/html') ||
                        contentType.includes('text/css') ||
                        contentType.includes('javascript') ||
                        contentType.includes('image')
                    )
                ) {
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseClone);
                    });
                }

                return response;

            })

            .catch(async () => {

                // fallback من الكاش
                const cachedResponse = await caches.match(event.request);

                if (cachedResponse) {
                    return cachedResponse;
                }

                // fallback نهائي للصفحة الرئيسية
                return caches.match('/');

            })

    );

});
"""

    response = app.response_class(
        response=sw_code,
        status=200,
        mimetype='application/javascript'
    )

    # منع تخزين sw.js نفسه
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/icons', 'icon-192.png')

@app.route('/static/<path:filename>')
def custom_static(filename):
    """خدمة الملفات الثابتة مع التخزين المؤقت"""
    try:
        response = send_file(f'static/{filename}')
        if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg')):
            response.headers['Cache-Control'] = 'public, max-age=31536000'
        elif filename.endswith(('.css', '.js')):
            response.headers['Cache-Control'] = 'public, max-age=604800'
        return response
    except FileNotFoundError:
        return jsonify({'error': 'الملف غير موجود'}), 404

# ====== معالجة الأخطاء ======
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'طلب غير صالح'}), 400

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
    return jsonify({
        'error': 'تجاوزت الحد المسموح من الطلبات. حاول لاحقاً'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'خطأ داخلي في الخادم'}), 500

# ====== مهم جداً لـ Gunicorn/Render ======
application = app

# ====== نقطة البداية ======
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.logger.info('Database tables created')
        print('✅ Database tables created successfully')
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║     🌟 GeoLegend Ultimate 3D System        ║
    ║                                            ║
    ║  Port: {port}                               ║
    ║  Debug: {debug}                               ║
    ║                                            ║
    ║  ✅ Live Tracking     ✅ Navigation        ║
    ║  ✅ Family System     ✅ Geofencing        ║
    ║  ✅ AI Analysis       ✅ Friends           ║
    ║  ✅ Trips             ✅ Groups            ║
    ║  ✅ SOS Alerts        ✅ Notifications     ║
    ║  ✅ Share Location    ✅ Real-time Updates ║
    ║  ✅ Rate Limiting     ✅ Brute Force Prot  ║
    ║  ✅ Caching           ✅ Logging           ║
    ╚══════════════════════════════════════════════╝
    """)
    
    socketio.run(
        app,
        debug=debug,
        host='0.0.0.0',
        port=port,
        allow_unsafe_werkzeug=True
    )
