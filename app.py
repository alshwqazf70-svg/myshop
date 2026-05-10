from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os
import re
import uuid

# ====== إعدادات التطبيق ======
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'geo-legend-2024-secure-key-change-in-production')

# قاعدة البيانات - مسار مضمون على Render
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(basedir, "geo_legend.db")}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# ====== تفعيل الإضافات ======
CORS(app, resources={
    r"/api/*": {
        "origins": "*"
    }
})
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

# ====== نماذج قاعدة البيانات ======
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200))
    avatar = db.Column(db.String(200), default='default.png')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    current_location = db.relationship('CurrentLocation', backref='user', uselist=False, cascade='all, delete-orphan')
    location_history = db.relationship('LocationHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    rooms = db.relationship('Room', backref='creator', lazy=True, foreign_keys='Room.creator_id')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'avatar': self.avatar
        }

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class CurrentLocation(db.Model):
    __tablename__ = 'current_locations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, default=0.0)
    heading = db.Column(db.Float, default=0.0)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'lat': self.lat,
            'lng': self.lng,
            'speed': self.speed,
            'heading': self.heading,
            'updated_at': self.updated_at.isoformat()
        }

class LocationHistory(db.Model):
    __tablename__ = 'location_history'
    __table_args__ = (
        db.Index('idx_user_timestamp', 'user_id', 'timestamp'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, default=0.0)
    heading = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'lat': self.lat,
            'lng': self.lng,
            'speed': self.speed,
            'heading': self.heading,
            'timestamp': self.timestamp.isoformat()
        }

class Room(db.Model):
    __tablename__ = 'rooms'

    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    participants = db.Column(db.Text, default='')
    expiry = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class SOSAlert(db.Model):
    __tablename__ = 'sos_alerts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    message = db.Column(db.String(500))
    resolved = db.Column(db.Boolean, default=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

# ====== JWT Blocklist Checker ======
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).first()
    return token is not None

# معالجة خطأ التوكن المنتهي
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مجدداً.'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'توكن غير صالح. الرجاء تسجيل الدخول.'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'التوكن مطلوب. الرجاء تسجيل الدخول.'}), 401

# ====== دوال التحقق ======
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_coordinates(lat, lng):
    try:
        lat_val = float(lat)
        lng_val = float(lng)
        return -90 <= lat_val <= 90 and -180 <= lng_val <= 180
    except (ValueError, TypeError):
        return False

def sanitize_input(text):
    if not text:
        return ''
    text = re.sub(r'<[^>]*>', '', text)
    return text.strip()[:1000]

# ====== SocketIO Events ======
@socketio.on('connect')
def handle_connect():
    print(f'🔗 مستخدم متصل: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'🔌 مستخدم منفصل: {request.sid}')

@socketio.on('join_tracking')
def handle_join_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        room = f'user_{user_id}'
        join_room(room)
        print(f'👁️ عميل انضم لتتبع المستخدم {user_id}')

@socketio.on('leave_tracking')
def handle_leave_tracking(data):
    user_id = data.get('user_id')
    if user_id:
        room = f'user_{user_id}'
        leave_room(room)
        print(f'👋 عميل غادر تتبع المستخدم {user_id}')

# ====== الصفحات الأمامية ======
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/map')
def map_view():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard_view():
    return render_template('index.html')

@app.route('/share/<room_id>')
def share_view(room_id):
    return render_template('index.html', room_id=room_id)

@app.route('/login')
def login_page():
    return render_template('index.html')

@app.route('/register')
def register_page():
    return render_template('index.html')

# ====== API المصادقة ======
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
        email = sanitize_input(data.get('email', '')).lower().strip()
        password = data.get('password', '')

        errors = []
        if not name or len(name) < 2:
            errors.append('الاسم يجب أن يكون حرفين على الأقل')
        if not email or not is_valid_email(email):
            errors.append('البريد الإلكتروني غير صالح')
        if not password or len(password) < 6:
            errors.append('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
        if errors:
            return jsonify({'error': '. '.join(errors)}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'البريد الإلكتروني مستخدم بالفعل'}), 409

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        return jsonify({
            'status': 'success',
            'message': 'تم إنشاء الحساب بنجاح',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f'Registration error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء التسجيل. الرجاء المحاولة لاحقاً.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")
def login():
    try:
        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'البيانات فارغة'}), 400

        email = sanitize_input(data.get('email', '')).lower().strip()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'جميع الحقول مطلوبة'}), 400

        user = User.query.filter_by(email=email).first()

        if not user or not user.password_hash:
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401

        if not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'بيانات الدخول غير صحيحة'}), 401

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        return jsonify({
            'status': 'success',
            'message': 'تم تسجيل الدخول بنجاح',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        })

    except Exception as e:
        print(f'Login error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تسجيل الدخول. الرجاء المحاولة لاحقاً.'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)
        return jsonify({'access_token': new_access_token})
    except Exception as e:
        return jsonify({'error': 'حدث خطأ أثناء تحديث التوكن'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تسجيل الخروج بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء تسجيل الخروج'}), 500

# ====== API الموقع ======
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

        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400

        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400

        # تحديث أو إنشاء الموقع الحالي
        current_loc = CurrentLocation.query.filter_by(user_id=user_id).first()

        if current_loc:
            current_loc.lat = float(lat)
            current_loc.lng = float(lng)
            current_loc.speed = float(speed) if speed else 0
            current_loc.heading = float(heading) if heading else 0
            current_loc.updated_at = datetime.now(timezone.utc)
        else:
            current_loc = CurrentLocation(
                user_id=user_id,
                lat=float(lat),
                lng=float(lng),
                speed=float(speed) if speed else 0,
                heading=float(heading) if heading else 0
            )
            db.session.add(current_loc)

        # إضافة للسجل التاريخي
        last_history = LocationHistory.query.filter_by(user_id=user_id)\
            .order_by(LocationHistory.timestamp.desc()).first()

        should_save_history = (
            not last_history or
            (datetime.now(timezone.utc) - last_history.timestamp).total_seconds() >= 60
        )

        if should_save_history:
            history = LocationHistory(
                user_id=user_id,
                lat=float(lat),
                lng=float(lng),
                speed=float(speed) if speed else 0,
                heading=float(heading) if heading else 0
            )
            db.session.add(history)

        db.session.commit()

        # بث الموقع المباشر عبر SocketIO
        socketio.emit('location_update', {
            'user_id': user_id,
            'lat': float(lat),
            'lng': float(lng),
            'speed': float(speed) if speed else 0,
            'heading': float(heading) if heading else 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f'user_{user_id}')

        return jsonify({
            'status': 'success',
            'message': 'تم تحديث الموقع بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        print(f'Location update error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء تحديث الموقع'}), 500

@app.route('/api/location/current', methods=['GET'])
@jwt_required()
def get_my_current_location():
    try:
        user_id = int(get_jwt_identity())

        location = CurrentLocation.query.filter_by(user_id=user_id).first()

        if not location:
            return jsonify({
                'status': 'no_data',
                'location': None
            })

        time_diff = datetime.now(timezone.utc) - location.updated_at
        is_stale = time_diff > timedelta(seconds=30)

        return jsonify({
            'status': 'offline' if is_stale else 'online',
            'location': location.to_dict(),
            'stale': is_stale,
            'last_update_seconds_ago': int(time_diff.total_seconds())
        })

    except Exception as e:
        return jsonify({'error': 'حدث خطأ أثناء جلب الموقع'}), 500

@app.route('/api/location/live/<int:user_id>', methods=['GET'])
def get_live_location(user_id):
    try:
        location = CurrentLocation.query.filter_by(user_id=user_id).first()

        if not location:
            return jsonify({
                'status': 'offline',
                'location': None,
                'message': 'المستخدم غير متصل حالياً'
            })

        time_diff = datetime.now(timezone.utc) - location.updated_at
        is_online = time_diff < timedelta(seconds=30)

        user = User.query.get(user_id)

        return jsonify({
            'status': 'online' if is_online else 'offline',
            'user': user.to_dict() if user else None,
            'location': location.to_dict() if is_online else None,
            'last_update_seconds_ago': int(time_diff.total_seconds()),
            'is_moving': location.speed > 1 if is_online else False
        })

    except Exception as e:
        print(f'Live location error: {str(e)}')
        return jsonify({'error': 'حدث خطأ أثناء جلب الموقع المباشر'}), 500

# ====== API المشاركة ======
@app.route('/api/share/create', methods=['POST'])
@jwt_required()
@limiter.limit("20 per minute")
def create_share():
    try:
        user_id = int(get_jwt_identity())

        data = request.get_json() if request.is_json else {}
        minutes = data.get('minutes') if data else None

        expiry = None
        if minutes is not None:
            try:
                minutes_int = int(minutes)
                if minutes_int < 1 or minutes_int > 1440:
                    return jsonify({'error': 'المدة يجب أن تكون بين 1 و 1440 دقيقة'}), 400
                expiry = datetime.now(timezone.utc) + timedelta(minutes=minutes_int)
            except (ValueError, TypeError):
                return jsonify({'error': 'قيمة غير صالحة للمدة'}), 400

        room = Room(
            creator_id=user_id,
            participants=str(user_id),
            expiry=expiry
        )
        db.session.add(room)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'room_id': room.room_id,
            'share_url': f'/share/{room.room_id}',
            'full_url': f'{request.host_url.rstrip("/")}/share/{room.room_id}',
            'expires_at': room.expiry.isoformat() if room.expiry else None
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء إنشاء الرابط'}), 500

@app.route('/api/share/<room_id>', methods=['GET'])
def get_share_info(room_id):
    try:
        room = Room.query.filter_by(room_id=room_id).first()

        if not room:
            return jsonify({'error': 'الرابط غير موجود'}), 404

        if room.expiry and room.expiry < datetime.now(timezone.utc):
            room.is_active = False
            db.session.commit()
            return jsonify({'error': 'انتهت صلاحية الرابط'}), 410

        user = User.query.get(room.creator_id)
        if not user:
            return jsonify({'error': 'المستخدم غير موجود'}), 404

        location = CurrentLocation.query.filter_by(user_id=user.id).first()

        return jsonify({
            'status': 'success',
            'user': user.to_dict(),
            'location': location.to_dict() if location else None
        })

    except Exception as e:
        return jsonify({'error': 'حدث خطأ أثناء عرض المشاركة'}), 500

# ====== API الطوارئ ======
@app.route('/api/sos', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def send_sos():
    try:
        user_id = int(get_jwt_identity())

        if not request.is_json:
            return jsonify({'error': 'يجب إرسال JSON'}), 400

        data = request.get_json()
        lat = data.get('lat')
        lng = data.get('lng')
        message = sanitize_input(data.get('message', '🚨 طلب مساعدة عاجل'))

        if lat is None or lng is None:
            return jsonify({'error': 'الإحداثيات مطلوبة'}), 400

        if not is_valid_coordinates(lat, lng):
            return jsonify({'error': 'إحداثيات غير صالحة'}), 400

        sos = SOSAlert(
            user_id=user_id,
            lat=float(lat),
            lng=float(lng),
            message=message[:500]
        )
        db.session.add(sos)
        db.session.commit()

        socketio.emit('sos_alert', {
            'user_id': user_id,
            'lat': float(lat),
            'lng': float(lng),
            'message': message[:500],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, broadcast=True)

        return jsonify({
            'status': 'success',
            'message': 'تم إرسال إشارة الطوارئ بنجاح',
            'alert_id': sos.id
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء إرسال إشارة الطوارئ'}), 500

# ====== API الإحصائيات ======
@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    try:
        five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)

        total_users = User.query.count()
        online_users = CurrentLocation.query.filter(
            CurrentLocation.updated_at >= five_min_ago
        ).count()
        active_rooms = Room.query.filter_by(is_active=True).count()

        return jsonify({
            'status': 'success',
            'stats': {
                'total_users': total_users,
                'online_users': online_users,
                'active_rooms': active_rooms,
                'pending_sos': 0
            }
        })

    except Exception as e:
        return jsonify({'error': 'حدث خطأ في الإحصائيات'}), 500

# ====== خدمة الملفات ======
@app.route('/manifest.json')
def manifest():
    manifest_data = {
        "name": "GeoLegend - مشاركة الموقع الأسطوري",
        "short_name": "GeoLegend",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a1a",
        "theme_color": "#00ffff",
        "description": "نظام مشاركة الموقع الجغرافي المتطور",
        "icons": [
            {
                "src": "/static/icons/icon-192.png",
                "sizes": "192x192",
                "type": "image/png"
            }
        ]
    }
    return jsonify(manifest_data)

@app.route('/sw.js')
def service_worker():
    sw_content = """
const CACHE_NAME = 'geolegend-v2';
self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(CACHE_NAME));
});
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request)
            .then((response) => response || fetch(event.request))
    );
});
"""
    response = app.response_class(
        response=sw_content,
        status=200,
        mimetype='application/javascript'
    )
    return response

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/icons', 'icon-192.png')

# ====== معالجة الأخطاء ======
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'المسار غير موجود'}), 404
    return render_template('index.html'), 200

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'خطأ داخلي في الخادم'}), 500

# ====== نقطة البداية ======
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    print(f'🌟 GeoLegend - Live Tracking System on port {port}')
    socketio.run(app, debug=False, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)