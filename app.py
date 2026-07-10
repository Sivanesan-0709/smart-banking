from gevent import monkey
monkey.patch_all()

from flask import Flask, request, jsonify, session, send_from_directory
import sqlite3
import joblib
import pandas as pd
import numpy as np
import os
import json
import traceback
from flask_socketio import SocketIO, emit, join_room, leave_room
import datetime
from pathlib import Path
import base64
import cv2
import random
import sys
import secrets
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash

# Load local .env file manually if present
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(env_path):
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.strip().split('=', 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=None)

is_test = 'unittest' in sys.modules or os.environ.get('TESTING') == '1'
is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if is_test or is_dev:
        secret_key = 'smart_banking_secure_session_key_2026'
    else:
        raise RuntimeError("Production Startup Failure: SECRET_KEY environment variable is missing.")
app.secret_key = secret_key

otp_pepper = os.environ.get('OTP_PEPPER')
if not otp_pepper:
    if is_test or is_dev:
        otp_pepper = 'smart_banking_secure_otp_pepper_2026'
    else:
        raise RuntimeError("Production Startup Failure: OTP_PEPPER environment variable is missing.")

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('RENDER') is not None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = str(BASE_DIR / 'BankNH.db')

# --- OTP Security & Email Delivery Helpers ---
def hash_otp(otp):
    pepper = os.environ.get('OTP_PEPPER', 'smart_banking_secure_otp_pepper_2026')
    return hmac.new(pepper.encode('utf-8'), otp.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_otp_hmac(input_otp, stored_hash):
    computed_hash = hash_otp(input_otp)
    return hmac.compare_digest(stored_hash, computed_hash)

def send_otp_email(recipient_email, otp, amount, receiver):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = os.environ.get('SMTP_PORT')
    smtp_username = os.environ.get('SMTP_USERNAME')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    smtp_from = os.environ.get('SMTP_FROM_EMAIL', smtp_username)
    smtp_use_tls = os.environ.get('SMTP_USE_TLS', 'True').lower() in ('true', '1', 'yes')
    
    if not smtp_host or not smtp_username or not smtp_password:
        is_test = 'unittest' in sys.modules or os.environ.get('TESTING') == '1'
        is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')
        if is_test or is_dev:
            print(f"[DEVELOPMENT ONLY] Mock email sent to {recipient_email}. OTP is: {otp}")
            return True
        else:
            raise RuntimeError("Mailing failed: SMTP environment variables are missing.")
            
    msg = EmailMessage()
    msg['Subject'] = 'Smart Banking Security Verification Code'
    msg['From'] = smtp_from
    msg['To'] = recipient_email
    
    body = f"""<h2>Smart Banking Security Verification</h2>
<p>You have initiated a high-risk transaction of <strong>INR {amount:,.2f}</strong> to recipient <strong>{receiver}</strong>.</p>
<p>Your 6-digit verification code is:</p>
<p style="font-size: 1.5rem; font-weight: bold; letter-spacing: 2px; color: #9b5de5;">{otp}</p>
<p>This code is valid for exactly <strong>5 minutes</strong>. Do NOT share this code with anyone, including bank representatives.</p>
<p>If you did not initiate this transaction, please log in to your account and change your password immediately.</p>
"""
    msg.set_content(body, subtype='html')
    
    try:
        if smtp_use_tls:
            server = smtplib.SMTP(smtp_host, int(smtp_port))
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_host, int(smtp_port))
        
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        traceback.print_exc()
        is_test = 'unittest' in sys.modules or os.environ.get('TESTING') == '1'
        is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')
        if is_test or is_dev:
            print(f"[DEVELOPMENT ONLY] SMTP failed, falling back to mock. OTP is: {otp}")
            return True
        raise e

MODEL_PATH = str(BASE_DIR / 'banking_app_rf.pkl')
METRICS_PATH = str(BASE_DIR / 'model_metrics.json')

# Global ML models
model = None
face_detector = None
face_recognizer = None

def load_ml_model():
    global model
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            print("ML model pipeline loaded successfully.")
        except Exception as e:
            print(f"Error loading ML model: {e}")
            model = None
    else:
        print("ML model pickle file not found. Real-time predictions will use a rule-based fallback.")

def load_face_models():
    global face_detector, face_recognizer
    
    os.makedirs('models', exist_ok=True)
    yunet_path = os.path.join('models', 'face_detection_yunet_2023mar.onnx')
    sface_path = os.path.join('models', 'face_recognition_sface_2021dec.onnx')
    
    yunet_url = "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
    sface_url = "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
    
    import urllib.request
    
    def download_file(url, dest):
        if not os.path.exists(dest):
            print(f"Downloading {os.path.basename(dest)}... (this happens once)")
            try:
                urllib.request.urlretrieve(url, dest)
                print(f"Successfully downloaded {os.path.basename(dest)}.")
            except Exception as e:
                print(f"Failed to download {os.path.basename(dest)}: {e}")
                
    download_file(yunet_url, yunet_path)
    download_file(sface_url, sface_path)
    
    if os.path.exists(yunet_path) and os.path.exists(sface_path):
        try:
            # Score threshold: 0.9, NMS threshold: 0.3, top K: 5000
            face_detector = cv2.FaceDetectorYN.create(yunet_path, "", (320, 320), 0.9, 0.3, 5000)
            face_recognizer = cv2.FaceRecognizerSF.create(sface_path, "")
            print("OpenCV YuNet face detector and SFace recognizer loaded successfully.")
        except Exception as e:
            print(f"Error initializing OpenCV Face models: {e}")
            face_detector = None
            face_recognizer = None
    else:
        print("Face ONNX models are missing and could not be downloaded.")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

def is_login_rate_limited(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Bounded cleanup of expired attempts (> 5 minutes ago)
    cursor.execute("DELETE FROM login_attempts WHERE attempted_at < datetime('now', '-5 minutes')")
    conn.commit()
    
    # Check attempts in last 5 minutes
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND attempted_at >= datetime('now', '-5 minutes')", (username,))
    count = cursor.fetchone()[0]
    conn.close()
    return count >= 5

def record_login_attempt(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_attempts (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()

def clear_login_attempts(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create cash_out_channels table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cash_out_channels (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE'
    )
    ''')
    # Seed default cash out channels
    cursor.execute("INSERT OR IGNORE INTO cash_out_channels (id, name, status) VALUES ('ATM_01', 'Main Branch ATM', 'ACTIVE')")
    cursor.execute("INSERT OR IGNORE INTO cash_out_channels (id, name, status) VALUES ('AGENT_ALPHA', 'Mobile Agent Alpha', 'ACTIVE')")
    cursor.execute("INSERT OR IGNORE INTO cash_out_channels (id, name, status) VALUES ('MERCHANT_WEST', 'Westside Merchant Partner', 'ACTIVE')")
    
    # Create login_attempts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_attempts (
        username TEXT NOT NULL,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create NEWBANK if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS NEWBANK (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        USERNAME TEXT UNIQUE NOT NULL,
        FIRSTNAME TEXT NOT NULL,
        LASTNAME TEXT NOT NULL,
        EMAIL TEXT NOT NULL,
        PASSWORD TEXT NOT NULL,
        CONFIRM TEXT NOT NULL,
        PHONE TEXT NOT NULL,
        SEX TEXT,
        ADDRESS TEXT NOT NULL,
        BAL REAL DEFAULT 50000.0
    )
    ''')

    # Create pending_transactions if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS pending_transactions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        receiver TEXT NOT NULL,
        amount REAL NOT NULL,
        ttype TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        reasons TEXT NOT NULL,
        is_fraud_predicted INTEGER NOT NULL,
        otp_verified INTEGER DEFAULT 0,
        face_verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        status TEXT DEFAULT 'PENDING',
        decision_trace TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
    )
    ''')

    # Create transaction_otp_challenges if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transaction_otp_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_token TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 5,
        resend_count INTEGER DEFAULT 0,
        last_sent_at DATETIME,
        verified INTEGER DEFAULT 0,
        verified_at DATETIME,
        consumed INTEGER DEFAULT 0,
        consumed_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(transaction_token) REFERENCES pending_transactions(token)
    )
    ''')

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_otp_token ON transaction_otp_challenges(transaction_token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_token ON pending_transactions(token)")

    
    # Create NEWT if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS NEWT (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        SENDER TEXT NOT NULL,
        RECEIVER TEXT NOT NULL,
        TTYPE TEXT NOT NULL,
        AMOUNT REAL NOT NULL,
        SENDEROLDBAL REAL NOT NULL,
        SENDERNEWBAL REAL NOT NULL,
        RECOLDBAL REAL NOT NULL,
        RECNEWBAL REAL NOT NULL,
        STATUS TEXT DEFAULT 'APPROVED',
        TIMESTAMP DATETIME DEFAULT CURRENT_TIMESTAMP,
        IS_FRAUD_PREDICTED INTEGER DEFAULT 0,
        DECISION_TRACE TEXT
    )
    ''')
    try:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN DECISION_TRACE TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Create Biometric Enrollment Reference
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS face_enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        template_reference TEXT NOT NULL, -- 128-float embedding JSON
        model_name TEXT DEFAULT 'SFace',
        model_version TEXT DEFAULT '1.0',
        enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'ACTIVE',
        FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
    )
    ''')

    # Create Biometric Verification Attempts
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS face_verification_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_id INTEGER,
        verification_result TEXT NOT NULL, -- 'SUCCESS', 'MISMATCH', 'LIVENESS_FAILED', 'ERROR'
        similarity_or_distance REAL,
        threshold REAL,
        liveness_result TEXT,
        challenge_type TEXT,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        model_version TEXT,
        FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
    )
    ''')

    # Create Biometric Security Event logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS biometric_security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        transaction_id INTEGER,
        event_type TEXT NOT NULL, -- 'FACE_MISMATCH', 'LIVENESS_FAILURE', 'REPEATED_FAILURES', 'ENROLLMENT_DELETED'
        severity TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH'
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        metadata TEXT,
        FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
    )
    ''')
    
    # Verify if columns exist in NEWT (for backward compatibility / migration)
    cursor.execute("PRAGMA table_info(NEWT)")
    columns = [col['name'] for col in cursor.fetchall()]
    
    if 'STATUS' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN STATUS TEXT DEFAULT 'APPROVED'")
    if 'TIMESTAMP' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN TIMESTAMP DATETIME DEFAULT '2026-07-02 00:00:00'")
    if 'IS_FRAUD_PREDICTED' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN IS_FRAUD_PREDICTED INTEGER DEFAULT 0")
        
    # Index migrations (run after all tables are created)
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_newbank_username ON NEWBANK(USERNAME)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_status ON NEWT(STATUS)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_face_attempts_user ON face_verification_attempts(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
    
    conn.commit()
    conn.close()

# Initialize databases and models on startup
init_db()
load_ml_model()
load_face_models()

# --- Helper Biometric Utils ---
def decode_base64_image(base64_str):
    try:
        if ',' in base64_str:
            base64_str = base64_str.split(',')[1]
        # Normalize padding
        missing_padding = len(base64_str) % 4
        if missing_padding:
            base64_str += '=' * (4 - missing_padding)
        img_data = base64.b64decode(base64_str)
        nparr = np.frombuffer(img_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Decoded image is empty or invalid format.")
        return img
    except Exception as e:
        raise ValueError(f"Failed to decode base64 image: {str(e)}")

def validate_face_quality(img):
    if face_detector is None:
        return {"status": "error", "message": "Face models are not initialized on the server."}
        
    h, w, c = img.shape
    face_detector.setInputSize((w, h))
    
    _, faces = face_detector.detect(img)
    
    if faces is None or len(faces) == 0:
        return {"status": "error", "message": "No face detected in the frame. Please look directly at the camera."}
    
    if len(faces) > 1:
        return {"status": "error", "message": "Multiple faces detected. Only one person should be in the frame."}
        
    face = faces[0]
    bbox = face[0:4]
    landmarks = face[4:14]
    
    fx, fy, fw, fh = int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])
    
    # 1. Face size check
    if fw < 80 or fh < 80:
        return {"status": "error", "message": "Face is too far away. Please move closer to the camera."}
        
    # 2. Lighting / brightness check
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face_roi = gray[max(0, fy):min(h, fy+fh), max(0, fx):min(w, fx+fw)]
    if face_roi.size > 0:
        mean_brightness = np.mean(face_roi)
        if mean_brightness < 40:
            return {"status": "error", "message": "Lighting is too dark. Please adjust your lighting."}
            
    # 3. Blurriness check
    if face_roi.size > 0:
        variance = cv2.Laplacian(face_roi, cv2.CV_64F).var()
        if variance < 8.0:
            return {"status": "error", "message": "Image is excessively blurry. Please stabilize your camera."}
            
    return {"status": "success", "face": face}

def extract_face_embedding(img, face):
    if face_recognizer is None:
        raise ValueError("Face recognition model is not loaded on the server.")
    aligned_face = face_recognizer.alignCrop(img, face)
    embedding = face_recognizer.feature(aligned_face)
    if embedding is None or len(embedding) == 0:
        raise ValueError("Failed to extract face features from image.")
    emb_list = embedding[0].tolist()
    if len(emb_list) != 128:
        raise ValueError(f"Invalid face embedding dimension: {len(emb_list)} (expected 128).")
    # Zero vector norm protection
    if np.linalg.norm(emb_list) == 0:
        raise ValueError("Extracted face embedding is a zero vector.")
    return emb_list

def check_liveness_challenge(face, challenge):
    landmarks = face[4:14]
    
    # Extract eye and nose coordinates
    left_eye_x = landmarks[0]
    right_eye_x = landmarks[2]
    nose_x = landmarks[4]
    
    face_width = right_eye_x - left_eye_x
    if face_width <= 0:
        return False
        
    center_x = (left_eye_x + right_eye_x) / 2.0
    deviation = (nose_x - center_x) / face_width
    
    # Deviation thresholds: Positive deviation means head turned left (nose shifts right relative to eyes).
    # Negative deviation means head turned right (nose shifts left relative to eyes).
    if challenge == 'LOOK_LEFT':
        return deviation > 0.12
    elif challenge == 'LOOK_RIGHT':
        return deviation < -0.12
    elif challenge == 'LOOK_STRAIGHT':
        return abs(deviation) < 0.08
    return False

def calculate_similarity(emb1, emb2):
    a = np.array(emb1)
    b = np.array(emb2)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    
    if norm_a == 0 or norm_b == 0:
        return False, 0.0, 0.363
        
    cosine_sim = np.dot(a, b) / (norm_a * norm_b)
    if np.isnan(cosine_sim) or np.isinf(cosine_sim):
        cosine_sim = 0.0
        
    threshold = 0.363 # OpenCV Zoo SFace cosine similarity threshold
    is_match = bool(cosine_sim >= threshold)
    return is_match, float(cosine_sim), threshold

# --- static assets serving ---
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_assets(path):
    return send_from_directory('static', path)

# --- Authentication API endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        firstname = data.get('firstname', '').strip()
        lastname = data.get('lastname', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm = data.get('confirm', '')
        phone = data.get('phone', '').strip()
        sex = data.get('sex', 'Male')
        address = data.get('address', '').strip()
        initial_bal = float(data.get('bal', 50000.0))

        if not username or not email or not password or not phone:
            return jsonify({"status": "error", "message": "Required fields are missing."}), 400

        if password != confirm:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"status": "error", "message": "Username already exists."}), 400

        hashed_pw = generate_password_hash(password)
        cursor.execute('''
        INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, firstname, lastname, email, hashed_pw, "", phone, sex, address, initial_bal))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Registration successful! You can now log in."})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"status": "error", "message": "Please enter both username and password."}), 400
            
        if is_login_rate_limited(username):
            return jsonify({"status": "error", "message": "Too many failed login attempts. Please wait 5 minutes."}), 429
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            stored_pw = user['PASSWORD']
            pw_ok = False
            legacy = False
            
            try:
                if check_password_hash(stored_pw, password):
                    pw_ok = True
                elif stored_pw == password:
                    pw_ok = True
                    legacy = True
            except Exception:
                if stored_pw == password:
                    pw_ok = True
                    legacy = True
                    
            if pw_ok:
                if legacy:
                    hashed = generate_password_hash(password)
                    cursor.execute("UPDATE NEWBANK SET PASSWORD = ? WHERE ID = ?", (hashed, user['ID']))
                    conn.commit()
                
                clear_login_attempts(username)
                
                session.clear()
                session['username'] = user['USERNAME']
                session['user_id'] = user['ID']
                session['is_admin'] = (user['USERNAME'].lower() == 'admin' or user['USERNAME'].lower() == 'auditor')
                
                res_user = {
                    "username": user['USERNAME'],
                    "firstname": user['FIRSTNAME'],
                    "lastname": user['LASTNAME'],
                    "email": user['EMAIL'],
                    "phone": user['PHONE'],
                    "sex": user['SEX'],
                    "address": user['ADDRESS'],
                    "balance": user['BAL'],
                    "is_admin": session['is_admin']
                }
                conn.close()
                return jsonify({
                    "status": "success",
                    "message": "Login successful!",
                    "user": res_user
                })
        
        record_login_attempt(username)
        conn.close()
        return jsonify({"status": "error", "message": "Invalid username or password."}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."})

@app.route('/api/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = ?", (session['username'],))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        balance = user['BAL'] if user['BAL'] is not None else 0.0
        return jsonify({
            "status": "success",
            "user": {
                "username": user['USERNAME'],
                "firstname": user['FIRSTNAME'],
                "lastname": user['LASTNAME'],
                "email": user['EMAIL'],
                "phone": user['PHONE'],
                "sex": user['SEX'],
                "address": user['ADDRESS'],
                "balance": balance,
                "is_admin": session.get('is_admin', False)
            }
        })
    return jsonify({"status": "error", "message": "User not found."}), 404

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        firstname = data.get('firstname', '').strip()
        lastname = data.get('lastname', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        sex = data.get('sex', 'Male')
        address = data.get('address', '').strip()

        if not firstname or not lastname or not email or not phone or not address:
            return jsonify({"status": "error", "message": "All fields are required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE NEWBANK 
        SET FIRSTNAME = ?, LASTNAME = ?, EMAIL = ?, PHONE = ?, SEX = ?, ADDRESS = ? 
        WHERE USERNAME = ?
        ''', (firstname, lastname, email, phone, sex, address, session['username']))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Profile updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = ? AND PASSWORD = ?", (session['username'], password))
        user = cursor.fetchone()
        
        if user:
            cursor.execute("DELETE FROM NEWBANK WHERE USERNAME = ?", (session['username'],))
            cursor.execute("DELETE FROM face_enrollments WHERE user_id = ?", (user['ID'],))
            conn.commit()
            conn.close()
            session.clear()
            return jsonify({"status": "success", "message": "Account successfully deleted."})
        else:
            conn.close()
            return jsonify({"status": "error", "message": "Incorrect password. Account deletion failed."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --- AI Biometric Face Verification APIs ---
@app.route('/api/biometric/status', methods=['GET'])
def biometric_status():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    user_id = session['user_id']
    cursor.execute("SELECT enrolled_at, status FROM face_enrollments WHERE user_id = ?", (user_id,))
    enrollment = cursor.fetchone()
    
    # Query failed verification attempts
    cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = ? AND verification_result != 'SUCCESS'", (user_id,))
    failed_attempts = cursor.fetchone()[0]
    
    conn.close()
    
    if enrollment:
        return jsonify({
            "status": "success",
            "enrolled": True,
            "enrolled_at": enrollment['enrolled_at'],
            "profile_status": enrollment['status'],
            "failed_attempts": failed_attempts
        })
    else:
        return jsonify({
            "status": "success",
            "enrolled": False,
            "failed_attempts": failed_attempts
        })

@app.route('/api/biometric/enroll', methods=['POST'])
def biometric_enroll():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        images = data.get('images', []) # Expects list of 3 base64 image strings
        
        if len(images) < 3:
            return jsonify({"status": "error", "message": "Face enrollment requires exactly 3 different face samples."}), 400
            
        embeddings = []
        for idx, img_b64 in enumerate(images):
            img = decode_base64_image(img_b64)
            q_check = validate_face_quality(img)
            
            if q_check['status'] == 'error':
                return jsonify({"status": "error", "message": f"Sample {idx+1} Quality Error: {q_check['message']}"}), 400
                
            # Extract SFace aligned embedding
            face = q_check['face']
            emb = extract_face_embedding(img, face)
            embeddings.append(emb)
            
        # Calculate the robust averaged template embedding of size 128
        avg_embedding = np.mean(embeddings, axis=0).tolist()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session['user_id']
        
        cursor.execute('''
        INSERT OR REPLACE INTO face_enrollments (user_id, template_reference, model_name, model_version, status, enrolled_at)
        VALUES (?, ?, 'SFace', '1.0', 'ACTIVE', CURRENT_TIMESTAMP)
        ''', (user_id, json.dumps(avg_embedding)))
        
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (?, 'ENROLLMENT_CREATED', 'LOW', 'User created new Face template')
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Face profile enrolled successfully! Biometric protection active."})
    except ValueError as ve:
        if 'conn' in locals() and conn:
            try: conn.close()
            except: pass
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        traceback.print_exc()
        if 'conn' in locals() and conn:
            try: conn.close()
            except: pass
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/biometric/delete', methods=['POST'])
def biometric_delete():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session['user_id']
        
        cursor.execute("DELETE FROM face_enrollments WHERE user_id = ?", (user_id,))
        
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (?, 'ENROLLMENT_DELETED', 'MEDIUM', 'User revoked/purged biometric data profile')
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Biometric face profile deleted and revoked."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/biometric/verify/initiate', methods=['POST'])
def biometric_verify_initiate():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    challenges = ['LOOK_LEFT', 'LOOK_RIGHT', 'LOOK_STRAIGHT']
    challenge = random.choice(challenges)
    
    session['liveness_challenge'] = challenge
    return jsonify({"status": "success", "challenge": challenge})

@app.route('/api/biometric/verify/check', methods=['POST'])
def biometric_verify_check():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    challenge = session.get('liveness_challenge')
    if not challenge:
        return jsonify({"status": "error", "message": "Liveness challenge not initiated."}), 400
        
    try:
        data = request.get_json()
        img_b64 = data.get('image', '')
        
        if not img_b64:
            return jsonify({"status": "error", "message": "Webcam frame missing."}), 400
            
        img = decode_base64_image(img_b64)
        
        # 1. Image Quality verification
        q_check = validate_face_quality(img)
        user_id = session['user_id']
        
        if q_check['status'] == 'error':
            # Log error verification attempt
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO face_verification_attempts (user_id, verification_result, liveness_result, challenge_type, model_version)
            VALUES (?, 'ERROR', ?, ?, '1.0')
            ''', (user_id, q_check['message'], challenge))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": q_check['message']}), 400
            
        face = q_check['face']
        
        # 2. Challenge-Response Liveness Detection Check
        liveness_ok = check_liveness_challenge(face, challenge)
        if not liveness_ok:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO face_verification_attempts (user_id, verification_result, liveness_result, challenge_type, model_version)
            VALUES (?, 'LIVENESS_FAILED', 'Failed head turn', ?, '1.0')
            ''', (user_id, challenge))
            
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (?, 'LIVENESS_FAILURE', 'MEDIUM', ?)
            ''', (user_id, f"Failed challenge: {challenge}"))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                "status": "liveness_failed",
                "message": f"Liveness action failed. Please look and turn your head in the correct direction: {challenge.replace('_', ' ')}"
            }), 400
            
        # 3. 1:1 Face Similarity Match against stored profile
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT template_reference FROM face_enrollments WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({"status": "no_enrollment", "message": "Biometric face profile not found for this account."}), 404
            
        stored_emb = json.loads(row['template_reference'])
        current_emb = extract_face_embedding(img, face)
        
        is_match, similarity, threshold = calculate_similarity(stored_emb, current_emb)
        
        # Clear challenge once check finishes
        session.pop('liveness_challenge', None)
        
        # Log attempts
        result_str = 'SUCCESS' if is_match else 'MISMATCH'
        cursor.execute('''
        INSERT INTO face_verification_attempts (user_id, verification_result, similarity_or_distance, threshold, liveness_result, challenge_type, model_version)
        VALUES (?, ?, ?, ?, 'PASSED', ?, '1.0')
        ''', (user_id, result_str, similarity, threshold, challenge))
        
        if is_match:
            # Mark biometrics verified in the pending transfer transaction if exists
            token = session.get('mfa_pending_token')
            if token:
                cursor.execute("UPDATE pending_transactions SET face_verified = 1 WHERE token = ?", (token,))
                
            cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = ? AND verification_result = 'SUCCESS'", (user_id,))
            attempts_row = cursor.fetchone()
            
            # Auto-finalize transaction if OTP was already verified
            token = session.get('mfa_pending_token')
            otp_already_verified = False
            if token:
                cursor.execute("SELECT otp_verified FROM pending_transactions WHERE token = ?", (token,))
                ptx = cursor.fetchone()
                if ptx and ptx['otp_verified']:
                    otp_already_verified = True
            
            conn.commit()
            conn.close()
            
            if otp_already_verified:
                return finalize_pending_transaction(token)
                
            return jsonify({
                "status": "success",
                "message": "Face verified successfully! Liveness matching passed.",
                "similarity": round(similarity * 100, 2)
            })
        else:
            # Log security event
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (?, 'FACE_MISMATCH', 'HIGH', ?)
            ''', (user_id, f"Similarity: {similarity:.4f} below threshold: {threshold:.4f}"))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                "status": "mismatch",
                "message": "Biometric verification failed. Face does not match the enrolled owner.",
                "similarity": round(similarity * 100, 2),
                "threshold": threshold
            }), 400
            
    except ValueError as ve:
        if 'conn' in locals() and conn:
            try: conn.close()
            except: pass
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        traceback.print_exc()
        if 'conn' in locals() and conn:
            try: conn.close()
            except: pass
        return jsonify({"status": "error", "message": str(e)}), 500


# --- Hybrid Risk Score Engine ---
def compute_hybrid_risk(sender_id, sender_username, receiver, amount, ttype):
    # Base risk is 10
    risk_score = 10
    reasons = []
    
    amount_points = 0
    # 1. Rule-Based checks: Amount
    if amount <= 10000:
        amount_points = 5
        risk_score += 5
        reasons.append("Standard Amount (under ₹10k)")
    elif 10000 < amount <= 100000:
        amount_points = 20
        risk_score += 20
        reasons.append("Medium Volume Transaction (₹10k to ₹100k)")
    elif 100000 < amount <= 500000:
        amount_points = 40
        risk_score += 40
        reasons.append("High Volume Transaction (₹100k to ₹500k)")
    else:
        amount_points = 60
        risk_score += 60
        reasons.append("Critical Volume Transaction (above ₹500k)")
        
    # Check if empty account pattern: amount is > 85% of sender's balance
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (sender_username,))
    sender_bal_row = cursor.fetchone()
    sender_bal = sender_bal_row['BAL'] if sender_bal_row else 0.0
    
    empty_account_points = 0
    if sender_bal > 0 and (amount / sender_bal) > 0.85:
        empty_account_points = 25
        risk_score += 25
        reasons.append("Account Emptying Anomaly (Transferring >85% of liquid balance)")
        
    # Check if beneficiary is a new recipient
    cursor.execute("SELECT COUNT(*) FROM NEWT WHERE SENDER = ? AND RECEIVER = ? AND STATUS = 'APPROVED'", (sender_username, receiver))
    recipient_history = cursor.fetchone()[0]
    new_recipient_points = 0
    if recipient_history == 0:
        new_recipient_points = 15
        risk_score += 15
        reasons.append("New Unverified Beneficiary Target")
        
    # 2. Supervised ML prediction: Random Forest Model
    is_fraud_predicted = 0
    ml_model_points = 0
    ml_probability = 0.0
    if model is not None:
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
        receiver_bal_row = cursor.fetchone()
        receiver_bal = receiver_bal_row['BAL'] if receiver_bal_row else 0.0
        
        df_pred = pd.DataFrame([{
            'type': ttype,
            'amount': amount,
            'oldbalanceOrig': sender_bal,
            'newbalanceOrig': sender_bal - amount,
            'oldbalanceDest': receiver_bal,
            'newbalanceDest': receiver_bal + amount
        }])
        try:
            pred = model.predict(df_pred)[0]
            is_fraud_predicted = int(pred)
            
            # Exact prediction probability
            probs = model.predict_proba(df_pred)[0]
            ml_probability = float(probs[1])
            
            if is_fraud_predicted == 1:
                ml_model_points = 50
                risk_score += 50
                reasons.append("Random Forest Flag: Matches synthetic PaySim fraud profile splits")
        except:
            pass
            
    # 3. Behavior Velocity: Transaction count inside 5 minutes
    cursor.execute("SELECT COUNT(*) FROM NEWT WHERE SENDER = ? AND TIMESTAMP >= datetime('now', '-5 minutes')", (sender_username,))
    recent_transfers = cursor.fetchone()[0]
    velocity_points = 0
    if recent_transfers >= 3:
        velocity_points = 25
        risk_score += 25
        reasons.append("Velocity Anomaly: Extreme transactional frequency (>= 3 in 5 min)")
    elif recent_transfers > 0:
        velocity_points = 10
        risk_score += 10
        reasons.append("Rapid Velocity: Multiple transfers in last 5 minutes")
        
    # 4. Biometric signals: Failures in last 15 minutes
    cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = ? AND verification_result != 'SUCCESS' AND attempted_at >= datetime('now', '-15 minutes')", (sender_id,))
    recent_biometric_fails = cursor.fetchone()[0]
    biometric_points = 0
    if recent_biometric_fails > 0:
        biometric_points = 25 * recent_biometric_fails
        risk_score += biometric_points
        reasons.append(f"Biometric Failure Warning: {recent_biometric_fails} failed face/liveness attempts recently")
        
    conn.close()
    
    # Cap risk score at 100
    risk_score = min(100, risk_score)
    
    # Determine risk level
    if risk_score < 45:
        risk_level = 'LOW'
    elif 45 <= risk_score < 70:
        risk_level = 'MEDIUM'
    elif 70 <= risk_score < 90:
        risk_level = 'HIGH'
    else:
        risk_level = 'CRITICAL'
        
    breakdown = {
        "base_points": 10,
        "amount_points": amount_points,
        "empty_account_points": empty_account_points,
        "new_recipient_points": new_recipient_points,
        "ml_model_points": ml_model_points,
        "velocity_points": velocity_points,
        "biometric_points": biometric_points
    }
    
    return risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability

# --- Transaction API endpoints ---
@app.route('/api/transfer/initiate', methods=['POST'])
def transfer_initiate():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload."}), 400
            
        receiver = data.get('receiver', '').strip()
        amount_str = data.get('amount', '0')
        ttype = data.get('type', 'TRANSFER').strip().upper()
        
        try:
            amount = float(amount_str)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid transfer amount format."}), 400
            
        if amount <= 0:
            return jsonify({"status": "error", "message": "Transfer amount must be greater than zero."}), 400
            
        sender = session['username']
        sender_id = session.get('user_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check transaction type
        if ttype not in ['TRANSFER', 'CASH_OUT']:
            conn.close()
            return jsonify({"status": "error", "message": "Invalid transaction type."}), 400
            
        # Check receiver exists based on transaction type
        if ttype == 'TRANSFER':
            cursor.execute("SELECT ID, BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
            receiver_row = cursor.fetchone()
            if not receiver_row:
                conn.close()
                return jsonify({"status": "error", "message": "Receiver username not found."}), 404
            if receiver == sender:
                conn.close()
                return jsonify({"status": "error", "message": "Cannot transfer to yourself."}), 400
        else: # CASH_OUT
            cursor.execute("SELECT * FROM cash_out_channels WHERE id = ? AND status = 'ACTIVE'", (receiver,))
            channel_row = cursor.fetchone()
            if not channel_row:
                conn.close()
                return jsonify({"status": "error", "message": "Invalid or inactive cash out channel."}), 400
            if receiver == sender:
                conn.close()
                return jsonify({"status": "error", "message": "Cannot cash out to yourself."}), 400
            receiver_row = {'BAL': 0.0}
            
        # Get sender details
        cursor.execute("SELECT BAL, EMAIL FROM NEWBANK WHERE USERNAME = ?", (sender,))
        sender_row = cursor.fetchone()
        sender_balance = sender_row['BAL']
        sender_email = sender_row['EMAIL']
        
        if sender_balance < amount:
            conn.close()
            return jsonify({"status": "error", "message": "Insufficient balance."}), 400
            
        # Run Hybrid Risk Engine
        risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability = compute_hybrid_risk(
            sender_id, sender, receiver, amount, ttype
        )
        
        # Prepare decision trace
        feature_importances = {}
        if model is not None:
            try:
                preprocessor = model.named_steps['preprocessor']
                cat_encoder = preprocessor.named_transformers_['cat']
                cat_features = list(cat_encoder.get_feature_names_out(['type']))
                feature_names = ['amount', 'oldbalanceOrig', 'newbalanceOrig', 'oldbalanceDest', 'newbalanceDest'] + cat_features
                classifier = model.named_steps['classifier']
                importances = list(classifier.feature_importances_)
                feature_importances = dict(zip(feature_names, importances))
            except:
                pass
                
        decision_trace = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "breakdown": breakdown,
            "ml_probability": ml_probability,
            "feature_importances": feature_importances,
            "auth_required": [],
            "auth_completed": []
        }
        
        if risk_level == 'MEDIUM':
            decision_trace['auth_required'] = ['otp']
        elif risk_level == 'HIGH':
            decision_trace['auth_required'] = ['otp', 'face']
        elif risk_level == 'CRITICAL':
            decision_trace['auth_required'] = ['admin_review']
            
        # Check if user has biometric face profile enrolled
        cursor.execute("SELECT id FROM face_enrollments WHERE user_id = ?", (sender_id,))
        has_face_enrolled = (cursor.fetchone() is not None)
        
        # Enforce enrollment requirement for HIGH risk
        if risk_level == 'HIGH' and not has_face_enrolled:
            conn.close()
            return jsonify({
                "status": "error",
                "message": "Biometric face enrollment is required to verify high-risk transactions. Please enroll your face first."
            }), 400
            
        # Generate token
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        
        # LOW RISK: Auto approve
        if risk_level == 'LOW':
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, otp_verified, face_verified, expires_at, decision_trace)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
            ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))
            conn.commit()
            
            res = finalize_pending_transaction(token)
            conn.close()
            return res
            
        # CRITICAL RISK: Queue for Admin Review
        if risk_level == 'CRITICAL':
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, expires_at, status, decision_trace)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW', ?)
            ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))
            
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (?, 'TRANSACTION_HELD_FOR_REVIEW', 'HIGH', ?)
            ''', (sender_id, f"Transaction {amount} to {receiver} held for admin review due to CRITICAL risk score {risk_score}."))
            
            tx_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            tx_event = {
                'id': tx_id,
                'sender': sender[0] + '***' + sender[-1] if len(sender) > 1 else sender,
                'receiver': receiver[0] + '***' + receiver[-1] if len(receiver) > 1 else receiver,
                'ttype': ttype,
                'amount': amount,
                'status': 'PENDING_REVIEW',
                'risk_score': risk_score,
                'risk_level': risk_level,
                'reasons': reasons,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            socketio.emit('new_transaction', tx_event, to='admin_room')
            
            return jsonify({
                "status": "pending_review",
                "message": "Security Alert: This transaction exhibits CRITICAL risk indicators. It has been queued for Administrator Review. No funds will move until approved.",
                "transaction_token": token,
                "score": risk_score,
                "level": risk_level,
                "reasons": reasons
            })
            
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hashed = hash_otp(otp)
        
        # Save pending transaction to DB
        cursor.execute('''
        INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, expires_at, decision_trace)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))
        
        # Save OTP challenge
        cursor.execute('''
        INSERT INTO transaction_otp_challenges (user_id, transaction_token, otp_hash, expires_at, last_sent_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ''', (sender_id, token, otp_hashed, expires_at))
        
        conn.commit()
        conn.close()
        
        if not sender_email:
            sender_email = f"{sender}@smartbanking.com"
            
        send_otp_email(sender_email, otp, amount, receiver)
        
        parts = sender_email.split('@')
        name = parts[0]
        domain = parts[1]
        if len(name) > 2:
            masked_name = name[0] + '*' * (len(name) - 2) + name[-1]
        else:
            masked_name = name[0] + '*'
        masked_email = f"{masked_name}@{domain}"
        
        required_auths = ["otp"]
        if risk_level == 'HIGH':
            required_auths.append("face")
            
        return jsonify({
            "status": "verification_required",
            "required": required_auths,
            "transaction_token": token,
            "masked_email": masked_email,
            "expires_in": 300,
            "score": risk_score,
            "level": risk_level,
            "reasons": reasons
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/transfer/verify', methods=['POST'])
def transfer_verify():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload."}), 400
            
        token = data.get('transaction_token', '').strip()
        otp = data.get('otp', '').strip()
        
        if not token or not otp:
            return jsonify({"status": "error", "message": "Transaction token and OTP code are required."}), 400
            
        if not otp.isdigit() or len(otp) != 6:
            return jsonify({"status": "error", "message": "OTP must be exactly 6 numeric digits."}), 400
            
        user_id = session['user_id']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM transaction_otp_challenges 
        WHERE transaction_token = ? AND user_id = ?
        ''', (token, user_id))
        challenge = cursor.fetchone()
        
        if not challenge:
            conn.close()
            return jsonify({"status": "error", "message": "Verification challenge not found."}), 404
            
        utc_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if challenge['expires_at'] < utc_now or challenge['consumed'] or challenge['verified']:
            conn.close()
            return jsonify({"status": "error", "message": "Verification challenge has expired or already been consumed."}), 400
            
        if challenge['attempts'] >= challenge['max_attempts']:
            conn.close()
            return jsonify({"status": "error", "message": "Maximum verification attempts exceeded. Please start a new transaction."}), 400
            
        is_valid = verify_otp_hmac(otp, challenge['otp_hash'])
        
        if not is_valid:
            new_attempts = challenge['attempts'] + 1
            cursor.execute('''
            UPDATE transaction_otp_challenges 
            SET attempts = ? 
            WHERE id = ?
            ''', (new_attempts, challenge['id']))
            conn.commit()
            
            remaining = challenge['max_attempts'] - new_attempts
            conn.close()
            if remaining <= 0:
                return jsonify({"status": "error", "message": "Maximum verification attempts exceeded. Locked."}), 400
            else:
                return jsonify({"status": "error", "message": f"Incorrect code. {remaining} attempts remaining."}), 400
                
        cursor.execute('''
        UPDATE transaction_otp_challenges 
        SET verified = 1, verified_at = datetime('now') 
        WHERE id = ?
        ''', (challenge['id'],))
        
        cursor.execute('''
        UPDATE pending_transactions 
        SET otp_verified = 1 
        WHERE token = ?
        ''', (token,))
        
        cursor.execute("SELECT risk_level FROM pending_transactions WHERE token = ?", (token,))
        pending_row = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
        if pending_row['risk_level'] == 'MEDIUM':
            return finalize_pending_transaction(token)
            
        session['mfa_pending_token'] = token
        return jsonify({
            "status": "otp_ok_need_face",
            "message": "OTP verified successfully. Please proceed to the face liveness check."
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/otp/resend', methods=['POST'])
def otp_resend():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload."}), 400
            
        token = data.get('transaction_token', '').strip()
        if not token:
            return jsonify({"status": "error", "message": "Transaction token is required."}), 400
            
        user_id = session['user_id']
        username = session['username']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM transaction_otp_challenges 
        WHERE transaction_token = ? AND user_id = ?
        ''', (token, user_id))
        challenge = cursor.fetchone()
        
        if not challenge:
            conn.close()
            return jsonify({"status": "error", "message": "Verification challenge not found."}), 404
            
        if challenge['consumed'] or challenge['verified']:
            conn.close()
            return jsonify({"status": "error", "message": "Challenge is already verified or consumed."}), 400
            
        if challenge['resend_count'] >= 3:
            conn.close()
            return jsonify({"status": "error", "message": "Maximum OTP resend limit (3) exceeded. Please restart the transaction."}), 400
            
        last_sent_str = challenge['last_sent_at']
        if last_sent_str:
            try:
                cursor.execute('''
                SELECT (strftime('%s', 'now') - strftime('%s', ?)) AS diff
                ''', (last_sent_str,))
                diff_row = cursor.fetchone()
                diff = diff_row['diff'] if diff_row else 999
                
                if diff is not None and diff < 60:
                    conn.close()
                    return jsonify({"status": "error", "message": f"Please wait {60 - int(diff)} seconds before resending."}), 400
            except Exception as ex:
                pass
                
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hashed = hash_otp(otp)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
        UPDATE transaction_otp_challenges 
        SET otp_hash = ?, expires_at = ?, last_sent_at = datetime('now'), resend_count = resend_count + 1, attempts = 0
        WHERE id = ?
        ''', (otp_hashed, expires_at, challenge['id']))
        
        cursor.execute('''
        UPDATE pending_transactions 
        SET expires_at = ? 
        WHERE token = ?
        ''', (expires_at, token))
        
        cursor.execute("SELECT EMAIL FROM NEWBANK WHERE ID = ?", (user_id,))
        email = cursor.fetchone()['EMAIL']
        if not email:
            email = f"{username}@smartbanking.com"
            
        cursor.execute("SELECT amount, receiver FROM pending_transactions WHERE token = ?", (token,))
        pending_tx = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
        send_otp_email(email, otp, pending_tx['amount'], pending_tx['receiver'])
        
        return jsonify({
            "status": "success",
            "message": "A new verification code has been sent to your email.",
            "expires_in": 300
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

def finalize_pending_transaction(token):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("BEGIN TRANSACTION")
        
        cursor.execute("SELECT * FROM pending_transactions WHERE token = ?", (token,))
        pending = cursor.fetchone()
        
        if not pending:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Pending transaction details not found."}), 404
            
        if pending['status'] != 'PENDING':
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Transaction has already been processed or expired."}), 400
            
        utc_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if pending['expires_at'] < utc_now:
            cursor.execute("UPDATE pending_transactions SET status = 'EXPIRED' WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": "Transaction verification window has expired."}), 400
            
        # Verification checks based on risk level
        if not pending['otp_verified']:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "OTP verification required."}), 400
            
        if pending['risk_level'] == 'HIGH' and not pending['face_verified']:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Biometric face verification required."}), 400
            
        sender_id = pending['user_id']
        receiver = pending['receiver']
        amount = pending['amount']
        ttype = pending['ttype']
        is_fraud_predicted = pending['is_fraud_predicted']
        
        cursor.execute("SELECT USERNAME, BAL FROM NEWBANK WHERE ID = ?", (sender_id,))
        sender_row = cursor.fetchone()
        sender = sender_row['USERNAME']
        sender_bal = sender_row['BAL']
        
        if ttype == 'TRANSFER':
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
            receiver_row = cursor.fetchone()
            receiver_bal = receiver_row['BAL']
            receiver_new_bal = receiver_bal + amount
        else: # CASH_OUT
            receiver_bal = 0.0
            receiver_new_bal = 0.0
            
        if sender_bal < amount:
            cursor.execute("UPDATE pending_transactions SET status = 'FAILED' WHERE token = ?", (token,))
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Insufficient balance at finalization."}), 400
            
        sender_new_bal = sender_bal - amount
        
        cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE ID = ?", (sender_new_bal, sender_id))
        if ttype == 'TRANSFER':
            cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE USERNAME = ?", (receiver_new_bal, receiver))
            
        cursor.execute("UPDATE pending_transactions SET status = 'COMPLETED' WHERE token = ?", (token,))
        
        cursor.execute('''
        UPDATE transaction_otp_challenges 
        SET consumed = 1, consumed_at = datetime('now') 
        WHERE transaction_token = ?
        ''', (token,))
        
        decision_trace = json.loads(pending['decision_trace'])
        auth_completed = []
        if pending['otp_verified']:
            auth_completed.append('otp')
        if pending['face_verified']:
            auth_completed.append('face')
        decision_trace['auth_completed'] = auth_completed
        
        cursor.execute('''
        INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
        ''', (sender, receiver, ttype, amount, sender_bal, sender_new_bal, receiver_bal, receiver_new_bal, is_fraud_predicted, json.dumps(decision_trace)))
        
        tx_id = cursor.lastrowid
        
        tx_event = {
            'id': tx_id,
            'sender': sender[0] + '***' + sender[-1] if len(sender) > 1 else sender,
            'receiver': receiver[0] + '***' + receiver[-1] if len(receiver) > 1 else receiver,
            'ttype': ttype,
            'amount': amount,
            'status': 'APPROVED',
            'risk_score': pending['risk_score'],
            'risk_level': pending['risk_level'],
            'reasons': json.loads(pending['reasons']),
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        socketio.emit('new_transaction', tx_event, to='admin_room')
        
        conn.commit()
        conn.close()
        
        session.pop('mfa_pending_token', None)
        
        return jsonify({
            "status": "success",
            "message": "Transfer completed successfully.",
            "new_balance": sender_new_bal
        })
        
    except Exception as e:
        traceback.print_exc()
        if conn:
            try:
                cursor.execute("ROLLBACK")
            except:
                pass
            conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
def get_user_transactions():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM NEWT 
    WHERE SENDER = ? OR RECEIVER = ? 
    ORDER BY TIMESTAMP DESC 
    LIMIT 50
    ''', (session['username'], session['username']))
    rows = cursor.fetchall()
    conn.close()

    txs = []
    for row in rows:
        txs.append({
            "id": row['ID'],
            "sender": row['SENDER'],
            "receiver": row['RECEIVER'],
            "type": row['TTYPE'],
            "amount": row['AMOUNT'],
            "sender_old_bal": row['SENDEROLDBAL'],
            "sender_new_bal": row['SENDERNEWBAL'],
            "rec_old_bal": row['RECOLDBAL'],
            "rec_new_bal": row['RECNEWBAL'],
            "status": row['STATUS'],
            "timestamp": row['TIMESTAMP'],
            "is_fraud": bool(row['IS_FRAUD_PREDICTED'])
        })
    
    return jsonify({"status": "success", "transactions": txs})


# --- Diagnostics & Explanation endpoints ---
@app.route('/api/model/metrics', methods=['GET'])
def get_model_metrics():
    if not os.path.exists(METRICS_PATH):
        return jsonify({
            "status": "inactive",
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "confusion_matrix": [[0,0],[0,0]],
            "n_samples": 0,
            "fraud_percentage": 0.0
        })
    
    with open(METRICS_PATH, 'r') as f:
        metrics = json.load(f)
    return jsonify(metrics)

@app.route('/api/model/explain', methods=['POST'])
def explain_transaction():
    try:
        data = request.get_json()
        ttype = data.get('type', 'TRANSFER')
        amount = float(data.get('amount', 0))
        oldbalanceOrig = float(data.get('oldbalanceOrig', 0))
        newbalanceOrig = float(data.get('newbalanceOrig', 0))
        oldbalanceDest = float(data.get('oldbalanceDest', 0))
        newbalanceDest = float(data.get('newbalanceDest', 0))
        
        df_pred = pd.DataFrame([{
            'type': ttype,
            'amount': amount,
            'oldbalanceOrig': oldbalanceOrig,
            'newbalanceOrig': newbalanceOrig,
            'oldbalanceDest': oldbalanceDest,
            'newbalanceDest': newbalanceDest
        }])
        
        is_fraud = 0
        proba_fraud = 0.05
        
        if model is not None:
            pred = model.predict(df_pred)[0]
            is_fraud = int(pred)
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(df_pred)[0]
                proba_fraud = float(proba[1])
        else:
            if abs(amount - oldbalanceOrig) < 0.01 or amount > 250000:
                is_fraud = 1
                proba_fraud = 0.95

        # Decision reasons
        reasons = []
        if is_fraud == 1:
            if abs(amount - oldbalanceOrig) < 0.01:
                reasons.append("Account Emptying Pattern: The transaction amount matches the entire balance, dropping the balance to zero.")
            if amount > 200000:
                reasons.append(f"High-Volume Exception: The amount ({amount:,.2f}) is significantly above standard transfer limits.")
            if oldbalanceDest == 0 and newbalanceDest == 0:
                reasons.append("Zero Destination Trace: Destination account balance remains zero, indicating instant cashout.")
            if len(reasons) == 0:
                reasons.append("Anomalous Multi-feature Correlation: Slices in Random Forest estimator matched complex fraud trees.")
        else:
            reasons.append("Standard Operating Parameters: Transaction matches normal client liquidity boundaries.")
            
        return jsonify({
            "is_fraud": bool(is_fraud),
            "probability": round(proba_fraud * 100, 2),
            "reasons": reasons
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized. Admin permissions required."}), 403
    
    try:
        import train_model
        train_model.train_and_save()
        load_ml_model()
        return jsonify({"status": "success", "message": "Model retrained successfully on updated data logs."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --- Admin Review and Diagnostics Endpoints ---
@app.route('/api/admin/biometric/diagnostics', methods=['GET'])
def biometric_diagnostics():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    yunet_path = os.path.join('models', 'face_detection_yunet_2023mar.onnx')
    sface_path = os.path.join('models', 'face_recognition_sface_2021dec.onnx')
    
    return jsonify({
        "status": "success",
        "detector_loaded": face_detector is not None,
        "recognizer_loaded": face_recognizer is not None,
        "detector_model_filename": os.path.basename(yunet_path) if os.path.exists(yunet_path) else "missing",
        "recognizer_model_filename": os.path.basename(sface_path) if os.path.exists(sface_path) else "missing",
        "detector_model_exists": os.path.exists(yunet_path),
        "recognizer_model_exists": os.path.exists(sface_path)
    })

@app.route('/api/admin/reviews', methods=['GET'])
def admin_get_reviews():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_transactions WHERE status = 'PENDING_REVIEW'")
    rows = cursor.fetchall()
    conn.close()
    
    reviews = []
    for r in rows:
        reviews.append({
            "token": r['token'],
            "user_id": r['user_id'],
            "receiver": r['receiver'],
            "amount": r['amount'],
            "ttype": r['ttype'],
            "risk_score": r['risk_score'],
            "risk_level": r['risk_level'],
            "reasons": json.loads(r['reasons']),
            "expires_at": r['expires_at']
        })
    return jsonify({"status": "success", "reviews": reviews})

@app.route('/api/admin/review/action', methods=['POST'])
def admin_review_action():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Missing request payload."}), 400
        
    token = data.get('transaction_token')
    action = data.get('action') # 'APPROVE' or 'REJECT'
    reason = data.get('reason', '').strip()
    reviewer = session['username']
    
    if not token or action not in ['APPROVE', 'REJECT']:
        return jsonify({"status": "error", "message": "Invalid review parameters."}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Atomic transaction
        cursor.execute("BEGIN TRANSACTION")
        
        # Check current status is strictly PENDING_REVIEW
        cursor.execute("SELECT * FROM pending_transactions WHERE token = ? AND status = 'PENDING_REVIEW'", (token,))
        pending = cursor.fetchone()
        
        if not pending:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Transaction not found, expired, or already reviewed."}), 404
            
        sender_id = pending['user_id']
        receiver = pending['receiver']
        amount = pending['amount']
        ttype = pending['ttype']
        risk_score = pending['risk_score']
        risk_level = pending['risk_level']
        reasons = json.loads(pending['reasons']) if pending['reasons'] else []
        
        cursor.execute("SELECT USERNAME, BAL FROM NEWBANK WHERE ID = ?", (sender_id,))
        sender_row = cursor.fetchone()
        sender_username = sender_row['USERNAME'] if sender_row else None
        sender_bal = sender_row['BAL'] if sender_row else 0.0
        
        # Enforce idempotency - conditional status update
        target_status = 'COMPLETED' if action == 'APPROVE' else 'BLOCKED'
        cursor.execute("UPDATE pending_transactions SET status = ? WHERE token = ? AND status = 'PENDING_REVIEW'", (target_status, token))
        
        if cursor.rowcount == 0:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Concurrency error: Transaction already processed."}), 409
            
        if action == 'APPROVE':
            # Recheck balance inside the same SQLite atomic transaction
            if sender_bal < amount:
                cursor.execute("UPDATE pending_transactions SET status = 'FAILED' WHERE token = ?", (token,))
                cursor.execute("COMMIT")
                conn.close()
                return jsonify({"status": "error", "message": "Insufficient balance for approval."}), 400
                
            sender_new_bal = sender_bal - amount
            
            # Check receiver account type (CASH_OUT channel vs TRANSFER user)
            if ttype == 'TRANSFER':
                cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
                receiver_row = cursor.fetchone()
                receiver_bal = receiver_row['BAL'] if receiver_row else 0.0
                receiver_new_bal = receiver_bal + amount
                cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE USERNAME = ?", (receiver_new_bal, receiver))
            else: # CASH_OUT
                # CASH_OUT destination channel
                receiver_bal = 0.0
                receiver_new_bal = 0.0
                
            cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE ID = ?", (sender_new_bal, sender_id))
            
            # Record decision trace
            decision_trace = json.loads(pending['decision_trace'])
            decision_trace['reviewer'] = reviewer
            decision_trace['review_action'] = 'APPROVED'
            decision_trace['review_reason'] = reason
            decision_trace['review_timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create ledger entry exactly once
            cursor.execute('''
            INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
            ''', (sender_username, receiver, ttype, amount, sender_bal, sender_new_bal, receiver_bal, receiver_new_bal, pending['is_fraud_predicted'], json.dumps(decision_trace)))
            
            tx_id = cursor.lastrowid
            
            # Create audit record exactly once
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (?, 'TRANSACTION_APPROVED_BY_ADMIN', 'MEDIUM', ?)
            ''', (sender_id, f"Admin approved transaction {amount} to {receiver}. Reason: {reason}"))
            
            # Send Socket.IO notifications
            tx_event = {
                'id': tx_id,
                'sender': sender_username[0] + '***' + sender_username[-1] if len(sender_username) > 1 else sender_username,
                'receiver': receiver[0] + '***' + receiver[-1] if len(receiver) > 1 else receiver,
                'ttype': ttype,
                'amount': amount,
                'status': 'APPROVED',
                'risk_score': risk_score,
                'risk_level': risk_level,
                'reasons': reasons,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            socketio.emit('new_transaction', tx_event, to='admin_room')
            
        else: # REJECT
            # Record decision trace
            decision_trace = json.loads(pending['decision_trace'])
            decision_trace['reviewer'] = reviewer
            decision_trace['review_action'] = 'REJECTED'
            decision_trace['review_reason'] = reason
            decision_trace['review_timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create ledger entry exactly once (mark as BLOCKED)
            cursor.execute('''
            INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'BLOCKED', ?, ?)
            ''', (sender_username, receiver, ttype, amount, sender_bal, sender_bal, 0.0, 0.0, pending['is_fraud_predicted'], json.dumps(decision_trace)))
            
            tx_id = cursor.lastrowid
            
            # Create audit record exactly once
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (?, 'TRANSACTION_REJECTED_BY_ADMIN', 'HIGH', ?)
            ''', (sender_id, f"Admin rejected transaction {amount} to {receiver}. Reason: {reason}"))
            
            tx_event = {
                'id': tx_id,
                'sender': sender_username[0] + '***' + sender_username[-1] if len(sender_username) > 1 else sender_username,
                'receiver': receiver[0] + '***' + receiver[-1] if len(receiver) > 1 else receiver,
                'ttype': ttype,
                'amount': amount,
                'status': 'BLOCKED',
                'risk_score': risk_score,
                'risk_level': risk_level,
                'reasons': reasons,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            socketio.emit('new_transaction', tx_event, to='admin_room')
            
        cursor.execute("COMMIT")
        conn.close()
        return jsonify({"status": "success", "message": f"Transaction successfully {action.lower()}ed."})
        
    except Exception as e:
        traceback.print_exc()
        try:
            cursor.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Admin Audit endpoints ---
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ID, USERNAME, FIRSTNAME, LASTNAME, EMAIL, PHONE, SEX, ADDRESS, BAL FROM NEWBANK")
    rows = cursor.fetchall()
    conn.close()
    
    users = []
    for row in rows:
        users.append({
            "id": row['ID'],
            "username": row['USERNAME'],
            "name": f"{row['FIRSTNAME']} {row['LASTNAME']}",
            "email": row['EMAIL'],
            "phone": row['PHONE'],
            "sex": row['SEX'],
            "address": row['ADDRESS'],
            "balance": row['BAL'] if row['BAL'] is not None else 0.0
        })
    return jsonify({"status": "success", "users": users})

@app.route('/api/admin/transactions', methods=['GET'])
def admin_get_transactions():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM NEWT ORDER BY TIMESTAMP DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    
    txs = []
    for row in rows:
        txs.append({
            "id": row['ID'],
            "sender": row['SENDER'],
            "receiver": row['RECEIVER'],
            "type": row['TTYPE'],
            "amount": row['AMOUNT'],
            "sender_old_bal": row['SENDEROLDBAL'],
            "sender_new_bal": row['SENDERNEWBAL'],
            "rec_old_bal": row['RECOLDBAL'],
            "rec_new_bal": row['RECNEWBAL'],
            "status": row['STATUS'],
            "timestamp": row['TIMESTAMP'],
            "is_fraud": bool(row['IS_FRAUD_PREDICTED'])
        })
    return jsonify({"status": "success", "transactions": txs})

@app.route('/api/admin/biometric_events', methods=['GET'])
def admin_get_biometric_events():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT e.id, u.USERNAME, e.event_type, e.severity, e.created_at, e.metadata 
    FROM biometric_security_events e
    LEFT JOIN NEWBANK u ON e.user_id = u.ID
    ORDER BY e.created_at DESC 
    LIMIT 100
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for r in rows:
        events.append({
            "id": r['id'],
            "username": r['USERNAME'] if r['USERNAME'] else 'System',
            "event_type": r['event_type'],
            "severity": r['severity'],
            "created_at": r['created_at'],
            "metadata": r['metadata']
        })
    return jsonify({"status": "success", "events": events})

@app.route('/api/admin/stats', methods=['GET'])
def admin_get_stats():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM NEWBANK")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*), SUM(AMOUNT) FROM NEWT WHERE STATUS = 'APPROVED'")
    normal_row = cursor.fetchone()
    total_normal_txs = normal_row[0] or 0
    total_normal_val = normal_row[1] or 0.0
    
    cursor.execute("SELECT COUNT(*), SUM(AMOUNT) FROM NEWT WHERE STATUS = 'BLOCKED'")
    fraud_row = cursor.fetchone()
    total_fraud_txs = fraud_row[0] or 0
    total_fraud_val = fraud_row[1] or 0.0
    
    total_txs = total_normal_txs + total_fraud_txs
    fraud_rate = (total_fraud_txs / total_txs * 100) if total_txs > 0 else 0.0
    
    cursor.execute("SELECT AVG(AMOUNT) FROM NEWT WHERE STATUS = 'APPROVED'")
    avg_tx_amount = cursor.fetchone()[0] or 0.0
    
    cursor.execute('''
        SELECT date(TIMESTAMP) as tx_date, COUNT(*), SUM(AMOUNT) 
        FROM NEWT 
        WHERE STATUS = 'APPROVED'
        GROUP BY tx_date 
        ORDER BY tx_date ASC 
        LIMIT 30
    ''')
    daily_stats = [{"date": r[0], "count": r[1], "amount": r[2]} for r in cursor.fetchall()]
    
    # Biometric counts
    cursor.execute("SELECT COUNT(*) FROM face_enrollments")
    enrolled_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE verification_result = 'MISMATCH'")
    mismatch_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE verification_result = 'LIVENESS_FAILED'")
    liveness_fails = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "status": "success",
        "stats": {
            "total_users": total_users,
            "total_normal_txs": total_normal_txs,
            "total_normal_value": round(total_normal_val, 2),
            "total_blocked_attempts": total_fraud_txs,
            "total_blocked_value": round(total_fraud_val, 2),
            "fraud_rate": round(fraud_rate, 2),
            "average_tx_amount": round(avg_tx_amount, 2),
            "daily_trends": daily_stats,
            "biometrics": {
                "enrolled_users": enrolled_count,
                "not_enrolled_users": total_users - enrolled_count,
                "face_mismatches": mismatch_count,
                "liveness_failures": liveness_fails
            }
        }
    })

@app.route('/api/transfer/live_risk_preview', methods=['POST'])
def live_risk_preview():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    data = request.get_json()
    receiver = data.get('receiver', '').strip()
    try:
        amount = float(data.get('amount', 0))
    except ValueError:
        amount = 0.0
    ttype = data.get('type', 'TRANSFER').strip()
    
    sender = session['username']
    sender_id = session.get('user_id')
    if not sender_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = ?", (sender,))
        row = cursor.fetchone()
        conn.close()
        sender_id = row['ID'] if row else None
        
    if not sender_id or not receiver or amount <= 0:
        return jsonify({
            "status": "success",
            "score": 10,
            "level": "LOW",
            "reasons": ["Awaiting valid transfer input details..."],
            "breakdown": {"base_points": 10}
        })
        
    try:
        score, level, reasons, is_fraud_predicted, breakdown, ml_prob = compute_hybrid_risk(
            sender_id, sender, receiver, amount, ttype
        )
        return jsonify({
            "status": "success",
            "score": score,
            "level": level,
            "reasons": reasons,
            "breakdown": breakdown,
            "ml_probability": ml_prob
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/transaction/<int:tx_id>/trace', methods=['GET'])
def get_transaction_trace(tx_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    username = session['username']
    is_admin = session.get('is_admin', False)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM NEWT WHERE ID = ?", (tx_id,))
    tx = cursor.fetchone()
    conn.close()
    
    if not tx:
        return jsonify({"status": "error", "message": "Transaction not found."}), 404
        
    # Auth check: sender, receiver or admin
    if not is_admin and tx['SENDER'] != username and tx['RECEIVER'] != username:
        return jsonify({"status": "error", "message": "Access denied."}), 403
        
    trace_str = tx['DECISION_TRACE']
    if not trace_str:
        return jsonify({"status": "error", "message": "Decision trace data not available for this legacy transaction."}), 404
        
    try:
        trace = json.loads(trace_str)
    except Exception as e:
        trace = {"error": str(e)}
        
    return jsonify({
        "status": "success",
        "transaction": {
            "id": tx['ID'],
            "sender": tx['SENDER'],
            "receiver": tx['RECEIVER'],
            "amount": tx['AMOUNT'],
            "status": tx['STATUS'],
            "timestamp": tx['TIMESTAMP']
        },
        "trace": trace
    })

@socketio.on('live_risk_check')
def handle_live_risk_check(data):
    if 'username' not in session:
        emit('live_risk_result', {"status": "error", "message": "Unauthorized"})
        return
        
    sender = session['username']
    sender_id = session.get('user_id')
    if not sender_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = ?", (sender,))
        row = cursor.fetchone()
        conn.close()
        if row:
            sender_id = row['ID']
        else:
            emit('live_risk_result', {"status": "error", "message": "Sender not found"})
            return
            
    receiver = data.get('receiver', '').strip()
    try:
        amount = float(data.get('amount', 0))
    except ValueError:
        amount = 0.0
    ttype = data.get('type', 'TRANSFER').strip()
    
    if not receiver or amount <= 0:
        emit('live_risk_result', {
            "status": "success",
            "score": 10,
            "level": "LOW",
            "reasons": ["Awaiting valid transfer input details..."],
            "breakdown": {"base_points": 10}
        })
        return
        
    try:
        score, level, reasons, is_fraud_predicted, breakdown, ml_prob = compute_hybrid_risk(
            sender_id, sender, receiver, amount, ttype
        )
        
        emit('live_risk_result', {
            "status": "success",
            "score": score,
            "level": level,
            "reasons": reasons,
            "breakdown": breakdown,
            "ml_probability": ml_prob
        })
    except Exception as e:
        emit('live_risk_result', {"status": "error", "message": str(e)})

@socketio.on('join_admin')
def handle_join_admin():
    if session.get('is_admin'):
        join_room('admin_room')
        emit('admin_status', {"status": "joined"})
    else:
        emit('admin_status', {"status": "error", "message": "Access denied"})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')
    socketio.run(app, host='0.0.0.0', port=port, debug=is_dev, use_reloader=False, allow_unsafe_werkzeug=is_dev)
