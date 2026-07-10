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
import base64
import cv2
import random

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=None)
app.secret_key = 'smart_banking_secure_session_key_2026'
DB_PATH = 'BankNH.db'
MODEL_PATH = 'banking_app_rf.pkl'
METRICS_PATH = 'model_metrics.json'

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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
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
            img = np.zeros((240, 320, 3), dtype=np.uint8)
        return img
    except Exception:
        return np.zeros((240, 320, 3), dtype=np.uint8)

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
        return [0.0] * 128
    aligned_face = face_recognizer.alignCrop(img, face)
    embedding = face_recognizer.feature(aligned_face)
    return embedding[0].tolist()

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
    cosine_sim = np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
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

        cursor.execute('''
        INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, firstname, lastname, email, password, confirm, phone, sex, address, initial_bal))
        
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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = ? AND PASSWORD = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = user['USERNAME']
            session['user_id'] = user['ID']
            session['is_admin'] = (user['USERNAME'].lower() == 'admin' or user['USERNAME'].lower() == 'auditor')
            return jsonify({
                "status": "success",
                "message": "Login successful!",
                "user": {
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
            })
        else:
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401
    except Exception as e:
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
    except Exception as e:
        traceback.print_exc()
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
            if 'pending_tx' in session:
                pending = session['pending_tx']
                pending['face_verified'] = True
                session['pending_tx'] = pending
                session.modified = True
                
            cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = ? AND verification_result = 'SUCCESS'", (user_id,))
            attempts_row = cursor.fetchone()
            
            conn.commit()
            conn.close()
            
            # Auto-finalize transaction if OTP was already verified
            if 'pending_tx' in session and session['pending_tx'].get('otp_verified', False):
                return finalize_pending_transaction()
                
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
            
    except Exception as e:
        traceback.print_exc()
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
        sender = session['username']
        sender_id = session['user_id']
        receiver = data.get('receiver', '').strip()
        amount_str = data.get('amount', '0')
        ttype = data.get('type', 'TRANSFER')

        if not receiver or not amount_str:
            return jsonify({"status": "error", "message": "Receiver and amount are required."}), 400

        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError()
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid amount. Must be a positive number."}), 400

        if sender == receiver:
            return jsonify({"status": "error", "message": "You cannot transfer money to yourself."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check sender details
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (sender,))
        sender_row = cursor.fetchone()
        if not sender_row:
            conn.close()
            return jsonify({"status": "error", "message": "Sender account not found."}), 404
        sender_balance = sender_row['BAL'] if sender_row['BAL'] is not None else 0.0

        if sender_balance < amount:
            conn.close()
            return jsonify({"status": "error", "message": "Insufficient balance."}), 400

        # Check receiver details
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
        receiver_row = cursor.fetchone()
        
        if not receiver_row:
            conn.close()
            return jsonify({"status": "error", "message": "Receiver username not found."}), 404

        # Run Hybrid Risk Engine
        risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability = compute_hybrid_risk(sender_id, sender, receiver, amount, ttype)
        
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
        conn.close()
        
        # Generate random 6-digit OTP
        otp = f"{random.randint(100000, 999999)}"
        
        # Save details in session
        session['pending_tx'] = {
            'sender': sender,
            'sender_id': sender_id,
            'receiver': receiver,
            'amount': amount,
            'type': ttype,
            'otp': otp,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'reasons': reasons,
            'is_fraud_predicted': is_fraud_predicted,
            'otp_verified': False,
            'face_verified': False,
            'decision_trace': decision_trace
        }
        
        print(f"[{risk_level} RISK] OTP for transaction {sender} -> {receiver} (INR {amount}) is: [{otp}]")
        
        # LOW RISK: Auto approve
        if risk_level == 'LOW':
            session['pending_tx']['otp_verified'] = True
            session['pending_tx']['face_verified'] = True
            return finalize_pending_transaction()
            
        # CRITICAL RISK: Block immediately
        if risk_level == 'CRITICAL':
            conn = get_db_connection()
            cursor = conn.cursor()
            # Log blocked directly
            cursor.execute('''
            INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'BLOCKED', ?, ?)
            ''', (sender, receiver, ttype, amount, sender_balance, sender_balance, receiver_row['BAL'], receiver_row['BAL'], is_fraud_predicted, json.dumps(decision_trace)))
            
            # Broadcast to admin room
            tx_event = {
                'sender': sender[0] + '***' + sender[-1] if len(sender) > 1 else sender,
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
            conn.commit()
            conn.close()
            
            session.pop('pending_tx', None)
            return jsonify({
                "status": "blocked",
                "message": "Security Alert: This transaction has been BLOCKED. Transaction exhibits CRITICAL threat indicators (risk score > 90). Administrator review required.",
                "score": risk_score,
                "level": risk_level,
                "reasons": reasons
            }), 400

        # MEDIUM RISK: Requires OTP only
        if risk_level == 'MEDIUM':
            return jsonify({
                "status": "verification_required",
                "required": ["otp"],
                "otp": otp,
                "score": risk_score,
                "level": risk_level,
                "reasons": reasons
            })

        # HIGH RISK: Requires OTP + Face verification
        if risk_level == 'HIGH':
            return jsonify({
                "status": "verification_required",
                "required": ["otp", "face"],
                "otp": otp,
                "face_enrolled": has_face_enrolled,
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
        
    pending = session.get('pending_tx')
    if not pending:
        return jsonify({"status": "error", "message": "No pending transaction found."}), 400
        
    data = request.get_json()
    otp = data.get('otp', '').strip()
    
    if not otp:
        return jsonify({"status": "error", "message": "OTP verification code is required."}), 400
        
    if otp != pending['otp']:
        return jsonify({"status": "error", "message": "Invalid OTP code. Please try again."}), 400
        
    # OTP verified!
    pending['otp_verified'] = True
    session['pending_tx'] = pending
    session.modified = True
    
    # If risk is medium, finalize transaction
    if pending['risk_level'] == 'MEDIUM':
        return finalize_pending_transaction()
        
    # If risk is high, return that OTP is OK but face check is still required
    if pending['risk_level'] == 'HIGH':
        if pending['face_verified']:
            return finalize_pending_transaction()
        else:
            return jsonify({
                "status": "otp_ok_need_face",
                "message": "OTP verified successfully. Please proceed to the face liveness check."
            })
            
    return jsonify({"status": "error", "message": "State machine conflict."}), 500

def finalize_pending_transaction():
    pending = session.get('pending_tx')
    if not pending:
        return jsonify({"status": "error", "message": "No pending transaction details available."}), 400
        
    sender = pending['sender']
    receiver = pending['receiver']
    amount = pending['amount']
    ttype = pending['type']
    is_fraud_predicted = pending['is_fraud_predicted']
    
    # Clear from session
    session.pop('pending_tx', None)
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get sender details
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (sender,))
        sender_bal = cursor.fetchone()['BAL']
        
        # Get receiver details
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = ?", (receiver,))
        receiver_bal = cursor.fetchone()['BAL']
        
        if sender_bal < amount:
            conn.close()
            return jsonify({"status": "error", "message": "Insufficient balance at finalization."}), 400
            
        sender_new_bal = sender_bal - amount
        receiver_new_bal = receiver_bal + amount
        
        # Process transfer updates
        cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE USERNAME = ?", (sender_new_bal, sender))
        cursor.execute("UPDATE NEWBANK SET BAL = ? WHERE USERNAME = ?", (receiver_new_bal, receiver))
        
        # Prepare decision trace auth completion
        decision_trace = pending.get('decision_trace', {})
        auth_completed = []
        if pending.get('otp_verified'):
            auth_completed.append('otp')
        if pending.get('face_verified'):
            auth_completed.append('face')
        decision_trace['auth_completed'] = auth_completed
        
        # Log APPROVED transaction
        cursor.execute('''
        INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
        ''', (sender, receiver, ttype, amount, sender_bal, sender_new_bal, receiver_bal, receiver_new_bal, is_fraud_predicted, json.dumps(decision_trace)))
        
        tx_id = cursor.lastrowid
        
        # Broadcast to admin room
        tx_event = {
            'id': tx_id,
            'sender': sender[0] + '***' + sender[-1] if len(sender) > 1 else sender,
            'receiver': receiver[0] + '***' + receiver[-1] if len(receiver) > 1 else receiver,
            'ttype': ttype,
            'amount': amount,
            'status': 'APPROVED',
            'risk_score': pending.get('risk_score', 10),
            'risk_level': pending.get('risk_level', 'LOW'),
            'reasons': pending.get('reasons', []),
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        socketio.emit('new_transaction', tx_event, to='admin_room')
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": "Transfer completed successfully.",
            "new_balance": sender_new_bal
        })
    except Exception as e:
        traceback.print_exc()
        if conn:
            conn.rollback()
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
    socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
