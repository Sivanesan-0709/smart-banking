from gevent import monkey
monkey.patch_all()

from flask import Flask, request, jsonify, session, send_from_directory
from db_helper import get_db_connection, DB_PATH
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
import time
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

def create_notification(user_id, title, message, ntype="SYSTEM", cursor=None):
    try:
        if cursor:
            cursor.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, %s)
            ''', (user_id, title, message, ntype))
        else:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, %s)
            ''', (user_id, title, message, ntype))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to create notification: {e}", flush=True)

def parse_user_agent(ua_string):
    if not ua_string:
        return "Unknown", "Unknown", "Unknown"
    ua = ua_string.lower()
    if "chrome" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    elif "edge" in ua:
        browser = "Edge"
    else:
        browser = "Mobile Browser" if "mobile" in ua else "Other Browser"
        
    if "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"
        
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        device_type = "Mobile"
    elif "ipad" in ua or "tablet" in ua:
        device_type = "Tablet"
    else:
        device_type = "Desktop"
        
    return browser, os_name, device_type

@app.before_request
def check_session_validity():
    if request.path.startswith('/static') or request.path in ['/api/login', '/api/register', '/api/logout']:
        return
    if 'username' in session and 'session_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM login_history WHERE session_id = %s", (session['session_id'],))
        row = cursor.fetchone()
        if row:
            if row['status'] == 'REVOKED':
                session.clear()
                conn.close()
                return jsonify({"status": "error", "message": "Session has been revoked."}), 401
            else:
                utc_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("UPDATE login_history SET last_activity = %s WHERE session_id = %s", (utc_now, session['session_id']))
                conn.commit()
        conn.close()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=None)

is_test = ('unittest' in sys.modules or os.environ.get('TESTING') == '1') and os.environ.get('TEST_PROD_SIMULATION') != '1'
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

def is_valid_email(email):
    if not email:
        return False
    import re
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(regex, email))

def send_email_smtp(recipient_email, subject, plain_text, html_body=None):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USERNAME')
    smtp_pass = os.environ.get('SMTP_PASSWORD')
    smtp_from = os.environ.get('SMTP_FROM') or smtp_user or "no-reply@smartbanking.com"
    
    if not smtp_host or not smtp_user or not smtp_pass:
        return False, "SMTP_NOT_CONFIGURED"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = smtp_from
    msg['To'] = recipient_email

    part1 = MIMEText(plain_text, 'plain', 'utf-8')
    msg.attach(part1)

    if html_body:
        part2 = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(part2)

    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [recipient_email], msg.as_string())
            server.quit()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception as e_tls:
                print(f"[DEBUG] STARTTLS negotiation skipped: {e_tls}", flush=True)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [recipient_email], msg.as_string())
            server.quit()
        print(f"[INFO] Authenticated SMTP email successfully delivered to {recipient_email}.", flush=True)
        return True
    except Exception as e:
        print(f"[ERROR] SMTP delivery failure to {recipient_email}: {type(e).__name__}", flush=True)
        return False, f"SMTP_ERROR_{type(e).__name__}"


def send_email(recipient_email, subject, plain_text, html_body=None):
    import urllib.request
    import urllib.error
    import json
    import sys
    import os
    
    if not is_valid_email(recipient_email):
        print(f"[ERROR] Invalid recipient email format: {recipient_email}", flush=True)
        return False
        
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_user = os.environ.get('SMTP_USERNAME')
    smtp_pass = os.environ.get('SMTP_PASSWORD')
    
    # Priority 1: Authenticated SMTP Delivery
    if smtp_host and smtp_user and smtp_pass:
        smtp_res = send_email_smtp(recipient_email, subject, plain_text, html_body)
        if smtp_res is True:
            return True
        elif isinstance(smtp_res, tuple) and smtp_res[0] is True:
            return True
        print(f"[WARN] Primary SMTP delivery failed ({smtp_res}). Evaluating fallbacks...", flush=True)

    # Priority 2: Resend API Delivery
    resend_api_key = os.environ.get('RESEND_API_KEY')
    resend_from = os.environ.get('RESEND_FROM_EMAIL', 'onboarding@resend.dev')
    
    is_test = ('unittest' in sys.modules or os.environ.get('TESTING') == '1') and os.environ.get('TEST_PROD_SIMULATION') != '1'
    is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')
    
    if resend_api_key:
        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {resend_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Smart-Banking-Fraud-Detection/1.0"
        }
        payload = {
            "from": resend_from,
            "to": [recipient_email],
            "subject": subject,
            "text": plain_text
        }
        if html_body:
            payload["html"] = html_body
            
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10.0) as response:
                res_body = response.read().decode('utf-8')
                print(f"[INFO] Resend email successfully delivered to {recipient_email}.", flush=True)
                return True
        except urllib.error.HTTPError as e:
            err_content = e.read().decode('utf-8')
            print(f"[ERROR] Resend HTTP Error {e.code} during email delivery: {err_content}", flush=True)
            if e.code == 403 or "1010" in err_content or "validation_error" in err_content or "testing" in err_content.lower() or "domain" in err_content.lower():
                return False, "RESEND_TEST_DOMAIN_RESTRICTION"
            return False, f"HTTP_{e.code}"
        except Exception as e:
            print(f"[ERROR] Network/Connection failure during Resend email delivery: {e}", flush=True)
            return False, "NETWORK_ERROR"

    # Priority 3: Development / Test Mode Mock Email Log
    if is_test or is_dev:
        print(f"[DEBUG] [MOCK EMAIL] To: {recipient_email} | Subject: {subject}", flush=True)
        print(f"Plain Text:\n{plain_text}", flush=True)
        if html_body:
            print(f"HTML:\n{html_body[:200]}...", flush=True)
        return True
    else:
        print("[ERROR] Neither SMTP nor Resend API key is configured in production environment.", flush=True)
        return False

def parse_datetime_safe(val):
    if val is None:
        return None
    if isinstance(val, datetime.datetime):
        if val.tzinfo is not None:
            return val.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return val
    if isinstance(val, str):
        val_clean = val.strip().replace('T', ' ')
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(val_clean.split('+')[0].split('Z')[0], fmt)
            except ValueError:
                pass
        try:
            dt = datetime.datetime.fromisoformat(val)
            if dt.tzinfo is not None:
                dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            pass
    return None

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def clean_and_parse_amount(val):
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    val_str = str(val).strip()
    # Keep only digits and decimal point using regular expression
    import re
    clean_str = re.sub(r'[^\d\.]', '', val_str)
    try:
        return float(clean_str)
    except ValueError:
        raise ValueError("Invalid amount format")

def build_html_email(body_html_content):
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333333; margin: 0; padding: 0; }}
  .container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; border: 1px solid #e1e4e8; }}
  .header {{ background: linear-gradient(135deg, #6f5782, #4a3b56); color: #ffffff; padding: 25px 20px; text-align: center; }}
  .header h1 {{ margin: 0; font-size: 24px; font-weight: 600; letter-spacing: 0.5px; }}
  .content {{ padding: 30px 20px; line-height: 1.6; }}
  .content p {{ margin: 0 0 15px 0; }}
  .content strong {{ color: #111111; }}
  .details-box {{ background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; margin: 20px 0; }}
  .details-row {{ display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 14px; }}
  .details-row:last-child {{ margin-bottom: 0; }}
  .details-label {{ color: #6c757d; }}
  .details-value {{ font-weight: 600; color: #212529; }}
  .footer {{ background-color: #f8f9fa; color: #6c757d; font-size: 12px; text-align: center; padding: 15px 20px; border-top: 1px solid #e9ecef; }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Smart Banking</h1>
    </div>
    <div class="content">
      {body_html_content}
    </div>
    <div class="footer">
      This is an automated notification. Please do not reply directly to this email. &copy; 2026 Smart Banking. All rights reserved.
    </div>
  </div>
</body>
</html>"""

def dispatch_email_async(recipient_email, subject, plain_text, html_body=None):
    is_test = ('unittest' in sys.modules or os.environ.get('TESTING') == '1') and os.environ.get('TEST_PROD_SIMULATION') != '1'
    if is_test:
        try:
            send_email(recipient_email, subject, plain_text, html_body)
        except Exception as e:
            print(f"[WARN] Test email dispatch failed: {e}", flush=True)
    else:
        try:
            from threading import Thread
            Thread(target=send_email, args=(recipient_email, subject, plain_text, html_body), daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Failed to start email thread: {e}", flush=True)

def send_withdrawal_email(recipient_email, tx_id, amount, remaining_balance):
    customer_name = "Valued Customer"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT FIRSTNAME, LASTNAME FROM NEWBANK WHERE EMAIL = %s", (recipient_email,))
        user_row = cursor.fetchone()
        conn.close()
        if user_row:
            customer_name = f"{user_row['FIRSTNAME']} {user_row['LASTNAME']}"
    except Exception as e:
        print(f"[WARN] Failed to fetch customer name for withdrawal email: {e}", flush=True)

    subject = "Withdrawal Successful"
    dt_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    plain_text = f"""Dear {customer_name},

Your withdrawal has been completed successfully.

Transaction ID: {tx_id}
Date & Time: {dt_str}
Amount: ₹{amount:,.2f}
Status: COMPLETED

Remaining Balance: ₹{remaining_balance:,.2f}

Thank you."""

    html_body = build_html_email(f"""<p>Dear {customer_name},</p>
<p>Your withdrawal has been completed successfully.</p>
<div class="details-box">
  <div class="details-row">
    <span class="details-label">Transaction ID:</span>
    <span class="details-value">{tx_id}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Date & Time:</span>
    <span class="details-value">{dt_str}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Amount:</span>
    <span class="details-value">₹{amount:,.2f}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Status:</span>
    <span class="details-value">COMPLETED</span>
  </div>
  <div class="details-row">
    <span class="details-label">Remaining Balance:</span>
    <span class="details-value">₹{remaining_balance:,.2f}</span>
  </div>
</div>
<p>Thank you.</p>""")

    dispatch_email_async(recipient_email, subject, plain_text, html_body)
    return True

def send_transfer_email(recipient_email, tx_id, amount, receiver):
    customer_name = "Valued Customer"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT FIRSTNAME, LASTNAME FROM NEWBANK WHERE EMAIL = %s", (recipient_email,))
        user_row = cursor.fetchone()
        conn.close()
        if user_row:
            customer_name = f"{user_row['FIRSTNAME']} {user_row['LASTNAME']}"
    except Exception as e:
        print(f"[WARN] Failed to fetch customer name for transfer email: {e}", flush=True)

    subject = "Fund Transfer Successful"
    dt_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    plain_text = f"""Dear {customer_name},

Your fund transfer was completed successfully.

Transaction ID: {tx_id}
Date & Time: {dt_str}
Amount: ₹{amount:,.2f}
Receiver: {receiver}
Status: SUCCESS

Thank you for banking with Smart Banking."""

    html_body = build_html_email(f"""<p>Dear {customer_name},</p>
<p>Your fund transfer was completed successfully.</p>
<div class="details-box">
  <div class="details-row">
    <span class="details-label">Transaction ID:</span>
    <span class="details-value">{tx_id}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Date & Time:</span>
    <span class="details-value">{dt_str}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Amount:</span>
    <span class="details-value">₹{amount:,.2f}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Receiver:</span>
    <span class="details-value">{receiver}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Status:</span>
    <span class="details-value">SUCCESS</span>
  </div>
</div>
<p>Thank you for banking with Smart Banking.</p>""")

    dispatch_email_async(recipient_email, subject, plain_text, html_body)
    return True

def send_otp_email(recipient_email, otp, amount, receiver):
    if os.environ.get('SIMULATE_RESEND_TEST_RESTRICTION') == '1':
        print(f"[DEBUG] [SIMULATED RESEND RESTRICTION] Recipient {recipient_email} restricted by onboarding@resend.dev.", flush=True)
        return False, "RESEND_TEST_DOMAIN_RESTRICTION"
    subject = 'Smart Banking Security Verification Code'
    plain_text = f"""Dear Customer,

You have initiated a transaction of INR {amount:,.2f} to recipient {receiver}.

Your 6-digit verification code is: {otp}

This code is valid for exactly 5 minutes. Do NOT share this code with anyone, including bank representatives.

If you did not initiate this transaction, please log in to your account and change your password immediately."""

    html_body = f"""<h2>Smart Banking Security Verification</h2>
<p>You have initiated a high-risk transaction of <strong>INR {amount:,.2f}</strong> to recipient <strong>{receiver}</strong>.</p>
<p>Your 6-digit verification code is:</p>
<p style="font-size: 1.5rem; font-weight: bold; letter-spacing: 2px; color: #9b5de5;">{otp}</p>
<p>This code is valid for exactly <strong>5 minutes</strong>. Do NOT share this code with anyone, including bank representatives.</p>
<p>If you did not initiate this transaction, please log in to your account and change your password immediately.</p>
"""
    try:
        res = send_email(recipient_email, subject, plain_text, html_body)
        if isinstance(res, tuple):
            return res
        return res
    except Exception as e:
        print(f"[WARN] send_otp_email exception safely handled: {e}", flush=True)
        return False

MODEL_PATH = str(BASE_DIR / 'banking_app_rf.pkl')
METRICS_PATH = str(BASE_DIR / 'model_metrics.json')

# Global ML models
model = None
face_detector = None
face_recognizer = None



def send_deposit_email(recipient_email, reference_id, amount, balance_before, balance_after, payment_id=None):
    try:
        customer_name = "Valued Customer"
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT FIRSTNAME, LASTNAME FROM NEWBANK WHERE EMAIL = %s", (recipient_email,))
            row = cursor.fetchone()
            conn.close()
            if row:
                customer_name = f"{row['FIRSTNAME']} {row['LASTNAME']}"
        except Exception:
            pass

        subject = "Smart Banking - Payment Successful" if payment_id else "Deposit Successful"
        dt_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        pay_ref_plain = f"\nPayment Reference: {payment_id}" if payment_id else ""
        pay_ref_html = f"""
  <div class="details-row">
    <span class="details-label">Payment Reference:</span>
    <span class="details-value">{payment_id}</span>
  </div>""" if payment_id else ""

        plain_text = f"""Dear {customer_name},

Your account has been credited successfully.

Transaction Reference: {reference_id}{pay_ref_plain}
Date & Time: {dt_str}
Amount Added: ₹{amount:,.2f}
Status: APPROVED

Updated Balance: ₹{balance_after:,.2f}

Thank you for banking with Smart Banking."""

        html_body = build_html_email(f"""<p>Dear {customer_name},</p>
<p>Your account has been credited successfully.</p>
<div class="details-box">
  <div class="details-row">
    <span class="details-label">Transaction Reference:</span>
    <span class="details-value">{reference_id}</span>
  </div>{pay_ref_html}
  <div class="details-row">
    <span class="details-label">Date & Time:</span>
    <span class="details-value">{dt_str}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Amount Added:</span>
    <span class="details-value">₹{amount:,.2f}</span>
  </div>
  <div class="details-row">
    <span class="details-label">Status:</span>
    <span class="details-value">APPROVED</span>
  </div>
  <div class="details-row">
    <span class="details-label">Updated Balance:</span>
    <span class="details-value">₹{balance_after:,.2f}</span>
  </div>
</div>
<p>Thank you for banking with Smart Banking.</p>""")

        dispatch_email_async(recipient_email, subject, plain_text, html_body)
        return True
    except Exception as e:
        print(f"[WARN] send_deposit_email error safely handled: {e}", flush=True)
        return False
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
    
    print("\n[STARTUP] ----- BIOMETRIC MODEL INITIALIZATION -----", flush=True)
    print(f"[STARTUP] OpenCV Version: {cv2.__version__}", flush=True)
    
    models_dir = os.path.join(str(BASE_DIR), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    yunet_path = os.path.join(models_dir, 'face_detection_yunet_2023mar.onnx')
    sface_path = os.path.join(models_dir, 'face_recognition_sface_2021dec.onnx')
    
    print(f"[STARTUP] Resolved Detector Path: {yunet_path}", flush=True)
    print(f"[STARTUP] Resolved Recognizer Path: {sface_path}", flush=True)
    
    yunet_exists = os.path.exists(yunet_path)
    sface_exists = os.path.exists(sface_path)
    
    print(f"[STARTUP] Detector Model File Exists: {yunet_exists}", flush=True)
    print(f"[STARTUP] Recognizer Model File Exists: {sface_exists}", flush=True)
    
    if yunet_exists:
        print(f"[STARTUP] Detector File Size: {os.path.getsize(yunet_path)} bytes", flush=True)
    if sface_exists:
        print(f"[STARTUP] Recognizer File Size: {os.path.getsize(sface_path)} bytes", flush=True)
        
    yunet_url = "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
    sface_url = "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
    
    import urllib.request
    
    def download_file(url, dest):
        if not os.path.exists(dest):
            print(f"[STARTUP] Downloading {os.path.basename(dest)}... (this happens once)", flush=True)
            try:
                req = urllib.request.Request(
                    url, 
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                )
                with urllib.request.urlopen(req, timeout=30.0) as response, open(dest, 'wb') as out_file:
                    out_file.write(response.read())
                print(f"[STARTUP] Successfully downloaded {os.path.basename(dest)}.", flush=True)
            except Exception as e:
                print(f"[STARTUP] [ERROR] Failed to download {os.path.basename(dest)}: {e}", flush=True)
                traceback.print_exc()
                
    if not yunet_exists:
        download_file(yunet_url, yunet_path)
        yunet_exists = os.path.exists(yunet_path)
        
    if not sface_exists:
        download_file(sface_url, sface_path)
        sface_exists = os.path.exists(sface_path)
        
    detector_ok = False
    recognizer_ok = False
    
    if yunet_exists and sface_exists:
        try:
            face_detector = cv2.FaceDetectorYN.create(yunet_path, "", (320, 320), 0.9, 0.3, 5000)
            detector_ok = True
            print("[STARTUP] OpenCV YuNet face detector initialized successfully.", flush=True)
        except Exception as e:
            print(f"[STARTUP] [ERROR] Failed to initialize OpenCV YuNet face detector: {e}", flush=True)
            traceback.print_exc()
            face_detector = None
            
        try:
            face_recognizer = cv2.FaceRecognizerSF.create(sface_path, "")
            recognizer_ok = True
            print("[STARTUP] OpenCV SFace face recognizer initialized successfully.", flush=True)
        except Exception as e:
            print(f"[STARTUP] [ERROR] Failed to initialize OpenCV SFace face recognizer: {e}", flush=True)
            traceback.print_exc()
            face_recognizer = None
    else:
        print("[STARTUP] [ERROR] Face ONNX models are missing and could not be loaded or downloaded.", flush=True)
        face_detector = None
        face_recognizer = None
        
    print(f"[STARTUP] Biometric status -> Detector: {'SUCCESS' if detector_ok else 'FAILED'}, Recognizer: {'SUCCESS' if recognizer_ok else 'FAILED'}", flush=True)
    print("--------------------------------------------------\n", flush=True)

def is_login_rate_limited(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Bounded cleanup of expired attempts (> 5 minutes ago)
    cursor.execute("DELETE FROM login_attempts WHERE attempted_at < datetime('now', '-5 minutes')")
    conn.commit()
    
    # Check attempts in last 5 minutes
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE username = %s AND attempted_at >= datetime('now', '-5 minutes')", (username,))
    count = cursor.fetchone()[0]
    conn.close()
    return count >= 5

def record_login_attempt(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_attempts (username) VALUES (%s)", (username,))
    conn.commit()
    conn.close()

def clear_login_attempts(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE username = %s", (username,))
    conn.commit()
    conn.close()


def run_biometric_migrations(cursor, is_postgres):
    # Create face_samples table
    if is_postgres:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_samples (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            sample_index INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            image_hash VARCHAR(64) NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            capture_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            embedding TEXT NOT NULL
        )
        ''')
    else:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sample_index INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            image_hash TEXT NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            capture_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            embedding TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        
    # Alter face_verification_attempts
    cols = ['image_path', 'image_hash', 'width', 'height', 'capture_timestamp']
    col_types = {
        'image_path': 'TEXT',
        'image_hash': 'VARCHAR(64)' if is_postgres else 'TEXT',
        'width': 'INTEGER',
        'height': 'INTEGER',
        'capture_timestamp': 'TIMESTAMP' if is_postgres else 'DATETIME'
    }
    
    for col in cols:
        try:
            cursor.execute(f"ALTER TABLE face_verification_attempts ADD COLUMN {col} {col_types[col]}")
        except Exception:
            pass
            
    # Alter face_enrollments
    for col in cols:
        try:
            cursor.execute(f"ALTER TABLE face_enrollments ADD COLUMN {col} {col_types[col]}")
        except Exception:
            pass

def run_razorpay_migrations(cursor, is_postgres):
    cols = {
        'razorpay_order_id': 'VARCHAR(100)' if is_postgres else 'TEXT',
        'razorpay_payment_id': 'VARCHAR(100)' if is_postgres else 'TEXT'
    }
    for col, col_type in cols.items():
        try:
            cursor.execute(f"ALTER TABLE deposits ADD COLUMN {col} {col_type}")
        except Exception:
            pass

def run_fraud_feedback_migrations(cursor, is_postgres):
    if is_postgres:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS fraud_feedback (
            id SERIAL PRIMARY KEY,
            transaction_id INTEGER,
            transaction_token VARCHAR(100),
            admin_user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            admin_username VARCHAR(100),
            sender VARCHAR(100),
            receiver VARCHAR(100),
            amount DOUBLE PRECISION,
            ttype VARCHAR(50),
            label VARCHAR(30) NOT NULL,
            risk_score INTEGER,
            risk_level VARCHAR(20),
            ml_probability DOUBLE PRECISION,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
    else:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS fraud_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER,
            transaction_token TEXT,
            admin_user_id INTEGER NOT NULL,
            admin_username TEXT,
            sender TEXT,
            receiver TEXT,
            amount REAL,
            ttype TEXT,
            label TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            ml_probability REAL,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(admin_user_id) REFERENCES NEWBANK(ID)
        )
        ''')
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_feedback_token ON fraud_feedback(transaction_token)")
    except Exception:
        pass

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    db_url = os.environ.get('DATABASE_URL')
    is_postgres = (db_url is not None or any(os.environ.get(var) for var in ['DB_HOST', 'DB_NAME', 'DB_USER']))
    
    if is_postgres:
        print("[INFO] Migrating schema to PostgreSQL...", flush=True)
        cursor.execute('''
        CREATE OR REPLACE FUNCTION datetime(val text) RETURNS timestamp AS $$
            SELECT CASE WHEN val = 'now' THEN CURRENT_TIMESTAMP::timestamp ELSE val::timestamp END;
        $$ LANGUAGE SQL;
        ''')
        cursor.execute('''
        CREATE OR REPLACE FUNCTION datetime(val text, modifier text) RETURNS timestamp AS $$
            SELECT CASE 
                WHEN val = 'now' THEN 
                    CASE 
                        WHEN modifier = '-5 minutes' THEN CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                        WHEN modifier = '-15 minutes' THEN CURRENT_TIMESTAMP - INTERVAL '15 minutes'
                        WHEN modifier = '-10 minutes' THEN CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                        ELSE CURRENT_TIMESTAMP + modifier::interval
                    END
                ELSE val::timestamp + modifier::interval
            END;
        $$ LANGUAGE SQL;
        ''')
        cursor.execute('''
        CREATE OR REPLACE FUNCTION strftime(format text, val text) RETURNS double precision AS $$
            SELECT CASE 
                WHEN format = '%s' THEN 
                    CASE 
                        WHEN val = 'now' THEN EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
                        ELSE EXTRACT(EPOCH FROM val::timestamp)
                    END
                ELSE 0
            END;
        $$ LANGUAGE SQL;
        ''')
        cursor.execute('''
        CREATE OR REPLACE FUNCTION strftime(format text, val timestamp) RETURNS double precision AS $$
            SELECT CASE WHEN format = '%s' THEN EXTRACT(EPOCH FROM val) ELSE 0 END;
        $$ LANGUAGE SQL;
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cash_out_channels (
            id VARCHAR(50) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            status VARCHAR(20) DEFAULT 'ACTIVE'
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            username VARCHAR(100) NOT NULL,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS NEWBANK (
            ID SERIAL PRIMARY KEY,
            USERNAME VARCHAR(100) UNIQUE NOT NULL,
            FIRSTNAME VARCHAR(50) NOT NULL,
            LASTNAME VARCHAR(50) NOT NULL,
            EMAIL VARCHAR(150) NOT NULL,
            PASSWORD VARCHAR(255) NOT NULL,
            CONFIRM VARCHAR(255) NOT NULL,
            PHONE VARCHAR(20) NOT NULL,
            SEX VARCHAR(10),
            ADDRESS TEXT NOT NULL,
            BAL DOUBLE PRECISION DEFAULT 50000.0
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_transactions (
            token VARCHAR(100) PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            receiver VARCHAR(100) NOT NULL,
            amount DOUBLE PRECISION NOT NULL,
            ttype VARCHAR(50) NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level VARCHAR(20) NOT NULL,
            reasons TEXT NOT NULL,
            is_fraud_predicted INTEGER NOT NULL,
            otp_verified INTEGER DEFAULT 0,
            face_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            status VARCHAR(50) DEFAULT 'PENDING',
            decision_trace TEXT NOT NULL
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS transaction_otp_challenges (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            transaction_token VARCHAR(100) NOT NULL REFERENCES pending_transactions(token) ON DELETE CASCADE,
            otp_hash VARCHAR(100) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            attempts INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 5,
            resend_count INTEGER DEFAULT 0,
            last_sent_at TIMESTAMP,
            verified INTEGER DEFAULT 0,
            verified_at TIMESTAMP,
            consumed INTEGER DEFAULT 0,
            consumed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS NEWT (
            ID SERIAL PRIMARY KEY,
            SENDER VARCHAR(100) NOT NULL,
            RECEIVER VARCHAR(100) NOT NULL,
            TTYPE VARCHAR(50) NOT NULL,
            AMOUNT DOUBLE PRECISION NOT NULL,
            SENDEROLDBAL DOUBLE PRECISION NOT NULL,
            SENDERNEWBAL DOUBLE PRECISION NOT NULL,
            RECOLDBAL DOUBLE PRECISION NOT NULL,
            RECNEWBAL DOUBLE PRECISION NOT NULL,
            STATUS VARCHAR(50) DEFAULT 'APPROVED',
            TIMESTAMP TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            IS_FRAUD_PREDICTED INTEGER DEFAULT 0,
            DECISION_TRACE TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_enrollments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL UNIQUE REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            template_reference TEXT NOT NULL,
            model_name VARCHAR(50) DEFAULT 'SFace',
            model_version VARCHAR(20) DEFAULT '1.0',
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'ACTIVE'
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_verification_attempts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            transaction_id INTEGER,
            verification_result VARCHAR(50) NOT NULL,
            similarity_or_distance DOUBLE PRECISION,
            threshold DOUBLE PRECISION,
            liveness_result VARCHAR(50),
            challenge_type VARCHAR(50),
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            model_version VARCHAR(20)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS biometric_security_events (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            transaction_id INTEGER,
            event_type VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS deposits (
            id SERIAL PRIMARY KEY,
            reference_id VARCHAR(100) UNIQUE NOT NULL,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            amount DOUBLE PRECISION NOT NULL,
            method VARCHAR(50) NOT NULL,
            gateway VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level VARCHAR(20) NOT NULL,
            remarks TEXT,
            balance_before DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            balance_after DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            ip_address VARCHAR(50),
            device TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            beneficiary_username VARCHAR(100) NOT NULL REFERENCES NEWBANK(USERNAME) ON DELETE CASCADE,
            nickname VARCHAR(100),
            is_favorite INTEGER DEFAULT 0,
            transfer_count INTEGER DEFAULT 0,
            total_transferred DOUBLE PRECISION DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, beneficiary_username)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_beneficiaries_user ON beneficiaries(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            session_id VARCHAR(255) NOT NULL UNIQUE,
            browser VARCHAR(100),
            os VARCHAR(100),
            ip_address VARCHAR(50),
            device_type VARCHAR(50),
            device_fingerprint VARCHAR(100),
            is_trusted INTEGER DEFAULT 0,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logout_time TIMESTAMP,
            status VARCHAR(20) DEFAULT 'ACTIVE'
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            type VARCHAR(50) DEFAULT 'SYSTEM',
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES NEWBANK(ID) ON DELETE SET NULL,
            username VARCHAR(100),
            action VARCHAR(100) NOT NULL,
            ip_address VARCHAR(50),
            device TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES NEWBANK(ID) ON DELETE CASCADE,
            device_fingerprint VARCHAR(100) NOT NULL,
            browser VARCHAR(100),
            os VARCHAR(100),
            last_login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, device_fingerprint)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        
    else:
        print("[INFO] Migrating schema to SQLite...", flush=True)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cash_out_channels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE'
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT NOT NULL,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
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
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            template_reference TEXT NOT NULL,
            model_name TEXT DEFAULT 'SFace',
            model_version TEXT DEFAULT '1.0',
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'ACTIVE',
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS face_verification_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_id INTEGER,
            verification_result TEXT NOT NULL,
            similarity_or_distance REAL,
            threshold REAL,
            liveness_result TEXT,
            challenge_type TEXT,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            model_version TEXT,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS biometric_security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            transaction_id INTEGER,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS deposits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            method TEXT NOT NULL,
            gateway TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            remarks TEXT,
            balance_before REAL NOT NULL DEFAULT 0.0,
            balance_after REAL NOT NULL DEFAULT 0.0,
            ip_address TEXT,
            device TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')

    cursor.execute("INSERT INTO cash_out_channels (id, name, status) VALUES ('ATM_01', 'Main Branch ATM', 'ACTIVE') ON CONFLICT DO NOTHING")
    cursor.execute("INSERT INTO cash_out_channels (id, name, status) VALUES ('AGENT_ALPHA', 'Mobile Agent Alpha', 'ACTIVE') ON CONFLICT DO NOTHING")
    cursor.execute("INSERT INTO cash_out_channels (id, name, status) VALUES ('MERCHANT_WEST', 'Westside Merchant Partner', 'ACTIVE') ON CONFLICT DO NOTHING")
    
    if is_postgres:
        cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'newt'")
        columns = [row[0].upper() for row in cursor.fetchall()]
    else:
        cursor.execute("PRAGMA table_info(NEWT)")
        columns = [col['name'].upper() for col in cursor.fetchall()]
        
    if 'STATUS' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN STATUS VARCHAR(50) DEFAULT 'APPROVED'")
    if 'TIMESTAMP' not in columns:
        if is_postgres:
            cursor.execute("ALTER TABLE NEWT ADD COLUMN TIMESTAMP TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        else:
            cursor.execute("ALTER TABLE NEWT ADD COLUMN TIMESTAMP DATETIME DEFAULT '2026-07-02 00:00:00'")
    if 'IS_FRAUD_PREDICTED' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN IS_FRAUD_PREDICTED INTEGER DEFAULT 0")
    if 'DECISION_TRACE' not in columns:
        cursor.execute("ALTER TABLE NEWT ADD COLUMN DECISION_TRACE TEXT")
        
    if is_postgres:
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_newbank_username ON NEWBANK(USERNAME)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_deposits_reference ON deposits(reference_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_status ON NEWT(STATUS)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_face_attempts_user ON face_verification_attempts(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
    else:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_otp_token ON transaction_otp_challenges(transaction_token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_token ON pending_transactions(token)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_newbank_username ON NEWBANK(USERNAME)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_deposits_reference ON deposits(reference_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_deposits_reference ON deposits(reference_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_status ON NEWT(STATUS)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_face_attempts_user ON face_verification_attempts(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            beneficiary_username TEXT NOT NULL,
            nickname TEXT,
            is_favorite INTEGER DEFAULT 0,
            transfer_count INTEGER DEFAULT 0,
            total_transferred DOUBLE PRECISION DEFAULT 0.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID),
            FOREIGN KEY(beneficiary_username) REFERENCES NEWBANK(USERNAME),
            UNIQUE(user_id, beneficiary_username)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_beneficiaries_user ON beneficiaries(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            browser TEXT,
            os TEXT,
            ip_address TEXT,
            device_type TEXT,
            device_fingerprint TEXT,
            is_trusted INTEGER DEFAULT 0,
            login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            logout_time DATETIME,
            status TEXT DEFAULT 'ACTIVE',
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'SYSTEM',
            is_read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            device TEXT,
            metadata TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            browser TEXT,
            os TEXT,
            last_login_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES NEWBANK(ID),
            UNIQUE(user_id, device_fingerprint)
        )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_sender ON NEWT(SENDER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_receiver ON NEWT(RECEIVER)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_newt_timestamp ON NEWT(TIMESTAMP)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        
    # Run dynamic biometric migrations
    run_biometric_migrations(cursor, is_postgres)
    run_razorpay_migrations(cursor, is_postgres)
    
    conn.commit()
    conn.close()
    print("[INFO] Schema initialization and migrations completed successfully.", flush=True)
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

# --- Face Recognition Pipeline Configurations & Hardening ---
FACE_DEBUG_MODE = True
UPLOAD_DIR = os.path.join('uploads', 'biometrics')
DEBUG_DIR = os.path.join('uploads', 'debug_faces')

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DEBUG_DIR, exist_ok=True)

def save_biometric_image(img, folder):
    import uuid, hashlib
    filename = f"{uuid.uuid4().hex}.jpg"
    filepath = os.path.join(folder, filename)
    
    cv2.imwrite(filepath, img)
    
    if not os.path.exists(filepath):
        raise IOError(f"Failed to write image to disk path: {filepath}")
        
    reloaded = cv2.imread(filepath)
    if reloaded is None:
        raise IOError("Saved image is corrupted and cannot be read back.")
        
    h, w, c = reloaded.shape
    if (h, w) != (img.shape[0], img.shape[1]):
        raise IOError("Saved image dimensions do not match source dimensions.")
        
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    img_hash = sha256.hexdigest()
    
    return {
        "path": filepath,
        "hash": img_hash,
        "width": w,
        "height": h,
        "timestamp": datetime.datetime.now().isoformat()
    }

def validate_pose_alignment(face, pose):
    landmarks = face[4:14]
    left_eye_x, right_eye_x, nose_x = landmarks[0], landmarks[2], landmarks[4]
    left_eye_y, right_eye_y, nose_y = landmarks[1], landmarks[3], landmarks[5]
    
    face_width = right_eye_x - left_eye_x
    if face_width <= 0:
        return False, "Invalid face landmarks."
        
    center_x = (left_eye_x + right_eye_x) / 2.0
    deviation_x = (nose_x - center_x) / face_width
    
    center_y = (left_eye_y + right_eye_y) / 2.0
    deviation_y = (nose_y - center_y) / face_width
    
    if pose == 'LOOK_LEFT' or pose == 'Slight Left':
        if deviation_x < 0.08:
            return False, "Please turn your head slightly to the left."
    elif pose == 'LOOK_RIGHT' or pose == 'Slight Right':
        if deviation_x > -0.08:
            return False, "Please turn your head slightly to the right."
    elif pose == 'LOOK_UP' or pose == 'Slight Up':
        if deviation_y > 0.40:
            return False, "Please tilt your head slightly up."
    elif pose == 'LOOK_DOWN' or pose == 'Slight Down':
        if deviation_y < 0.52:
            return False, "Please tilt your head slightly down."
    elif pose == 'LOOK_STRAIGHT' or pose == 'Straight':
        if abs(deviation_x) > 0.15 or deviation_y < 0.30 or deviation_y > 0.62:
            return False, "Please look straight at the camera."
            
    return True, "Pose aligned."

def validate_face_quality(img):
    if face_detector is None:
        return {"status": "error", "message": "Face models are not initialized on the server."}
        
    h, w, c = img.shape
    if w < 320 or h < 240:
        return {"status": "error", "message": f"Resolution is too low: {w}x{h} (minimum 320x240)."}
        
    face_detector.setInputSize((w, h))
    _, faces = face_detector.detect(img)
    
    if faces is None or len(faces) == 0:
        return {"status": "error", "message": "No face detected in the frame. Please look directly at the camera."}
    
    if len(faces) > 1:
        return {"status": "error", "message": "Multiple faces detected. Only one person should be in the frame."}
        
    face = faces[0]
    bbox = face[0:4]
    fx, fy, fw, fh = int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])
    
    if fx < 0 or fy < 0 or (fx + fw) > w or (fy + fh) > h:
        return {"status": "error", "message": "Face is outside the frame. Please align yourself."}
        
    # Enforce minimum size check
    if fw < 80 or fh < 80:
        return {"status": "error", "message": "Face is too far away. Please move closer to the camera."}
    
    # Enforce occupies ratio
    face_area = fw * fh
    img_area = w * h
    if face_area / img_area < 0.05:
        return {"status": "error", "message": "Face occupies less than 25% of the frame. Please move closer."}
        
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face_roi = gray[max(0, fy):min(h, fy+fh), max(0, fx):min(w, fx+fw)]
    if face_roi.size > 0:
        mean_brightness = np.mean(face_roi)
        if mean_brightness < 40:
            return {"status": "error", "message": "Lighting is too dark. Please adjust your lighting."}
        if mean_brightness > 240:
            return {"status": "error", "message": "Lighting is overexposed. Please adjust your lighting."}
            
    if face_roi.size > 0:
        variance = cv2.Laplacian(face_roi, cv2.CV_64F).var()
        if variance < 25.0:
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
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm = data.get('confirm', '')
        phone = data.get('phone', '').strip()
        sex = data.get('sex', 'Male')
        address = data.get('address', '').strip()
        initial_bal = float(data.get('bal', 50000.0))

        if not username or not email or not password or not phone:
            return jsonify({"status": "error", "message": "Required fields are missing."}), 400

        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Invalid email address format."}), 400

        if len(password) < 6:
            return jsonify({"status": "error", "message": "Password must be at least 6 characters long."}), 400

        if password != confirm:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = %s", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"status": "error", "message": "Username already exists."}), 400

        # Check if email exists (case-insensitive)
        cursor.execute("SELECT * FROM NEWBANK WHERE LOWER(EMAIL) = LOWER(%s)", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"status": "error", "message": "Email address is already registered."}), 409

        hashed_pw = generate_password_hash(password)
        cursor.execute('''
        INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (username, firstname, lastname, email, hashed_pw, "", phone, sex, address, initial_bal))
        
        conn.commit()
        
        # Async Welcome Email dispatch in try-except
        try:
            cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = %s", (username,))
            user_row = cursor.fetchone()
            user_id = user_row['ID'] if user_row else 0
            account_num = f"SB-1000{user_id}"
            
            subject = "Smart Banking - Account Created Successfully"
            reg_date = datetime.datetime.now().strftime("%Y-%m-%d")
            plain_text = f"Dear {firstname} {lastname},\n\nWelcome to Smart Banking.\n\nYour account has been created successfully.\n\nAccount Number:\n{account_num}\n\nRegistration Date:\n{reg_date}\n\nThank you for choosing Smart Banking."
            html_body = build_html_email(f"<p>Dear {firstname} {lastname},</p><p>Welcome to Smart Banking.</p><p>Your account has been created successfully.</p><div class='details-box'><div class='details-row'><span class='details-label'>Account Number:</span><span class='details-value'>{account_num}</span></div><div class='details-row'><span class='details-label'>Registration Date:</span><span class='details-value'>{reg_date}</span></div></div><p>Thank you for choosing Smart Banking.</p>")
            
            dispatch_email_async(email, subject, plain_text, html_body)
        except Exception as e_reg_mail:
            print(f"[ERROR] Registration email notification failed: {e_reg_mail}", flush=True)

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
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = %s", (username,))
        user = cursor.fetchone()
        
        ua = request.headers.get('User-Agent', '')
        browser, os_name, dev_type = parse_user_agent(ua)
        ip = request.remote_addr or '127.0.0.1'
        fingerprint = request.headers.get('X-Device-Fingerprint', 'default_fingerprint')
        
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
                is_trusted = check_or_register_device(user['ID'], fingerprint, browser, os_name)
                
                # Check first login ever -> trust device auto
                cursor.execute("SELECT COUNT(*) as count FROM trusted_devices WHERE user_id = %s", (user['ID'],))
                trusted_count = cursor.fetchone()['count']
                if trusted_count == 0:
                    add_trusted_device(user['ID'], fingerprint, browser, os_name)
                    is_trusted = True
                    
                if not is_trusted:
                    import random
                    otp = f"{random.randint(100000, 999999)}"
                    otp_hash = hash_otp(otp)
                    
                    session['login_pending_user_id'] = user['ID']
                    session['login_pending_username'] = user['USERNAME']
                    session['login_pending_password_ok'] = True
                    session['login_pending_fingerprint'] = fingerprint
                    session['login_pending_browser'] = browser
                    session['login_pending_os'] = os_name
                    session['login_pending_dev_type'] = dev_type
                    session['login_pending_ip'] = ip
                    session['login_otp_hash'] = otp_hash
                    session['login_otp_expires'] = time.time() + 300
                    
                    success = False
                    try:
                        subject = "Smart Banking Login Security Code"
                        plain_text = f"Dear {user['FIRSTNAME']} {user['LASTNAME']},\n\nA login attempt was made from an unrecognized browser/device.\n\nYour verification code is: {otp}\n\nIf this was not you, please secure your account."
                        html_body = build_html_email(f"<p>Dear {user['FIRSTNAME']} {user['LASTNAME']},</p><p>A login attempt was made from an unrecognized browser/device.</p><p>Your verification code is:</p><p style='font-size: 1.5rem; font-weight: bold; color: #9b5de5;'>{otp}</p><p>If this was not you, please secure your account immediately.</p>")
                        success = send_email(user['EMAIL'], subject, plain_text, html_body)
                    except Exception as e_mail:
                        print(f"[ERROR] Failed to send login OTP: {e_mail}", flush=True)
                        
                    if not success:
                        session.pop('login_pending_user_id', None)
                        session.pop('login_pending_username', None)
                        session.pop('login_otp_hash', None)
                        session.pop('login_otp_expires', None)
                        conn.close()
                        return jsonify({"status": "error", "message": "Unable to deliver the OTP email. Please try again."}), 500
                        
                    parts = user['EMAIL'].split('@')
                    masked_email = parts[0][0] + "*" * (len(parts[0]) - 1) + "@" + parts[1]
                    conn.close()
                    return jsonify({
                        "status": "verification_required",
                        "message": "A security code has been sent to your registered email.",
                        "email_masked": masked_email
                    })
                
                if legacy:
                    hashed = generate_password_hash(password)
                    cursor.execute("UPDATE NEWBANK SET PASSWORD = %s WHERE ID = %s", (hashed, user['ID']))
                    conn.commit()
                
                clear_login_attempts(username)
                
                session.clear()
                session['username'] = user['USERNAME']
                session['user_id'] = user['ID']
                session['is_admin'] = (user['USERNAME'].lower() in ['admin', 'auditor'])
                
                import uuid
                sess_id = uuid.uuid4().hex
                session['session_id'] = sess_id
                
                cursor.execute('''
                INSERT INTO login_history (user_id, session_id, browser, os, ip_address, device_type, device_fingerprint, is_trusted, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 1, 'ACTIVE')
                ''', (user['ID'], sess_id, browser, os_name, ip, dev_type, fingerprint))
                
                create_notification(user['ID'], "New Login Session", f"Authorized entry from browser {browser} on {os_name} (IP: {ip}).", "SECURITY", cursor=cursor)
                log_audit_event(user['ID'], 'LOGIN', user['USERNAME'], ip, f"{browser} ({os_name})", {"status": "SUCCESS", "trusted_device": True}, cursor)
                
                conn.commit()
                
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
        
        # Check login rate limiting for locking alert email
        try:
            if is_login_rate_limited(username):
                # Query user details
                cursor.execute("SELECT FIRSTNAME, LASTNAME, EMAIL FROM NEWBANK WHERE USERNAME = %s", (username,))
                u_row = cursor.fetchone()
                if u_row and u_row['EMAIL']:
                    customer_name = f"{u_row['FIRSTNAME']} {u_row['LASTNAME']}"
                    subject = "Security Alert - Account Locked"
                    plain_text = f"Dear {customer_name},\n\nYour account has been temporarily locked because multiple failed login attempts were detected.\n\nPlease wait until the lock expires or contact the administrator."
                    html_body = build_html_email(f"<p>Dear {customer_name},</p><p style='color: #d9534f; font-weight: bold;'>Your account has been temporarily locked because multiple failed login attempts were detected.</p><p>Please wait until the lock expires or contact the administrator.</p>")
                    dispatch_email_async(u_row['EMAIL'], subject, plain_text, html_body)
        except Exception as e_lock_mail:
            print(f"[ERROR] Failed to send lock alert email: {e_lock_mail}", flush=True)

        conn.close()
        return jsonify({"status": "error", "message": "Invalid username or password."}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    if user_id:
        try:
            ua = request.headers.get('User-Agent', '')
            browser, os_name, _ = parse_user_agent(ua)
            ip = request.remote_addr or '127.0.0.1'
            log_audit_event(user_id, 'LOGOUT', username, ip, f"{browser} ({os_name})")
            
            sess_id = session.get('session_id')
            if sess_id:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE login_history SET logout_time = CURRENT_TIMESTAMP, status = 'INACTIVE' WHERE session_id = %s", (sess_id,))
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"[ERROR] Failed to log logout event: {e}", flush=True)
            
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."})

@app.route('/api/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = %s", (session['username'],))
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
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if doing password change
        if current_password or new_password or confirm_password:
            if not current_password or not new_password or not confirm_password:
                conn.close()
                return jsonify({"status": "error", "message": "All password fields are required to update password."}), 400
                
            if new_password != confirm_password:
                conn.close()
                return jsonify({"status": "error", "message": "New passwords do not match."}), 400
                
            cursor.execute("SELECT PASSWORD, FIRSTNAME, LASTNAME, EMAIL FROM NEWBANK WHERE ID = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                conn.close()
                return jsonify({"status": "error", "message": "User not found."}), 404
                
            # Verify current password
            if not check_password_hash(user['PASSWORD'], current_password) and user['PASSWORD'] != current_password:
                conn.close()
                return jsonify({"status": "error", "message": "Incorrect current password."}), 400
                
            hashed_new = generate_password_hash(new_password)
            cursor.execute("UPDATE NEWBANK SET PASSWORD = %s WHERE ID = %s", (hashed_new, user_id))
            
            # Invalidate all other active sessions (Feature 9)
            cursor.execute("DELETE FROM login_history WHERE user_id = %s AND session_id != %s", (user_id, session.get('session_id')))
            
            # Audit log
            ua = request.headers.get('User-Agent', '')
            browser, os_name, _ = parse_user_agent(ua)
            ip = request.remote_addr or '127.0.0.1'
            log_audit_event(user_id, 'PASSWORD_CHANGE', session['username'], ip, f"{browser} ({os_name})", cursor=cursor)
            
            conn.commit()
            
            # Send email asynchronously after commit
            try:
                customer_name = f"{user['FIRSTNAME']} {user['LASTNAME']}"
                subject = "Password Changed Successfully"
                plain_text = f"Dear {customer_name},\n\nYour account password has been changed successfully.\n\nIf you did not perform this action, contact support immediately."
                html_body = build_html_email(f"<p>Dear {customer_name},</p><p>Your account password has been changed successfully.</p><p style='color: #d9534f; font-weight: bold;'>If you did not perform this action, contact support immediately.</p>")
                dispatch_email_async(user['EMAIL'], subject, plain_text, html_body)
            except Exception as e_mail:
                print(f"[ERROR] Failed to dispatch password changed email: {e_mail}", flush=True)
                
            conn.close()
            return jsonify({"status": "success", "message": "Password changed successfully."})
            
        # Regular profile update
        firstname = data.get('firstname', '').strip()
        lastname = data.get('lastname', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        sex = data.get('sex', 'Male')
        address = data.get('address', '').strip()

        if not firstname or not lastname or not email or not phone or not address:
            conn.close()
            return jsonify({"status": "error", "message": "All fields are required."}), 400

        cursor.execute('''
        UPDATE NEWBANK 
        SET FIRSTNAME = %s, LASTNAME = %s, EMAIL = %s, PHONE = %s, SEX = %s, ADDRESS = %s 
        WHERE USERNAME = %s
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
        cursor.execute("SELECT * FROM NEWBANK WHERE USERNAME = %s AND PASSWORD = %s", (session['username'], password))
        user = cursor.fetchone()
        
        if user:
            cursor.execute("DELETE FROM NEWBANK WHERE USERNAME = %s", (session['username'],))
            cursor.execute("DELETE FROM face_enrollments WHERE user_id = %s", (user['ID'],))
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
    cursor.execute("SELECT enrolled_at, status FROM face_enrollments WHERE user_id = %s", (user_id,))
    enrollment = cursor.fetchone()
    
    # Query failed verification attempts
    cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = %s AND verification_result != 'SUCCESS'", (user_id,))
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


@app.route('/api/biometric/enroll/sample', methods=['POST'])
def biometric_enroll_sample():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        img_b64 = data.get('image', '')
        idx = int(data.get('index', 0))
        poses = ['Straight', 'Straight', 'Straight']
        
        if not img_b64:
            return jsonify({"status": "error", "message": "Webcam frame missing."}), 400
            
        img = decode_base64_image(img_b64)
        
        # Check dimensions
        h, w, c = img.shape
        if w < 320 or h < 240:
            return jsonify({"status": "error", "message": f"Resolution is too low: {w}x{h} (minimum 320x240)."}), 400
            
        q_check = validate_face_quality(img)
        if q_check['status'] == 'error':
            return jsonify({"status": "error", "message": q_check['message']}), 400
            
        # Success validate
        return jsonify({"status": "success", "message": f"Capture {idx+1} of 3 accepted!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/biometric/enroll', methods=['POST'])
def biometric_enroll():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        images = data.get('images', []) # Expects list of 3 base64 image strings
        
        if len(images) != 3:
            return jsonify({"status": "error", "message": "Face enrollment requires exactly 3 face samples."}), 400
            
        poses = ['Straight', 'Straight', 'Straight']
        embeddings = []
        saved_samples_metadata = []
        failed_samples = []
        sample_messages = {}
        
        for idx, img_b64 in enumerate(images):
            try:
                print(f"[BIOMETRIC ENROLL] Processing sample {idx+1}/{len(images)}", flush=True)
                img = decode_base64_image(img_b64)
                
                # Check dimensions
                h, w, c = img.shape
                if w < 320 or h < 240:
                    raise ValueError(f"Resolution is too low: {w}x{h} (minimum 320x240).")
                    
                q_check = validate_face_quality(img)
                if q_check['status'] == 'error':
                    raise ValueError(q_check['message'])
                    
                face = q_check['face']
                    
                emb = extract_face_embedding(img, face)
                embeddings.append(emb)
                
                # Save enrolled image sample (Step 5 & 8)
                meta = save_biometric_image(img, UPLOAD_DIR)
                meta['embedding'] = emb
                meta['index'] = idx
                saved_samples_metadata.append(meta)
                
                # Debug mode (Step 12)
                if FACE_DEBUG_MODE:
                    debug_meta = save_biometric_image(img, DEBUG_DIR)
                    # Create debug report
                    report_path = debug_meta['path'] + ".json"
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    face_roi = gray[int(face[1]):int(face[1]+face[3]), int(face[0]):int(face[0]+face[2])]
                    report_data = {
                        "capture_successful": True,
                        "image_saved": True,
                        "file_size": os.path.getsize(debug_meta['path']),
                        "dimensions": f"{debug_meta['width']}x{debug_meta['height']}",
                        "brightness": float(np.mean(face_roi)) if face_roi.size > 0 else 0.0,
                        "blur_score": float(cv2.Laplacian(face_roi, cv2.CV_64F).var()) if face_roi.size > 0 else 0.0,
                        "faces_detected": 1,
                        "encoding_generated": True,
                        "pose": poses[idx]
                    }
                    with open(report_path, "w") as rf:
                        json.dump(report_data, rf, indent=4)
                        
            except Exception as e:
                failed_samples.append(idx)
                sample_messages[idx] = f"Capture {idx+1}: {str(e)}"
                
        if failed_samples:
            first_fail_idx = failed_samples[0]
            first_fail_msg = sample_messages[first_fail_idx]
            if ": " in first_fail_msg:
                first_fail_msg = first_fail_msg.split(": ", 1)[1]
            return jsonify({
                "status": "error",
                "message": first_fail_msg,
                "failed_samples": failed_samples,
                "messages": sample_messages
            }), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Clear existing samples
        cursor.execute("DELETE FROM face_samples WHERE user_id = %s", (user_id,))
        
        # Save all 3 samples metadata to database
        for meta in saved_samples_metadata:
            cursor.execute('''
            INSERT INTO face_samples (user_id, sample_index, image_path, image_hash, width, height, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (user_id, meta['index'], meta['path'], meta['hash'], meta['width'], meta['height'], json.dumps(meta['embedding'])))
            
        # Calculate the L2-normalized averaged template embedding of size 128
        avg_emb_arr = np.mean(embeddings, axis=0)
        norm_val = np.linalg.norm(avg_emb_arr)
        if norm_val > 0:
            avg_emb_arr = avg_emb_arr / norm_val
        avg_embedding = avg_emb_arr.tolist()
        
        primary_meta = saved_samples_metadata[0]
        cursor.execute('''
        INSERT INTO face_enrollments (user_id, template_reference, model_name, model_version, status, enrolled_at, image_path, image_hash, width, height, capture_timestamp)
        VALUES (%s, %s, 'SFace', '1.0', 'ACTIVE', CURRENT_TIMESTAMP, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id) DO UPDATE SET 
            template_reference = EXCLUDED.template_reference,
            image_path = EXCLUDED.image_path,
            image_hash = EXCLUDED.image_hash,
            width = EXCLUDED.width,
            height = EXCLUDED.height,
            capture_timestamp = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        ''', (user_id, json.dumps(avg_embedding), primary_meta['path'], primary_meta['hash'], primary_meta['width'], primary_meta['height']))
        
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'ENROLLMENT_CREATED', 'LOW', 'User created new Face template with 3 samples')
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Face profile enrolled successfully! Biometric protection active."})
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
        
        cursor.execute("DELETE FROM face_samples WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM face_enrollments WHERE user_id = %s", (user_id,))
        
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'ENROLLMENT_DELETED', 'MEDIUM', 'User revoked/purged biometric data profile')
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
        
        # 1. Quality validation (Step 7)
        q_check = validate_face_quality(img)
        user_id = session['user_id']
        
        if q_check['status'] == 'error':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO face_verification_attempts (user_id, verification_result, liveness_result, challenge_type, model_version)
            VALUES (%s, 'ERROR', %s, %s, '1.0')
            ''', (user_id, q_check['message'], challenge))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": q_check['message']}), 400
            
        face = q_check['face']
        
        # 2. Challenge-Response Liveness Detection Check (Step 11)
        liveness_ok = check_liveness_challenge(face, challenge)
        if not liveness_ok:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO face_verification_attempts (user_id, verification_result, liveness_result, challenge_type, model_version)
            VALUES (%s, 'LIVENESS_FAILED', 'Failed head turn', %s, '1.0')
            ''', (user_id, challenge))
            
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'LIVENESS_FAILURE', 'MEDIUM', %s)
            ''', (user_id, f"Failed challenge: {challenge}"))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                "status": "liveness_failed",
                "message": f"Liveness action failed. Please turn head: {challenge.replace('_', ' ')}"
            }), 400
            
        # 3. Save Verification Image (Step 5)
        meta = save_biometric_image(img, UPLOAD_DIR)
        
        # Debug mode (Step 12)
        if FACE_DEBUG_MODE:
            debug_meta = save_biometric_image(img, DEBUG_DIR)
            report_path = debug_meta['path'] + ".json"
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            face_roi = gray[int(face[1]):int(face[1]+face[3]), int(face[0]):int(face[0]+face[2])]
            report_data = {
                "capture_successful": True,
                "image_saved": True,
                "file_size": os.path.getsize(debug_meta['path']),
                "dimensions": f"{debug_meta['width']}x{debug_meta['height']}",
                "brightness": float(np.mean(face_roi)) if face_roi.size > 0 else 0.0,
                "blur_score": float(cv2.Laplacian(face_roi, cv2.CV_64F).var()) if face_roi.size > 0 else 0.0,
                "faces_detected": 1,
                "encoding_generated": True,
                "liveness_challenge": challenge
            }
            with open(report_path, "w") as rf:
                json.dump(report_data, rf, indent=4)
                
        # 4. 1:1 Face Similarity Match (Step 10)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT template_reference FROM face_enrollments WHERE user_id = %s", (user_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({"status": "no_enrollment", "message": "Biometric face profile not found for this account."}), 404
            
        stored_emb = json.loads(row['template_reference'])
        current_emb = extract_face_embedding(img, face)
        
        is_match, similarity, threshold = calculate_similarity(stored_emb, current_emb)
        
        # Clear challenge
        session.pop('liveness_challenge', None)
        
        # Log attempts
        result_str = 'SUCCESS' if is_match else 'MISMATCH'
        cursor.execute('''
        INSERT INTO face_verification_attempts (user_id, verification_result, similarity_or_distance, threshold, liveness_result, challenge_type, model_version, image_path, image_hash, width, height, capture_timestamp)
        VALUES (%s, %s, %s, %s, 'PASSED', %s, '1.0', %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ''', (user_id, result_str, similarity, threshold, challenge, meta['path'], meta['hash'], meta['width'], meta['height']))
        
        if is_match:
            # Mark face_verified in pending transaction
            token = session.get('mfa_pending_token') or (data.get('transaction_token') if data else None)
            if token:
                cursor.execute("UPDATE pending_transactions SET face_verified = 1 WHERE token = %s", (token,))
                
            # Check if transaction can be finalized now
            should_finalize = False
            if token:
                cursor.execute("SELECT otp_verified, face_verified, risk_level, status, decision_trace, amount FROM pending_transactions WHERE token = %s", (token,))
                ptx = cursor.fetchone()
                if ptx:
                    trace = {}
                    try:
                        trace = json.loads(ptx['decision_trace'] or '{}')
                    except:
                        pass
                    
                    is_biometric_fallback = bool(trace.get('biometric_fallback'))
                    is_high_val = (ptx['amount'] > 20000.0)
                    
                    if ptx['status'] == 'PENDING':
                        if is_biometric_fallback and ptx['face_verified']:
                            should_finalize = True
                        elif ptx['otp_verified'] and ptx['face_verified']:
                            should_finalize = True
                        elif ptx['otp_verified'] and not is_high_val and ptx['risk_level'] != 'HIGH':
                            should_finalize = True

            # Also check if there is a pending Razorpay deposit > ₹20,000 for this user
            cursor.execute('''
            SELECT * FROM deposits 
            WHERE user_id = %s AND status = 'PENDING_BIOMETRIC' 
            ORDER BY timestamp DESC LIMIT 1
            ''', (user_id,))
            pending_dep = cursor.fetchone()
            
            if pending_dep:
                dep_id = pending_dep['id']
                dep_amount = pending_dep['amount']
                dep_ref = pending_dep['reference_id']
                pay_id = pending_dep['razorpay_payment_id']
                
                cursor.execute("SELECT BAL, EMAIL FROM NEWBANK WHERE ID = %s", (user_id,))
                user_row = cursor.fetchone()
                cur_bal = user_row['BAL'] if user_row else 0.0
                u_email = user_row['EMAIL'] if user_row else ""
                n_bal = cur_bal + dep_amount
                
                cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE ID = %s", (n_bal, user_id))
                
                cursor.execute('''
                UPDATE deposits 
                SET status = 'APPROVED', 
                    balance_before = %s, 
                    balance_after = %s, 
                    remarks = 'Razorpay Payment Verified & Biometric Approved'
                WHERE id = %s
                ''', (cur_bal, n_bal, dep_id))
                
                cursor.execute('''
                INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
                VALUES (%s, 'Wallet', 'ADD_MONEY', %s, %s, %s, 0.0, 0.0, 'APPROVED', 0, %s)
                ''', (session['username'], dep_amount, cur_bal, n_bal, json.dumps({"gateway": "Razorpay Test Mode", "payment_id": pay_id, "biometric_verified": True})))
                
                cursor.execute('''
                INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
                VALUES (%s, 'WALLET_DEPOSIT_BIOMETRIC_SUCCESS', 'LOW', %s)
                ''', (user_id, f"High value deposit INR {dep_amount} authorized via Biometric Face Verification."))
                
                conn.commit()
                conn.close()
                
                if u_email:
                    try:
                        send_deposit_email(u_email, dep_ref, dep_amount, cur_bal, n_bal, payment_id=pay_id)
                    except Exception as e_mail:
                        print(f"[WARN] Deposit email notification failed: {e_mail}", flush=True)

                return jsonify({
                    "status": "success",
                    "message": "Biometric face verification passed! Smart Wallet credited successfully.",
                    "new_balance": n_bal,
                    "reference_id": dep_ref
                })

            conn.commit()
            conn.close()
            
            if should_finalize and token:
                return finalize_pending_transaction(token)
                
            return jsonify({
                "status": "success",
                "message": "Face verified successfully! Liveness matching passed.",
                "similarity": round(similarity * 100, 2),
                "similarity_raw": similarity,
                "threshold": threshold
            })
        else:
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'FACE_MISMATCH', 'HIGH', %s)
            ''', (user_id, f"Similarity: {similarity:.4f} below threshold: {threshold:.4f}"))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                "status": "mismatch",
                "message": "Biometric verification failed. Face does not match the enrolled owner.",
                "similarity": round(similarity * 100, 2),
                "similarity_raw": similarity,
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

@app.route('/api/admin/face/debug/<int:user_id>', methods=['GET'])
def admin_face_debug(user_id):
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Fetch enrollment samples metadata
        cursor.execute("SELECT sample_index, image_path, image_hash, width, height, capture_timestamp FROM face_samples WHERE user_id = %s ORDER BY sample_index ASC", (user_id,))
        samples_rows = cursor.fetchall()
        samples = []
        for r in samples_rows:
            exists = os.path.exists(r['image_path']) if r['image_path'] else False
            samples.append({
                "sample_index": r['sample_index'],
                "image_path": r['image_path'],
                "image_hash": r['image_hash'],
                "width": r['width'],
                "height": r['height'],
                "capture_timestamp": str(r['capture_timestamp']),
                "file_exists": exists
            })
            
        # 2. Fetch main enrollment
        cursor.execute("SELECT image_path, image_hash, width, height, capture_timestamp, status FROM face_enrollments WHERE user_id = %s", (user_id,))
        enrollment_row = cursor.fetchone()
        enrollment = None
        if enrollment_row:
            exists = os.path.exists(enrollment_row['image_path']) if enrollment_row['image_path'] else False
            enrollment = {
                "image_path": enrollment_row['image_path'],
                "image_hash": enrollment_row['image_hash'],
                "width": enrollment_row['width'],
                "height": enrollment_row['height'],
                "capture_timestamp": str(enrollment_row['capture_timestamp']),
                "status": enrollment_row['status'],
                "file_exists": exists
            }
            
        # 3. Fetch verification attempts history
        cursor.execute("SELECT verification_result, similarity_or_distance, threshold, challenge_type, attempted_at, image_path, image_hash, width, height FROM face_verification_attempts WHERE user_id = %s ORDER BY attempted_at DESC LIMIT 20", (user_id,))
        attempts_rows = cursor.fetchall()
        attempts = []
        for r in attempts_rows:
            exists = os.path.exists(r['image_path']) if r['image_path'] else False
            attempts.append({
                "verification_result": r['verification_result'],
                "similarity": r['similarity_or_distance'],
                "threshold": r['threshold'],
                "challenge_type": r['challenge_type'],
                "attempted_at": str(r['attempted_at']),
                "image_path": r['image_path'],
                "image_hash": r['image_hash'],
                "width": r['width'],
                "height": r['height'],
                "file_exists": exists
            })
            
        conn.close()
        return jsonify({
            "status": "success",
            "user_id": user_id,
            "enrollment": enrollment,
            "samples": samples,
            "verification_history": attempts
        })
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500


# --- Hybrid Risk Score Engine ---
def compute_hybrid_risk(sender_id, sender_username, receiver, amount, ttype):
    # Base risk is 10
    risk_score = 10
    reasons = []
    
    # 1. Rule-Based checks: Amount
    amount_points = 0
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
    cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = %s", (sender_username,))
    sender_bal_row = cursor.fetchone()
    sender_bal = sender_bal_row['BAL'] if sender_bal_row else 0.0
    
    empty_account_points = 0
    if ttype != 'ADD_MONEY' and sender_bal > 0 and (amount / sender_bal) > 0.85:
        empty_account_points = 25
        risk_score += 25
        reasons.append("Account Emptying Anomaly (Transferring >85% of liquid balance)")
        
    # Check if beneficiary is a new recipient / beneficiary risk
    new_recipient_points = 0
    if ttype not in ['ADD_MONEY', 'CASH_OUT'] and receiver not in ['Wallet', 'ATM_01'] and not str(receiver).startswith('ATM_'):
        cursor.execute("SELECT COUNT(*) FROM NEWT WHERE SENDER = %s AND RECEIVER = %s AND STATUS = 'APPROVED'", (sender_username, receiver))
        recipient_history = cursor.fetchone()[0]
        if recipient_history == 0:
            new_recipient_points = 15
            risk_score += 15
            reasons.append("New Unverified Beneficiary Target")
        
    # 2. Supervised ML prediction: Random Forest Model (Genuinely Continuous Probability Calibration)
    is_fraud_predicted = 0
    ml_model_points = 0
    ml_probability = 0.0
    if model is not None and ttype in ['TRANSFER', 'CASH_OUT', 'QR_PAYMENT']:
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = %s", (receiver,))
        receiver_bal_row = cursor.fetchone()
        receiver_bal = receiver_bal_row['BAL'] if receiver_bal_row else 0.0
        
        df_pred = pd.DataFrame([{
            'type': 'TRANSFER' if ttype == 'QR_PAYMENT' else ttype,
            'amount': amount,
            'oldbalanceOrig': sender_bal,
            'newbalanceOrig': sender_bal - amount,
            'oldbalanceDest': receiver_bal,
            'newbalanceDest': receiver_bal + amount
        }])
        try:
            pred = model.predict(df_pred)[0]
            is_fraud_predicted = int(pred)
            
            probs = model.predict_proba(df_pred)[0]
            ml_probability = float(probs[1])
            
            # Genuinely continuous & bounded scoring: min(50, round(p * 50))
            ml_model_points = min(50, max(0, int(round(ml_probability * 50))))
            risk_score += ml_model_points
            
            if is_fraud_predicted == 1 or ml_probability >= 0.50:
                reasons.append(f"Random Forest ML Flag: {ml_probability*100:.1f}% estimated fraud probability (+{ml_model_points} pts)")
            elif ml_probability > 0.05:
                reasons.append(f"Random Forest ML Signal: {ml_probability*100:.1f}% estimated fraud probability (+{ml_model_points} pts)")
        except Exception:
            pass

    # 3. Behavioral Anomaly Detection
    behavioral_points = 0
    try:
        cursor.execute('''
        SELECT AMOUNT, TIMESTAMP FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' 
        ORDER BY ID DESC LIMIT 50
        ''', (sender_username,))
        history_rows = cursor.fetchall()
        
        if len(history_rows) >= 3:
            past_amounts = [float(r['AMOUNT']) for r in history_rows]
            mean_amt = float(np.mean(past_amounts)) if len(past_amounts) > 0 else 0.0
            std_amt = float(np.std(past_amounts)) if len(past_amounts) > 0 else 0.0
            max_past_amt = float(max(past_amounts)) if len(past_amounts) > 0 else 0.0
            
            if std_amt > 0 and amount > (mean_amt + 3.0 * std_amt) and amount > (max_past_amt * 1.5):
                b_pts = 15
                reasons.append(f"Behavioral Anomaly: Amount INR {amount:,.2f} significantly exceeds historical average (INR {mean_amt:,.2f})")
                behavioral_points += b_pts
                risk_score += b_pts
            elif std_amt > 0 and amount > (mean_amt + 2.0 * std_amt) and amount > (max_past_amt * 1.2):
                b_pts = 10
                reasons.append(f"Behavioral Deviation: Amount INR {amount:,.2f} higher than typical customer range (INR {mean_amt:,.2f})")
                behavioral_points += b_pts
                risk_score += b_pts
        else:
            reasons.append("Neutral profile: Insufficient transaction history for behavioral profiling")
    except Exception:
        pass

    # 4. Enhanced Behavior Velocity: Transaction count inside 5 & 30 minutes
    velocity_points = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM NEWT WHERE SENDER = %s AND TIMESTAMP >= datetime('now', '-5 minutes')", (sender_username,))
        recent_transfers = cursor.fetchone()[0]
        
        if recent_transfers >= 3:
            velocity_points = 25
            risk_score += 25
            reasons.append("Velocity Anomaly: Extreme transactional frequency (>= 3 in 5 min)")
        elif recent_transfers > 0:
            velocity_points = 10
            risk_score += 10
            reasons.append("Rapid Velocity: Multiple transfers in last 5 minutes")
    except Exception:
        pass

    # 5. Biometric signals: Failures in last 15 minutes
    biometric_points = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM face_verification_attempts WHERE user_id = %s AND verification_result != 'SUCCESS' AND attempted_at >= datetime('now', '-15 minutes')", (sender_id,))
        recent_biometric_fails = cursor.fetchone()[0]
        if recent_biometric_fails > 0:
            biometric_points = 25 * recent_biometric_fails
            risk_score += biometric_points
            reasons.append(f"Biometric Failure Warning: {recent_biometric_fails} failed face/liveness attempts recently")
    except Exception:
        pass

    conn.close()

    # Cap risk score at 100
    risk_score = min(100, max(0, risk_score))

    # Determine risk level based on thresholds
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
        "behavioral_points": behavioral_points,
        "velocity_points": velocity_points,
        "biometric_points": biometric_points
    }

    return risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability

# --- Transaction API endpoints ---
@app.route('/api/transfer/initiate', methods=['POST'])
def transfer_initiate():
    start_time = time.time()
    print("START /api/transfer/initiate", flush=True)
    
    conn = None
    try:
        print(f"[DEBUG] [Step 1: Request received] elapsed: {time.time() - start_time:.4f}s", flush=True)
        
        if 'username' not in session:
            print(f"[DEBUG] [Step 2: User authentication failed] elapsed: {time.time() - start_time:.4f}s", flush=True)
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
            
        print(f"[DEBUG] [Step 2: User authentication verified] User: {session['username']}", flush=True)
        
        data = request.get_json()
        if not data:
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Missing request payload."}), 400

        receiver = data.get('receiver', '').strip()
        amount_str = data.get('amount', '0')
        ttype = data.get('type', 'TRANSFER').strip().upper()

        try:
            amount = clean_and_parse_amount(amount_str)
        except ValueError:
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Invalid transfer amount format."}), 400

        if amount <= 0:
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Transfer amount must be greater than zero."}), 400

        sender = session['username']
        sender_id = session.get('user_id')

        t_db = time.time()
        conn = get_db_connection()
        cursor = conn.cursor()
        print(f"[DEBUG] [Database connection opened] took {time.time() - t_db:.4f}s", flush=True)

        # Check transaction type
        if ttype not in ['TRANSFER', 'CASH_OUT', 'QR_PAYMENT']:
            conn.close()
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Invalid transaction type."}), 400

        if ttype == 'QR_PAYMENT':
            qr_token = data.get('qr_token', '').strip()
            if not qr_token:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Signed QR token is required for QR payments."}), 400
            try:
                from itsdangerous import URLSafeTimedSerializer
                serializer = URLSafeTimedSerializer(app.secret_key, salt="qr-payment-salt")
                token_data = serializer.loads(qr_token, max_age=300)
                token_receiver = token_data["username"]
                if token_receiver != receiver:
                    conn.close()
                    print("END /api/transfer/initiate", flush=True)
                    print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                    return jsonify({"status": "error", "message": "QR token does not match recipient."}), 400
            except Exception:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Invalid or expired QR code token."}), 400

        # Check receiver exists based on transaction type
        t_rec = time.time()
        if ttype in ['TRANSFER', 'QR_PAYMENT']:
            cursor.execute("SELECT ID, BAL FROM NEWBANK WHERE USERNAME = %s", (receiver,))
            receiver_row = cursor.fetchone()
            if not receiver_row:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Receiver username not found."}), 404
            if receiver == sender:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Cannot transfer to yourself."}), 400
        else: # CASH_OUT
            cursor.execute("SELECT * FROM cash_out_channels WHERE id = %s AND status = 'ACTIVE'", (receiver,))
            channel_row = cursor.fetchone()
            if not channel_row:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Invalid or inactive cash out channel."}), 400
            if receiver == sender:
                conn.close()
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Cannot cash out to yourself."}), 400
            receiver_row = {'BAL': 0.0}
        print(f"[DEBUG] [Step 3: Recipient validation completed] took {time.time() - t_rec:.4f}s", flush=True)

        # Get sender details
        t_bal = time.time()
        cursor.execute("SELECT BAL, EMAIL FROM NEWBANK WHERE USERNAME = %s", (sender,))
        sender_row = cursor.fetchone()
        sender_balance = sender_row['BAL']
        sender_email = sender_row['EMAIL']
        if not sender_email:
            conn.close()
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Registered email address not found."}), 404

        if sender_balance < amount:
            conn.close()
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({"status": "error", "message": "Insufficient balance."}), 400
        print(f"[DEBUG] [Step 4: Balance validation completed] took {time.time() - t_bal:.4f}s", flush=True)

        # Run Hybrid Risk Engine
        t_risk = time.time()
        risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability = compute_hybrid_risk(
            sender_id, sender, receiver, amount, ttype
        )
        print(f"[DEBUG] [Step 5: Risk score calculated] Score: {risk_score}, Level: {risk_level}, took {time.time() - t_risk:.4f}s", flush=True)
        print(f"[DEBUG] [Step 6: Risk classification completed] Level: {risk_level}", flush=True)

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

        # Phase 4 XAI features
        triggered_policies = []
        feature_contributions = {}
        total_points = sum(breakdown.values()) or 1
        for feat, pts in breakdown.items():
            pct = int((pts / total_points) * 100)
            if pct > 0:
                feature_contributions[feat] = pct
                
        for r in reasons:
            if "High Volume" in r or "large transaction" in r.lower():
                triggered_policies.append("POL-101: Large Transaction Threshold")
            elif "Emptying" in r or "liquid balance" in r.lower():
                triggered_policies.append("POL-102: Liquidity Depletion Check")
            elif "Velocity" in r or "rapid successive" in r.lower():
                triggered_policies.append("POL-103: Transfer Velocity Limit")
            elif "Beneficiary" in r or "new recipient" in r.lower():
                triggered_policies.append("POL-104: Unverified Recipient Verification")
            elif "Model" in r or "fraud predicted" in r.lower():
                triggered_policies.append("POL-105: Supervised ML Model Anomaly")
                
        if not triggered_policies:
            triggered_policies.append("POL-000: Standard Low Risk Profile")
            
        if risk_level == 'LOW':
            recommendation = "Approved: No immediate threat flags detected."
            confidence = max(90, 100 - risk_score)
        elif risk_level == 'MEDIUM':
            recommendation = "MFA Required: Request 2FA verification to confirm user identity."
            confidence = max(80, 100 - risk_score)
        elif risk_level == 'HIGH':
            recommendation = "Adaptive MFA Required: OTP + Face Biometrics required to verify live authorization."
            confidence = max(75, 100 - risk_score)
        else:
            recommendation = "Hold: Intercept transaction and route to manual review queue."
            confidence = max(95, risk_score)

        decision_trace = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "breakdown": breakdown,
            "ml_probability": ml_probability,
            "feature_importances": feature_importances,
            "auth_required": [],
            "auth_completed": [],
            "confidence": confidence,
            "feature_contributions": feature_contributions,
            "triggered_policies": triggered_policies,
            "recommendation": recommendation
        }

        if risk_level == 'MEDIUM':
            decision_trace['auth_required'] = ['otp']
        elif risk_level == 'HIGH':
            decision_trace['auth_required'] = ['otp', 'face']
        elif risk_level == 'CRITICAL':
            decision_trace['auth_required'] = ['admin_review']

        # Check if user has biometric face profile enrolled
        cursor.execute("SELECT id FROM face_enrollments WHERE user_id = %s", (sender_id,))
        has_face_enrolled = (cursor.fetchone() is not None)

        is_high_value = (amount > 20000.0)

        # High value (> ₹20,000) transactions require face verification
        is_high_value = (amount > 20000.0)

        # Enforce enrollment requirement for HIGH risk transactions
        if risk_level == 'HIGH' and not has_face_enrolled:
            conn.close()
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({
                "status": "error",
                "message": "Biometric face enrollment is required to verify high-risk transactions. Please enroll your face first."
            }), 400

        # Generate token
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

        # Velocity Security Floor Check (>=3 transfers in 5 mins forces minimum MEDIUM / OTP challenge)
        velocity_points = breakdown.get('velocity_points', 0)
        is_velocity_escalated = (velocity_points >= 25)
        
        if is_velocity_escalated and risk_level == 'LOW':
            reasons.append("Velocity Security Escalation: Extreme transaction frequency (>= 3 in 5 min) enforces OTP verification security floor.")
            effective_risk_level = 'MEDIUM'
            decision_trace['velocity_floor_triggered'] = True
            decision_trace['auth_required'] = ['otp']
        else:
            effective_risk_level = risk_level

        # LOW RISK (without velocity escalation): Auto approve
        if effective_risk_level == 'LOW':
            print(f"[DEBUG] [Step 12: Pending transaction creation started (LOW)]", flush=True)
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, otp_verified, face_verified, expires_at, decision_trace)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, %s, %s)
            ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))
            
            t_commit = time.time()
            conn.commit()
            print(f"[DEBUG] [Step 13: Database commit completed (LOW)] took {time.time() - t_commit:.4f}s", flush=True)
            
            res = finalize_pending_transaction(token)
            conn.close()
            print(f"[DEBUG] [Step 14: JSON response returned (LOW)]", flush=True)
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return res

        # CRITICAL RISK: Queue for Admin Review
        if risk_level == 'CRITICAL':
            print(f"[DEBUG] [Step 12: Pending transaction creation started (CRITICAL)]", flush=True)
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, expires_at, status, decision_trace)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING_REVIEW', %s)
            ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))

            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'TRANSACTION_HELD_FOR_REVIEW', 'HIGH', %s)
            RETURNING ID
            ''', (sender_id, f"Transaction {amount} to {receiver} held for admin review due to CRITICAL risk score {risk_score}."))

            tx_id = cursor.fetchone()[0]
            
            t_commit = time.time()
            conn.commit()
            print(f"[DEBUG] [Step 13: Database commit completed (CRITICAL)] took {time.time() - t_commit:.4f}s", flush=True)
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

            print(f"[DEBUG] [Step 14: JSON response returned (CRITICAL)]", flush=True)
            print("END /api/transfer/initiate", flush=True)
            print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
            return jsonify({
                "status": "pending_review",
                "message": "Security Alert: This transaction exhibits CRITICAL risk indicators. It has been queued for Administrator Review. No funds will move until approved.",
                "transaction_token": token,
                "score": risk_score,
                "level": risk_level,
                "reasons": reasons
            })

        # MEDIUM/HIGH RISK: Needs Verification (OTP / Biometric Face)
        t_otp_gen = time.time()
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hashed = hash_otp(otp)
        print(f"[DEBUG] [Step 7: OTP generation completed] took {time.time() - t_otp_gen:.4f}s", flush=True)

        print(f"[DEBUG] [Step 12: Pending transaction creation started ({risk_level})]", flush=True)
        cursor.execute('''
        INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, expires_at, decision_trace)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (token, sender_id, receiver, amount, ttype, risk_score, risk_level, json.dumps(reasons), is_fraud_predicted, expires_at, json.dumps(decision_trace)))

        t_challenge = time.time()
        cursor.execute('''
        INSERT INTO transaction_otp_challenges (user_id, transaction_token, otp_hash, expires_at, last_sent_at)
        VALUES (%s, %s, %s, %s, datetime('now'))
        ''', (sender_id, token, otp_hashed, expires_at))      
        print(f"[DEBUG] [Step 8: OTP database insert completed] took {time.time() - t_challenge:.4f}s", flush=True)
        
        if risk_level == 'HIGH':
            print(f"[DEBUG] [Step 11: Face verification challenge creation completed]", flush=True)

        t_commit = time.time()
        conn.commit()
        print(f"[DEBUG] [Step 13: Database commit completed ({risk_level})] took {time.time() - t_commit:.4f}s", flush=True)
        conn.close()


        t_mail = time.time()
        print(f"[DEBUG] [Step 9: SMTP email send started] To: {sender_email}", flush=True)
        mail_ok, mail_reason = False, "UNKNOWN"
        try:
            res_mail = send_otp_email(sender_email, otp, amount, receiver)
            if isinstance(res_mail, tuple):
                mail_ok, mail_reason = res_mail
            else:
                mail_ok, mail_reason = bool(res_mail), ("SUCCESS" if res_mail else "UNKNOWN")
        except Exception as mail_err:
            print(f"[DEBUG] [SMTP email send failed] Error: {mail_err}", flush=True)
            mail_ok, mail_reason = False, "EXCEPTION"

        parts = sender_email.split('@')
        name = parts[0]
        domain = parts[1]
        if len(name) > 2:
            masked_name = name[0] + '*' * (len(name) - 2) + name[-1]
        else:
            masked_name = name[0] + '*'
        masked_email = f"{masked_name}@{domain}"

        if not mail_ok:
            if mail_reason == "RESEND_TEST_DOMAIN_RESTRICTION":
                # DEMO-SAFE BIOMETRIC FALLBACK TRIGGERED!
                trace = json.loads(decision_trace or '{}') if isinstance(decision_trace, str) else (decision_trace or {})
                trace['biometric_fallback'] = 1
                trace['fallback_reason'] = "RESEND_TEST_DOMAIN_RESTRICTION"

                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE pending_transactions 
                SET decision_trace = %s
                WHERE token = %s
                ''', (json.dumps(trace), token))

                log_metadata = {
                    "amount": amount,
                    "receiver": receiver,
                    "reason": "RESEND_TEST_DOMAIN_RESTRICTION",
                    "transaction_token": token
                }
                log_audit_event(sender_id, 'BIOMETRIC_FALLBACK_TRIGGERED', sender[0], request.remote_addr or '127.0.0.1', request.headers.get('User-Agent', ''), log_metadata, cursor=cursor)

                cursor.execute('''
                INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
                VALUES (%s, 'BIOMETRIC_FALLBACK_TRIGGERED', 'MEDIUM', %s)
                ''', (sender_id, f"Demo Biometric Fallback activated for INR {amount} transfer due to Resend recipient test-domain restriction."))

                conn.commit()
                conn.close()

                required_auths = ["face"]

                print(f"[DEBUG] [Step 14: JSON response returned (BIOMETRIC_FALLBACK)]", flush=True)
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({
                    "status": "verification_required",
                    "biometric_fallback": True,
                    "fallback_reason": "RESEND_TEST_DOMAIN_RESTRICTION",
                    "required": required_auths,
                    "transaction_token": token,
                    "masked_email": masked_email,
                    "expires_in": 300,
                    "score": risk_score,
                    "level": risk_level,
                    "reasons": reasons,
                    "message": "DEMO FALLBACK: Resend test-domain restriction active for recipient email. Biometric Face Verification required to authorize transaction."
                }), 200
            else:
                t_rollback = time.time()
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM transaction_otp_challenges WHERE transaction_token = %s", (token,))
                cursor.execute("DELETE FROM pending_transactions WHERE token = %s", (token,))
                conn.commit()
                conn.close()
                print(f"[DEBUG] [Database rollback cleanup completed] took {time.time() - t_rollback:.4f}s", flush=True)
                print("END /api/transfer/initiate", flush=True)
                print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Unable to deliver the OTP email. Please try again."}), 500

        print(f"[DEBUG] [Step 10: SMTP email send completed] took {time.time() - t_mail:.4f}s", flush=True)

        required_auths = ["otp"]
        if risk_level == 'HIGH' or is_high_value:
            required_auths.append("face")

        print(f"[DEBUG] [Step 14: JSON response returned ({risk_level})]", flush=True)
        print("END /api/transfer/initiate", flush=True)
        print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
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
        if conn:
            try:
                conn.close()
            except:
                pass
        print(f"[DEBUG] [Unhandled exception caught] Error: {e}", flush=True)
        print("END /api/transfer/initiate", flush=True)
        print(f"TOTAL REQUEST TIME: {time.time() - start_time:.4f}s", flush=True)
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
        WHERE transaction_token = %s AND user_id = %s
        ''', (token, user_id))
        challenge = cursor.fetchone()
        
        if not challenge:
            conn.close()
            return jsonify({"status": "error", "message": "Verification challenge not found."}), 404
            
        exp_dt = parse_datetime_safe(challenge['expires_at'])
        now_dt = get_utc_now()
        if (exp_dt and exp_dt < now_dt) or challenge['consumed'] or challenge['verified']:
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
            SET attempts = %s 
            WHERE id = %s
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
        WHERE id = %s
        ''', (challenge['id'],))
        
        cursor.execute('''
        UPDATE pending_transactions 
        SET otp_verified = 1 
        WHERE token = %s
        ''', (token,))
        
        cursor.execute("SELECT risk_level FROM pending_transactions WHERE token = %s", (token,))
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

        cursor.execute("SELECT EMAIL FROM NEWBANK WHERE ID = %s", (user_id,))
        email_row = cursor.fetchone()
        email = email_row['EMAIL'] if email_row else None
        if not email:
            conn.close()
            return jsonify({"status": "error", "message": "Registered email address not found."}), 404
        
        cursor.execute('''
        SELECT * FROM transaction_otp_challenges 
        WHERE transaction_token = %s AND user_id = %s
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
            
        last_sent_dt = parse_datetime_safe(challenge['last_sent_at'])
        if last_sent_dt:
            diff = (get_utc_now() - last_sent_dt).total_seconds()
            if diff < 60:
                conn.close()
                return jsonify({"status": "error", "message": f"Please wait {60 - int(diff)} seconds before resending."}), 400
                
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hashed = hash_otp(otp)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
        UPDATE transaction_otp_challenges 
        SET otp_hash = %s, expires_at = %s, last_sent_at = datetime('now'), resend_count = resend_count + 1, attempts = 0
        WHERE id = %s
        ''', (otp_hashed, expires_at, challenge['id']))
        
        cursor.execute('''
        UPDATE pending_transactions 
        SET expires_at = %s 
        WHERE token = %s
        ''', (expires_at, token))
        
            
        cursor.execute("SELECT amount, receiver FROM pending_transactions WHERE token = %s", (token,))
        pending_tx = cursor.fetchone()
        
        success = False
        try:
            success = send_otp_email(email, otp, pending_tx['amount'], pending_tx['receiver'])
        except Exception as mail_err:
            print(f"[DEBUG] [SMTP email send failed] Error: {mail_err}", flush=True)
            
        if not success:
            conn.rollback()
            conn.close()
            return jsonify({"status": "error", "message": "Unable to deliver the OTP email. Please try again."}), 500
            
        conn.commit()
        conn.close()
            
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
        
        cursor.execute("SELECT * FROM pending_transactions WHERE token = %s", (token,))
        pending = cursor.fetchone()
        
        if not pending:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Pending transaction details not found."}), 404
            
        if pending['status'] != 'PENDING':
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Transaction has already been processed or expired."}), 400
            
        exp_dt = parse_datetime_safe(pending['expires_at'])
        now_dt = get_utc_now()
        if exp_dt and exp_dt < now_dt:
            cursor.execute("UPDATE pending_transactions SET status = 'EXPIRED' WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": "Transaction verification window has expired."}), 400
            
        # Parse decision_trace
        trace = {}
        try:
            trace = json.loads(pending['decision_trace'] or '{}')
        except:
            pass

        is_biometric_fallback = bool(trace.get('biometric_fallback'))

        # 1. OTP Verification check (bypassed ONLY if biometric_fallback is active AND face_verified is 1)
        if not pending['otp_verified'] and not (is_biometric_fallback and pending['face_verified']):
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "OTP verification required."}), 400

        # 2. Face Verification check (required if HIGH risk or Biometric Fallback)
        if (pending['risk_level'] == 'HIGH' or is_biometric_fallback) and not pending['face_verified']:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Biometric face verification required."}), 400
            
        sender_id = pending['user_id']
        receiver = pending['receiver']
        amount = pending['amount']
        ttype = pending['ttype']
        is_fraud_predicted = pending['is_fraud_predicted']
        
        cursor.execute("SELECT USERNAME, BAL FROM NEWBANK WHERE ID = %s", (sender_id,))
        sender_row = cursor.fetchone()
        sender = sender_row['USERNAME']
        sender_bal = sender_row['BAL']
        
        if ttype in ['TRANSFER', 'QR_PAYMENT']:
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = %s", (receiver,))
            receiver_row = cursor.fetchone()
            receiver_bal = receiver_row['BAL']
            receiver_new_bal = receiver_bal + amount
        else: # CASH_OUT or ADD_MONEY
            receiver_bal = 0.0
            receiver_new_bal = 0.0
            
        if ttype != 'ADD_MONEY' and sender_bal < amount:
            cursor.execute("UPDATE pending_transactions SET status = 'FAILED' WHERE token = ?", (token,))
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Insufficient balance at finalization."}), 400
            
        if ttype == 'ADD_MONEY':
            sender_new_bal = sender_bal + amount
        else:
            sender_new_bal = sender_bal - amount
        
        cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE ID = %s", (sender_new_bal, sender_id))
        if ttype in ['TRANSFER', 'QR_PAYMENT']:
            cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE USERNAME = %s", (receiver_new_bal, receiver))
            
        if ttype == 'ADD_MONEY':
            cursor.execute("UPDATE deposits SET status = 'APPROVED', balance_after = %s WHERE reference_id = %s", (sender_new_bal, token))
            
        cursor.execute("UPDATE pending_transactions SET status = 'COMPLETED' WHERE token = ?", (token,))
        
        # Audit logging for completed transactions
        log_metadata = {"amount": amount, "sender": sender, "receiver": receiver, "token": token, "risk_score": pending['risk_score']}
        log_audit_event(sender_id, ttype, sender, None, None, log_metadata, cursor)
        
        # Notify
        if ttype == 'ADD_MONEY':
            create_notification(sender_id, "Smart Wallet Credit", f"Successfully topped up wallet with Rs {amount:.2f}.", "DEPOSIT", cursor=cursor)
        elif ttype in ['TRANSFER', 'QR_PAYMENT']:
            create_notification(sender_id, "Funds Transferred", f"Debit of Rs {amount:.2f} to {receiver} completed.", "TRANSFER", cursor=cursor)
            try:
                # Try loading recipient ID to notify them
                cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = %s", (receiver,))
                rec_row = cursor.fetchone()
                if rec_row:
                    create_notification(rec_row['ID'], "Funds Credited", f"Credit of Rs {amount:.2f} from {sender} received.", "TRANSFER", cursor=cursor)
            except Exception as e_noti:
                print(f"[ERROR] Failed to notify receiver: {e_noti}", flush=True)

        # Phase 2: Update beneficiary transfer stats / auto-add recipient
        if ttype in ['TRANSFER', 'QR_PAYMENT']:
            try:
                cursor.execute("SELECT id FROM beneficiaries WHERE user_id = %s AND beneficiary_username = %s", (sender_id, receiver))
                b_row = cursor.fetchone()
                if b_row:
                    cursor.execute('''
                    UPDATE beneficiaries 
                    SET transfer_count = transfer_count + 1, total_transferred = total_transferred + %s 
                    WHERE user_id = %s AND beneficiary_username = %s
                    ''', (amount, sender_id, receiver))
                else:
                    cursor.execute('''
                    INSERT INTO beneficiaries (user_id, beneficiary_username, nickname, transfer_count, total_transferred)
                    VALUES (%s, %s, %s, 1, %s)
                    ''', (sender_id, receiver, receiver, amount))
            except Exception as e_b:
                print(f"[ERROR] Failed to update beneficiary stats: {e_b}", flush=True)
        
        cursor.execute('''
        UPDATE transaction_otp_challenges 
        SET consumed = 1, consumed_at = datetime('now') 
        WHERE transaction_token = %s
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'APPROVED', %s, %s)
            RETURNING ID
        ''', (sender, receiver, ttype, amount, sender_bal, sender_new_bal, receiver_bal, receiver_new_bal, is_fraud_predicted, json.dumps(decision_trace)))
        
        tx_id = cursor.fetchone()[0]
        
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
        if ttype == 'ADD_MONEY':
            try:
                cursor.execute("SELECT EMAIL FROM NEWBANK WHERE ID = %s", (sender_id,))
                email_row = cursor.fetchone()
                if email_row and email_row['EMAIL']:
                    send_deposit_email(email_row['EMAIL'], token, amount, sender_bal, sender_new_bal)
            except Exception as ee:
                print("[WARN] Failed to send deposit confirmation email", ee)
        conn.close()
        
        session.pop('mfa_pending_token', None)
        
        return jsonify({
            "status": "success",
            "message": "Transfer completed successfully.",
            "new_balance": sender_new_bal,
            "transaction_id": tx_id
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
    WHERE SENDER = %s OR RECEIVER = %s 
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
            'type': 'TRANSFER' if ttype == 'QR_PAYMENT' else ttype,
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
        
    models_dir = os.path.join(str(BASE_DIR), 'models')
    yunet_path = os.path.join(models_dir, 'face_detection_yunet_2023mar.onnx')
    sface_path = os.path.join(models_dir, 'face_recognition_sface_2021dec.onnx')
    
    detector_exists = os.path.exists(yunet_path)
    recognizer_exists = os.path.exists(sface_path)
    
    return jsonify({
        "status": "success",
        "detector_loaded": face_detector is not None,
        "recognizer_loaded": face_recognizer is not None,
        "detector_model_filename": os.path.basename(yunet_path) if detector_exists else "missing",
        "recognizer_model_filename": os.path.basename(sface_path) if recognizer_exists else "missing",
        "detector_model_exists": detector_exists,
        "recognizer_model_exists": recognizer_exists,
        "detector_file_size": os.path.getsize(yunet_path) if detector_exists else 0,
        "recognizer_file_size": os.path.getsize(sface_path) if recognizer_exists else 0,
        "opencv_version": cv2.__version__
    })

@app.route('/api/biometric/health', methods=['GET'])
def biometric_health():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    return jsonify({
        "status": "success",
        "detector_initialized": face_detector is not None,
        "recognizer_initialized": face_recognizer is not None
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
        cursor.execute("SELECT * FROM pending_transactions WHERE token = %s AND status = 'PENDING_REVIEW'", (token,))
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
        
        cursor.execute("SELECT USERNAME, BAL FROM NEWBANK WHERE ID = %s", (sender_id,))
        sender_row = cursor.fetchone()
        sender_username = sender_row['USERNAME'] if sender_row else None
        sender_bal = sender_row['BAL'] if sender_row else 0.0
        
        # Enforce idempotency - conditional status update
        target_status = 'COMPLETED' if action == 'APPROVE' else 'BLOCKED'
        cursor.execute("UPDATE pending_transactions SET status = %s WHERE token = %s AND status = 'PENDING_REVIEW'", (target_status, token))
        
        # Audit logging for admin review actions (Feature 12)
        log_metadata = {"token": token, "action": action, "reason": reason, "amount": amount, "sender": sender_username, "receiver": receiver}
        log_audit_event(session['user_id'], 'FRAUD_REVIEW', reviewer, None, None, log_metadata, cursor)
        
        if cursor.rowcount == 0:
            cursor.execute("ROLLBACK")
            conn.close()
            return jsonify({"status": "error", "message": "Concurrency error: Transaction already processed."}), 409
            
        if action == 'APPROVE':
            # Recheck balance inside the same SQLite atomic transaction
            if ttype != 'ADD_MONEY' and sender_bal < amount:
                cursor.execute("UPDATE pending_transactions SET status = 'FAILED' WHERE token = ?", (token,))
                cursor.execute("COMMIT")
                conn.close()
                return jsonify({"status": "error", "message": "Insufficient balance for approval."}), 400
                
            if ttype == 'ADD_MONEY':
                sender_new_bal = sender_bal + amount
            else:
                sender_new_bal = sender_bal - amount
            
            # Check receiver account type (CASH_OUT channel vs TRANSFER user)
            if ttype in ['TRANSFER', 'QR_PAYMENT']:
                cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = %s", (receiver,))
                receiver_row = cursor.fetchone()
                receiver_bal = receiver_row['BAL'] if receiver_row else 0.0
                receiver_new_bal = receiver_bal + amount
                cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE USERNAME = %s", (receiver_new_bal, receiver))
            else: # CASH_OUT or ADD_MONEY
                receiver_bal = 0.0
                receiver_new_bal = 0.0
                
            cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE ID = %s", (sender_new_bal, sender_id))
            
            if ttype == 'ADD_MONEY':
                cursor.execute("UPDATE deposits SET status = 'APPROVED', balance_after = %s WHERE reference_id = %s", (sender_new_bal, token))
            
            # Record decision trace
            decision_trace = json.loads(pending['decision_trace'])
            decision_trace['reviewer'] = reviewer
            decision_trace['review_action'] = 'APPROVED'
            decision_trace['review_reason'] = reason
            decision_trace['review_timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create ledger entry exactly once
            cursor.execute('''
            INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'APPROVED', %s, %s)
            RETURNING ID
            ''', (sender_username, receiver, ttype, amount, sender_bal, sender_new_bal, receiver_bal, receiver_new_bal, pending['is_fraud_predicted'], json.dumps(decision_trace)))
            
            tx_id = cursor.fetchone()[0]
            
            # Create audit record exactly once
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'TRANSACTION_APPROVED_BY_ADMIN', 'MEDIUM', %s)
            ''', (sender_id, f"Admin approved transaction {amount} to {receiver}. Reason: {reason}"))
            
            if ttype == 'ADD_MONEY':
                try:
                    cursor.execute("SELECT EMAIL FROM NEWBANK WHERE ID = %s", (sender_id,))
                    email_row = cursor.fetchone()
                    if email_row and email_row['EMAIL']:
                        send_deposit_email(email_row['EMAIL'], token, amount, sender_bal, sender_new_bal)
                except Exception as ee:
                    print("[WARN] Failed to send admin deposit confirmation email", ee)
                    
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
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'BLOCKED', %s, %s)
            RETURNING ID
            ''', (sender_username, receiver, ttype, amount, sender_bal, sender_bal, 0.0, 0.0, pending['is_fraud_predicted'], json.dumps(decision_trace)))
            
            tx_id = cursor.fetchone()[0]
            
            # Create audit record exactly once
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'TRANSACTION_REJECTED_BY_ADMIN', 'HIGH', %s)
            ''', (sender_id, f"Admin rejected transaction {amount} to {receiver}. Reason: {reason}"))
            
            if ttype == 'ADD_MONEY':
                cursor.execute("UPDATE deposits SET status = 'REJECTED' WHERE reference_id = %s", (token,))
            
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
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = %s", (sender,))
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
    cursor.execute("SELECT * FROM NEWT WHERE ID = %s", (tx_id,))
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
        
    # Ensure new XAI fields are present
    if 'confidence' not in trace:
        trace['confidence'] = max(50, 100 - trace.get('risk_score', 0))
    if 'feature_contributions' not in trace:
        trace['feature_contributions'] = {"base_points": 100}
    if 'triggered_policies' not in trace:
        trace['triggered_policies'] = ["POL-000: Default Compliance Verification"]
    if 'recommendation' not in trace:
        trace['recommendation'] = "MFA verification enforced." 
        
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
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = %s", (sender,))
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



# ==========================================
# SMART WALLET - ADD MONEY API ENDPOINTS
# ==========================================

@app.route('/api/add-money/initiate', methods=['POST'])
def add_money_initiate():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload."}), 400
            
        amount_raw = data.get('amount', 0)
        try:
            amount = clean_and_parse_amount(amount_raw)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid transaction amount format."}), 400
        method = data.get('method', '').strip()
        gateway = data.get('gateway', '').strip()
        remarks = data.get('remarks', '').strip()
        
        if amount < 100 or amount > 200000:
            return jsonify({"status": "error", "message": "Transaction amount must be between INR 100 and INR 2,00,000."}), 400
            
        if method not in ['UPI', 'Debit Card', 'Credit Card', 'Net Banking']:
            return jsonify({"status": "error", "message": "Invalid payment method."}), 400
            
        if gateway not in ['Google Pay', 'PhonePe', 'Paytm', 'BHIM', 'Visa', 'MasterCard', 'RuPay']:
            return jsonify({"status": "error", "message": "Invalid payment gateway."}), 400
            
        user_id = session['user_id']
        username = session['username']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Deduplication Filter (10 seconds)
        cursor.execute('''
        SELECT COUNT(*) FROM deposits 
        WHERE user_id = %s AND amount = %s AND method = %s AND gateway = %s AND timestamp >= datetime('now', '-10 seconds')
        ''', (user_id, amount, method, gateway))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return jsonify({"status": "error", "message": "Duplicate submission detected. Please wait 10 seconds."}), 400
            
        # 2. Rate Limit: 20 deposits / day
        cursor.execute('''
        SELECT COUNT(*) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= datetime('now', '-1 day')
        ''', (user_id,))
        if cursor.fetchone()[0] >= 20:
            conn.close()
            return jsonify({"status": "error", "message": "Daily deposit limit (20) reached."}), 400
            
        # Get current balance
        cursor.execute("SELECT BAL, EMAIL FROM NEWBANK WHERE ID = %s", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            conn.close()
            return jsonify({"status": "error", "message": "User not found."}), 404
        current_bal = user_row['BAL']
        email = user_row['EMAIL']
        
        # 3. Generate Reference ID
        import uuid
        ref_id = f"DEP-{uuid.uuid4().hex[:8].upper()}"
        
        # 4. Compute Hybrid Risk Score
        risk_score, risk_level, reasons, is_fraud_predicted, breakdown, ml_probability = compute_hybrid_risk(user_id, username, 'Wallet', amount, 'ADD_MONEY')
        
        # Apply amount overrides
        if amount > 50000:
            if risk_score < 70:
                risk_score = 75
                reasons.append("Amount exceeds INR 50,000 (High Risk)")
        elif amount > 20000:
            if risk_score >= 70 or risk_score < 45:
                risk_score = 45
                reasons.append("Amount exceeds INR 20,000 (Medium Risk)")
                
        # Classify risk level
        if risk_score >= 90:
            risk_level = 'CRITICAL'
        elif risk_score >= 70:
            risk_level = 'HIGH'
        elif risk_score >= 45:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        decision_trace = {
            "reasons": reasons,
            "is_fraud_predicted": is_fraud_predicted,
            "breakdown": breakdown,
            "ml_probability": ml_probability,
            "reference_id": ref_id,
            "gateway": gateway,
            "method": method
        }
            
        ip_addr = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        cursor.execute("BEGIN TRANSACTION")
        
        if risk_level == 'LOW':
            # Immediate success
            new_bal = current_bal + amount
            cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE ID = %s", (new_bal, user_id))
            
            # Save deposit
            cursor.execute('''
            INSERT INTO deposits (reference_id, user_id, amount, method, gateway, status, risk_score, risk_level, remarks, balance_before, balance_after, ip_address, device)
            VALUES (%s, %s, %s, %s, %s, 'APPROVED', %s, %s, %s, %s, %s, %s, %s)
            ''', (ref_id, user_id, amount, method, gateway, risk_score, risk_level, remarks, current_bal, new_bal, ip_addr, user_agent))
            
            # Save transaction ledger
            cursor.execute('''
            INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
            VALUES (%s, 'Wallet', 'ADD_MONEY', %s, %s, %s, 0.0, 0.0, 'APPROVED', 0, %s)
            ''', (username, amount, current_bal, new_bal, json.dumps(decision_trace)))
            
            # Create audit record
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'WALLET_DEPOSIT_SUCCESS', 'LOW', %s)
            ''', (user_id, f"Added INR {amount} via {method}/{gateway}"))
            
            # Audit log (Feature 12)
            log_metadata = {"amount": amount, "method": method, "gateway": gateway, "ref_id": ref_id, "risk_score": risk_score}
            log_audit_event(user_id, 'DEPOSIT', username, ip_addr, user_agent, log_metadata, cursor=cursor)
            
            # Create notification
            create_notification(user_id, "Smart Wallet Credit", f"Successfully topped up wallet with Rs {amount:.2f}.", "DEPOSIT", cursor=cursor)
            
            conn.commit()
            conn.close()
            
            # Send confirmation email
            if email:
                try:
                    send_deposit_email(email, ref_id, amount, current_bal, new_bal)
                except Exception as e_mail:
                    print(f"[WARN] Post-transaction deposit email notification failed: {e_mail}", flush=True)
                
            return jsonify({
                "status": "success",
                "reference_id": ref_id,
                "risk_level": "LOW",
                "risk_score": risk_score,
                "message": "Money added successfully!"
            })
            
        elif risk_level in ['MEDIUM', 'HIGH']:
            # PENDING_MFA
            cursor.execute('''
            INSERT INTO deposits (reference_id, user_id, amount, method, gateway, status, risk_score, risk_level, remarks, balance_before, balance_after, ip_address, device)
            VALUES (%s, %s, %s, %s, %s, 'PENDING_MFA', %s, %s, %s, %s, %s, %s, %s)
            ''', (ref_id, user_id, amount, method, gateway, risk_score, risk_level, remarks, current_bal, current_bal, ip_addr, user_agent))
            
            # Create pending_transactions entry
            expires_at = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, status, expires_at, decision_trace)
            VALUES (%s, %s, 'Wallet', %s, 'ADD_MONEY', %s, %s, %s, 0, 'PENDING', %s, %s)
            ''', (ref_id, user_id, amount, risk_score, risk_level, json.dumps(reasons), expires_at, json.dumps(decision_trace)))
            
            # Generate OTP
            import random
            otp = f"{random.randint(100000, 999999)}"
            otp_hash = hash_otp(otp)
            otp_expires = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute('''
            INSERT INTO transaction_otp_challenges (user_id, transaction_token, otp_hash, expires_at)
            VALUES (%s, %s, %s, %s)
            ''', (user_id, ref_id, otp_hash, otp_expires))
            
            conn.commit()
            conn.close()
            
            # Send OTP email
            success = False
            try:
                success = send_otp_email(email, otp, amount, 'Smart Wallet')
            except Exception as mail_err:
                print(f"[DEBUG] [SMTP email send failed] Error: {mail_err}", flush=True)
                
            if not success:
                t_rollback = time.time()
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM transaction_otp_challenges WHERE transaction_token = %s", (ref_id,))
                cursor.execute("DELETE FROM pending_transactions WHERE token = %s", (ref_id,))
                cursor.execute("DELETE FROM deposits WHERE reference_id = %s", (ref_id,))
                conn.commit()
                conn.close()
                print(f"[DEBUG] [Database rollback cleanup completed] took {time.time() - t_rollback:.4f}s", flush=True)
                return jsonify({"status": "error", "message": "Unable to deliver the OTP email. Please try again."}), 500
                
            session['mfa_pending_token'] = ref_id
            return jsonify({
                "status": "verification_required",
                "reference_id": ref_id,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "otp_required": True,
                "face_required": (risk_level == 'HIGH')
            })
            
        else: # CRITICAL
            # PENDING_REVIEW
            cursor.execute('''
            INSERT INTO deposits (reference_id, user_id, amount, method, gateway, status, risk_score, risk_level, remarks, balance_before, balance_after, ip_address, device)
            VALUES (%s, %s, %s, %s, %s, 'PENDING_REVIEW', %s, %s, %s, %s, %s, %s, %s)
            ''', (ref_id, user_id, amount, method, gateway, risk_score, risk_level, remarks, current_bal, current_bal, ip_addr, user_agent))
            
            # Create pending_transactions for Admin Review Queue
            expires_at = (datetime.datetime.now() + datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
            INSERT INTO pending_transactions (token, user_id, receiver, amount, ttype, risk_score, risk_level, reasons, is_fraud_predicted, status, expires_at, decision_trace)
            VALUES (%s, %s, 'Wallet', %s, 'ADD_MONEY', %s, %s, %s, 1, 'PENDING_REVIEW', %s, %s)
            ''', (ref_id, user_id, amount, risk_score, risk_level, json.dumps(reasons), expires_at, json.dumps(decision_trace)))
            
            # Create audit record
            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'WALLET_DEPOSIT_HELD_REVIEW', 'HIGH', %s)
            ''', (user_id, f"Deposit of INR {amount} held for admin review due to CRITICAL risk score {risk_score}."))
            
            conn.commit()
            
            # Send Socket.IO notification to admin dashboard
            try:
                socketio.emit('new_pending_review', {
                    'token': ref_id,
                    'username': username,
                    'amount': amount,
                    'ttype': 'ADD_MONEY',
                    'risk_score': risk_score,
                    'risk_level': 'CRITICAL'
                })
            except Exception as se:
                print(f"[WARN] Socket.IO notification failed: {se}", flush=True)
                
            conn.close()
            return jsonify({
                "status": "pending_review",
                "reference_id": ref_id,
                "risk_level": "CRITICAL",
                "risk_score": risk_score,
                "message": "Deposit held for administrative review due to CRITICAL security score."
            })
            
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

@app.route('/api/add-money/verify', methods=['POST'])
def add_money_verify():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        ref_id = data.get('reference_id', '').strip()
        if not ref_id:
            return jsonify({"status": "error", "message": "Reference ID is required."}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM deposits WHERE reference_id = %s AND user_id = %s", (ref_id, session['user_id']))
        dep = cursor.fetchone()
        conn.close()
        
        if not dep:
            return jsonify({"status": "error", "message": "Deposit transaction not found."}), 404
            
        return jsonify({
            "status": "success",
            "deposit": {
                "reference_id": dep['reference_id'],
                "amount": dep['amount'],
                "method": dep['method'],
                "gateway": dep['gateway'],
                "status": dep['status'],
                "risk_level": dep['risk_level'],
                "balance_before": dep['balance_before'],
                "balance_after": dep['balance_after'],
                "timestamp": str(dep['timestamp'])
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/add-money/history', methods=['GET'])
def add_money_history():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM deposits 
        WHERE user_id = %s 
        ORDER BY timestamp DESC
        ''', (session['user_id'],))
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for r in rows:
            history.append({
                "reference_id": r['reference_id'],
                "amount": r['amount'],
                "method": r['method'],
                "gateway": r['gateway'],
                "status": r['status'],
                "risk_level": r['risk_level'],
                "balance_before": r['balance_before'],
                "balance_after": r['balance_after'],
                "timestamp": str(r['timestamp'])
            })
        return jsonify({"status": "success", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/add-money/receipt/<reference_id>', methods=['GET'])
def add_money_receipt(reference_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT d.*, u.USERNAME, u.BAL 
        FROM deposits d
        JOIN NEWBANK u ON d.user_id = u.ID
        WHERE d.reference_id = %s AND d.user_id = %s
        ''', (reference_id, user_id))
        dep = cursor.fetchone()
        conn.close()
        
        if not dep:
            return jsonify({"status": "error", "message": "Deposit receipt not found."}), 404
            
        from io import BytesIO
        buffer = BytesIO()
        
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.graphics.barcode import createBarcodeDrawing
        
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor("#9b5de5")
        text_color = colors.HexColor("#0f172a")
        
        story = []
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=primary_color,
            spaceAfter=20,
            alignment=1
        )
        story.append(Paragraph("SMART BANKING - RECEIPT", title_style))
        story.append(Spacer(1, 10))
        
        # QR Code Drawing
        qr_code = createBarcodeDrawing('QR', value=f"https://smartbanking.com/verify/{reference_id}", width=80, height=80)
        
        data = [
            [Paragraph("<b>Transaction ID</b>", styles['Normal']), Paragraph(str(dep['id']), styles['Normal'])],
            [Paragraph("<b>Reference ID</b>", styles['Normal']), Paragraph(str(dep['reference_id']), styles['Normal'])],
            [Paragraph("<b>Timestamp</b>", styles['Normal']), Paragraph(str(dep['timestamp']), styles['Normal'])],
            [Paragraph("<b>Payment Method</b>", styles['Normal']), Paragraph(str(dep['method']), styles['Normal'])],
            [Paragraph("<b>Gateway</b>", styles['Normal']), Paragraph(str(dep['gateway']), styles['Normal'])],
            [Paragraph("<b>Deposit Amount</b>", styles['Normal']), Paragraph(f"INR {dep['amount']:,.2f}", styles['Normal'])],
            [Paragraph("<b>Status</b>", styles['Normal']), Paragraph(str(dep['status']), styles['Normal'])],
            [Paragraph("<b>Balance Before</b>", styles['Normal']), Paragraph(f"INR {dep['balance_before']:,.2f}", styles['Normal'])],
            [Paragraph("<b>Balance After</b>", styles['Normal']), Paragraph(f"INR {dep['balance_after']:,.2f}", styles['Normal'])],
            [Paragraph("<b>Verification QR</b>", styles['Normal']), qr_code]
        ]
        
        t = Table(data, colWidths=[200, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), text_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ]))
        
        story.append(t)
        doc.build(story)
        
        buffer.seek(0)
        from flask import Response
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment;filename=Receipt_{reference_id}.pdf"}
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/add-money/analytics', methods=['GET'])
def add_money_analytics():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Today's Deposits
        cursor.execute('''
        SELECT COALESCE(SUM(amount), 0) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= datetime('now', '-1 day')
        ''', (user_id,))
        today = cursor.fetchone()[0]
        
        # Weekly Deposits
        cursor.execute('''
        SELECT COALESCE(SUM(amount), 0) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= datetime('now', '-7 days')
        ''', (user_id,))
        weekly = cursor.fetchone()[0]
        
        # Monthly Deposits
        cursor.execute('''
        SELECT COALESCE(SUM(amount), 0) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= datetime('now', '-30 days')
        ''', (user_id,))
        monthly = cursor.fetchone()[0]
        
        # Average Deposit
        cursor.execute('''
        SELECT COALESCE(AVG(amount), 0) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED'
        ''', (user_id,))
        avg_dep = cursor.fetchone()[0]
        
        # Largest Deposit
        cursor.execute('''
        SELECT COALESCE(MAX(amount), 0) FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED'
        ''', (user_id,))
        largest = cursor.fetchone()[0]
        
        # Success Rate
        cursor.execute("SELECT COUNT(*) FROM deposits WHERE user_id = %s", (user_id,))
        total_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM deposits WHERE user_id = %s AND status = 'APPROVED'", (user_id,))
        success_count = cursor.fetchone()[0]
        success_rate = (success_count / total_count * 100) if total_count > 0 else 100.0
        
        # Deposit Trend
        cursor.execute('''
        SELECT strftime('%%Y-%%m-%%d', timestamp) as day, COALESCE(SUM(amount), 0) as total 
        FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= datetime('now', '-30 days')
        GROUP BY day 
        ORDER BY day ASC
        ''', (user_id,))
        trend = [{"day": row['day'], "total": row['total']} for row in cursor.fetchall()]
        
        # Gateway Distribution
        cursor.execute('''
        SELECT gateway, COUNT(*) as count 
        FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED'
        GROUP BY gateway
        ''', (user_id,))
        gateways = [{"gateway": row['gateway'], "count": row['count']} for row in cursor.fetchall()]
        
        # Payment Method Distribution
        cursor.execute('''
        SELECT method, COUNT(*) as count 
        FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED'
        GROUP BY method
        ''', (user_id,))
        methods = [{"method": row['method'], "count": row['count']} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            "status": "success",
            "today": today,
            "weekly": weekly,
            "monthly": monthly,
            "avg_dep": avg_dep,
            "largest": largest,
            "success_rate": success_rate,
            "trend": trend,
            "gateways": gateways,
            "methods": methods
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500




# ==========================================
# PHASE 1 – QR PAYMENT SYSTEM ROUTE ENDPOINTS
# ==========================================

@app.route('/api/qr/token', methods=['GET'])
def qr_get_token():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.secret_key, salt="qr-payment-salt")
        token = serializer.dumps({"username": session['username']})
        return jsonify({
            "status": "success",
            "qr_token": token,
            "expires_in": 300
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/qr/scan', methods=['POST'])
def qr_scan_token():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        if not data or 'qr_token' not in data:
            return jsonify({"status": "error", "message": "Missing qr_token"}), 400
        
        qr_token = data['qr_token'].strip()
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.secret_key, salt="qr-payment-salt")
        try:
            token_data = serializer.loads(qr_token, max_age=300)
            receiver_username = token_data["username"]
        except Exception:
            return jsonify({"status": "error", "message": "Invalid or expired QR code token."}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT FIRSTNAME, LASTNAME FROM NEWBANK WHERE USERNAME = %s", (receiver_username,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"status": "error", "message": "Recipient not found."}), 404
            
        return jsonify({
            "status": "success",
            "username": receiver_username,
            "firstname": row['FIRSTNAME'],
            "lastname": row['LASTNAME']
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/qr/receipt/<int:tx_id>', methods=['GET'])
def qr_payment_receipt(tx_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    try:
        user_id = session['user_id']
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM NEWT 
        WHERE ID = %s AND TTYPE = 'QR_PAYMENT' AND (SENDER = %s OR RECEIVER = %s)
        ''', (tx_id, username, username))
        tx = cursor.fetchone()
        conn.close()
        
        if not tx:
            return jsonify({"status": "error", "message": "QR payment receipt not found."}), 404
            
        from io import BytesIO
        buffer = BytesIO()
        
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.graphics.barcode import createBarcodeDrawing
        
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor("#9b5de5")
        text_color = colors.HexColor("#0f172a")
        
        story = []
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=primary_color,
            spaceAfter=20,
            alignment=1
        )
        story.append(Paragraph("SMART BANKING - QR RECEIPT", title_style))
        story.append(Spacer(1, 10))
        
        qr_code = createBarcodeDrawing('QR', value=f"https://smartbanking.com/verify/qr/{tx_id}", width=80, height=80)
        
        data = [
            [Paragraph("<b>Transaction ID</b>", styles['Normal']), Paragraph(str(tx['id']), styles['Normal'])],
            [Paragraph("<b>Timestamp</b>", styles['Normal']), Paragraph(str(tx['timestamp']), styles['Normal'])],
            [Paragraph("<b>Sender</b>", styles['Normal']), Paragraph(str(tx['sender']), styles['Normal'])],
            [Paragraph("<b>Recipient</b>", styles['Normal']), Paragraph(str(tx['receiver']), styles['Normal'])],
            [Paragraph("<b>Amount</b>", styles['Normal']), Paragraph(f"INR {tx['amount']:,.2f}", styles['Normal'])],
            [Paragraph("<b>Status</b>", styles['Normal']), Paragraph(str(tx['status']), styles['Normal'])],
            [Paragraph("<b>Verification QR</b>", styles['Normal']), qr_code]
        ]
        
        t = Table(data, colWidths=[200, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), text_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ]))
        
        story.append(t)
        doc.build(story)
        
        buffer.seek(0)
        from flask import Response
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment;filename=QR_Receipt_{tx_id}.pdf"}
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 2 – BENEFICIARY MANAGEMENT ENDPOINTS
# ==========================================

@app.route('/api/beneficiaries', methods=['GET'])
def get_beneficiaries():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort', 'nickname').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM beneficiaries WHERE user_id = %s"
        params = [user_id]
        
        if search:
            query += " AND (nickname LIKE %s OR beneficiary_username LIKE %s)"
            params.extend([f"%{search}%", f"%{search}%"])
            
        if sort_by == 'favorite':
            query += " ORDER BY is_favorite DESC, nickname ASC"
        elif sort_by == 'stats':
            query += " ORDER BY total_transferred DESC"
        else:
            query += " ORDER BY nickname ASC"
            
        query += " LIMIT %s OFFSET %s"
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Total count for pagination
        count_query = "SELECT COUNT(*) as total FROM beneficiaries WHERE user_id = %s"
        count_params = [user_id]
        if search:
            count_query += " AND (nickname LIKE %s OR beneficiary_username LIKE %s)"
            count_params.extend([f"%{search}%", f"%{search}%"])
        cursor.execute(count_query, count_params)
        total_rows = cursor.fetchone()
        total_count = total_rows['total'] if total_rows else 0
        
        conn.close()
        
        list_b = []
        for r in rows:
            list_b.append({
                "id": r['id'],
                "beneficiary_username": r['beneficiary_username'],
                "nickname": r['nickname'],
                "is_favorite": bool(r['is_favorite']),
                "transfer_count": r['transfer_count'],
                "total_transferred": r['total_transferred']
            })
            
        return jsonify({
            "status": "success",
            "beneficiaries": list_b,
            "total": total_count,
            "page": page,
            "per_page": per_page
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/beneficiaries', methods=['POST'])
def add_beneficiary():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({"status": "error", "message": "Username is required."}), 400
            
        user_id = session['user_id']
        current_username = session['username']
        b_username = data['username'].strip()
        nickname = data.get('nickname', b_username).strip()
        
        if b_username.lower() == current_username.lower():
            return jsonify({"status": "error", "message": "Cannot add yourself as a beneficiary."}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify user exists
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = %s", (b_username,))
        rec_row = cursor.fetchone()
        if not rec_row:
            conn.close()
            return jsonify({"status": "error", "message": "Recipient username not found."}), 404
            
        # Prevent duplicates
        cursor.execute("SELECT id FROM beneficiaries WHERE user_id = %s AND beneficiary_username = %s", (user_id, b_username))
        dup_row = cursor.fetchone()
        if dup_row:
            conn.close()
            return jsonify({"status": "error", "message": "Beneficiary already exists."}), 400
            
        cursor.execute('''
        INSERT INTO beneficiaries (user_id, beneficiary_username, nickname)
        VALUES (%s, %s, %s)
        ''', (user_id, b_username, nickname))
        
        # Write to audit trail
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'BENEFICIARY_ADDED', 'LOW', %s)
        ''', (user_id, json.dumps({"beneficiary": b_username, "nickname": nickname})))
        
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Beneficiary added successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/beneficiaries/<int:b_id>', methods=['PUT'])
def update_beneficiary(b_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        nickname = data.get('nickname', '').strip()
        if not nickname:
            return jsonify({"status": "error", "message": "Nickname is required."}), 400
            
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Validate ownership
        cursor.execute("SELECT beneficiary_username FROM beneficiaries WHERE id = %s AND user_id = %s", (b_id, user_id))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Beneficiary not found or unauthorized."}), 404
            
        cursor.execute("UPDATE beneficiaries SET nickname = %s WHERE id = %s", (nickname, b_id))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'BENEFICIARY_UPDATED', 'LOW', %s)
        ''', (user_id, json.dumps({"beneficiary": row['beneficiary_username'], "new_nickname": nickname})))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Beneficiary updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/beneficiaries/<int:b_id>', methods=['DELETE'])
def delete_beneficiary(b_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Validate ownership
        cursor.execute("SELECT beneficiary_username FROM beneficiaries WHERE id = %s AND user_id = %s", (b_id, user_id))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Beneficiary not found or unauthorized."}), 404
            
        cursor.execute("DELETE FROM beneficiaries WHERE id = %s", (b_id,))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'BENEFICIARY_REMOVED', 'LOW', %s)
        ''', (user_id, json.dumps({"beneficiary": row['beneficiary_username']})))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Beneficiary removed successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/beneficiaries/<int:b_id>/favorite', methods=['POST'])
def favorite_beneficiary(b_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Validate ownership
        cursor.execute("SELECT beneficiary_username, is_favorite FROM beneficiaries WHERE id = %s AND user_id = %s", (b_id, user_id))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Beneficiary not found or unauthorized."}), 404
            
        new_fav = 1 - row['is_favorite']
        cursor.execute("UPDATE beneficiaries SET is_favorite = %s WHERE id = %s", (new_fav, b_id))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'BENEFICIARY_FAVORITED', 'LOW', %s)
        ''', (user_id, json.dumps({"beneficiary": row['beneficiary_username'], "is_favorite": bool(new_fav)})))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Favorite status updated.", "is_favorite": bool(new_fav)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 3 – LOGIN SECURITY CENTER ENDPOINTS
# ==========================================

@app.route('/api/security/sessions', methods=['GET'])
def get_security_sessions():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM login_history 
        WHERE user_id = %s 
        ORDER BY login_time DESC 
        LIMIT %s OFFSET %s
        ''', (user_id, per_page, offset))
        rows = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) as total FROM login_history WHERE user_id = %s", (user_id,))
        count_row = cursor.fetchone()
        total = count_row['total'] if count_row else 0
        conn.close()
        
        sessions = []
        for r in rows:
            sessions.append({
                "id": r['id'],
                "session_id": r['session_id'],
                "browser": r['browser'],
                "os": r['os'],
                "ip_address": r['ip_address'],
                "device_type": r['device_type'],
                "is_trusted": bool(r['is_trusted']),
                "login_time": r['login_time'],
                "last_activity": r['last_activity'],
                "status": r['status'],
                "is_current": r['session_id'] == session.get('session_id')
            })
            
        return jsonify({
            "status": "success",
            "sessions": sessions,
            "total": total,
            "page": page,
            "per_page": per_page
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/sessions/revoke', methods=['POST'])
def revoke_session():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        target_sid = data.get('session_id', '').strip()
        if not target_sid:
            return jsonify({"status": "error", "message": "session_id is required."}), 400
            
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute("SELECT user_id, status FROM login_history WHERE session_id = %s", (target_sid,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Session not found."}), 404
            
        if row['user_id'] != user_id:
            conn.close()
            return jsonify({"status": "error", "message": "Access denied."}), 403
            
        cursor.execute("UPDATE login_history SET status = 'REVOKED' WHERE session_id = %s", (target_sid,))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'SESSION_REVOKED', 'LOW', %s)
        ''', (user_id, json.dumps({"session_id": target_sid})))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Session successfully revoked."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/sessions/revoke-others', methods=['POST'])
def revoke_other_sessions():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        current_sid = session.get('session_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE login_history 
        SET status = 'REVOKED' 
        WHERE user_id = %s AND session_id != %s AND status = 'ACTIVE'
        ''', (user_id, current_sid))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'ALL_OTHER_SESSIONS_REVOKED', 'LOW', '{}')
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "All other sessions successfully revoked."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/devices/trust', methods=['POST'])
def toggle_device_trust():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        fingerprint = data.get('device_fingerprint', '').strip()
        trust_status = int(data.get('is_trusted', 0))
        
        if not fingerprint:
            return jsonify({"status": "error", "message": "device_fingerprint is required."}), 400
            
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE login_history 
        SET is_trusted = %s 
        WHERE user_id = %s AND device_fingerprint = %s
        ''', (trust_status, user_id, fingerprint))
        
        # Audit
        cursor.execute('''
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'DEVICE_TRUST_TOGGLED', 'LOW', %s)
        ''', (user_id, json.dumps({"fingerprint": fingerprint, "is_trusted": bool(trust_status)})))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Device trust level updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 4 – EXPLAINABLE AI (XAI) ENDPOINTS
# ==========================================

@app.route('/api/xai/explain/<int:tx_id>', methods=['GET'])
def get_xai_explanation(tx_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify transaction ownership
        cursor.execute("SELECT * FROM NEWT WHERE ID = %s AND (SENDER = %s OR RECEIVER = %s)", (tx_id, username, username))
        tx = cursor.fetchone()
        conn.close()
        
        if not tx:
            return jsonify({"status": "error", "message": "Transaction not found."}), 404
            
        trace_str = tx['decision_trace']
        try:
            trace = json.loads(trace_str)
        except Exception:
            # Construct legacy fallback trace
            trace = {
                "risk_score": 10,
                "risk_level": "LOW",
                "reasons": ["Legacy Transaction: Decision trace reconstructed."],
                "breakdown": {"base_points": 10},
                "ml_probability": 0.0,
                "feature_importances": {},
                "auth_required": [],
                "auth_completed": [],
                "confidence": 95,
                "feature_contributions": {"base_points": 100},
                "triggered_policies": ["POL-000: Standard Low Risk Profile"],
                "recommendation": "Legacy transaction processed under default parameters."
            }
            
        # Ensure new fields are present even if partial trace
        if 'confidence' not in trace:
            trace['confidence'] = max(50, 100 - trace.get('risk_score', 0))
        if 'feature_contributions' not in trace:
            trace['feature_contributions'] = {"base_points": 100}
        if 'triggered_policies' not in trace:
            trace['triggered_policies'] = ["POL-000: Policy Mapping Unavailable"]
        if 'recommendation' not in trace:
            trace['recommendation'] = "MFA verified successfully."
            
        return jsonify({
            "status": "success",
            "explanation": trace
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 5 – ENTERPRISE ADMIN ANALYTICS & EXPORTS
# ==========================================

@app.route('/api/admin/analytics/stats', methods=['GET'])
def get_admin_analytics_stats():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized Access"}), 401
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWBANK")
        total_users = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT SUM(BAL) as sum_bal FROM NEWBANK")
        total_bal = cursor.fetchone()['sum_bal'] or 0.0
        
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWT")
        total_txs = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT SUM(AMOUNT) as sum_amt FROM NEWT")
        total_volume = cursor.fetchone()['sum_amt'] or 0.0
        
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWT WHERE IS_FRAUD_PREDICTED = 1")
        total_frauds = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM pending_transactions WHERE status = 'PENDING'")
        total_pending = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM biometric_security_events WHERE event_type LIKE '%FAILED%' OR event_type LIKE '%MISMATCH%'")
        otp_failures = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM login_attempts")
        login_failures = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWT WHERE TTYPE = 'QR_PAYMENT'")
        qr_count = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM login_history WHERE status = 'ACTIVE'")
        active_sessions = cursor.fetchone()['cnt']
        
        conn.close()
        return jsonify({
            "status": "success",
            "stats": {
                "total_users": total_users,
                "total_balance": total_bal,
                "total_transactions": total_txs,
                "total_volume": total_volume,
                "total_frauds": total_frauds,
                "total_pending": total_pending,
                "otp_failures": otp_failures,
                "login_failures": login_failures,
                "qr_count": qr_count,
                "active_sessions": active_sessions
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/reports/csv', methods=['GET'])
def export_ledger_csv():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized Access"}), 401
    try:
        import io
        import csv
        from flask import Response
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM NEWT ORDER BY TIMESTAMP DESC")
        rows = cursor.fetchall()
        conn.close()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Transaction ID", "Sender", "Receiver", "Type", "Amount", "Status", "Timestamp", "Fraud Predicted"])
        
        for r in rows:
            writer.writerow([
                r['ID'], r['SENDER'], r['RECEIVER'], r['TTYPE'], r['AMOUNT'],
                r['STATUS'], r['TIMESTAMP'], r['IS_FRAUD_PREDICTED']
            ])
            
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=ledger_report.csv"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/reports/pdf', methods=['GET'])
def export_ledger_pdf():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized Access"}), 401
    try:
        import io
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from flask import send_file
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM NEWT ORDER BY TIMESTAMP DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        story = []
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1e1b4b'),
            spaceAfter=15
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=25
        )
        
        story.append(Paragraph("Smart Banking Enterprise System", title_style))
        story.append(Paragraph("Master Audit Report - Generated by Auditor", subtitle_style))
        story.append(Spacer(1, 10))
        
        # Table data
        data = [["ID", "Sender", "Receiver", "Type", "Amount", "Status", "Timestamp"]]
        for r in rows:
            data.append([
                str(r['ID']),
                r['SENDER'],
                r['RECEIVER'],
                r['TTYPE'],
                f"Rs {r['AMOUNT']:.2f}",
                r['STATUS'],
                r['TIMESTAMP']
            ])
            
        t = Table(data, colWidths=[40, 80, 80, 80, 100, 70, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e1b4b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('FONTSIZE', (0,1), (-1,-1), 8),
        ]))
        
        story.append(t)
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name="ledger_audit_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 6 – NOTIFICATION CENTER ENDPOINTS
# ==========================================

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if unread_only:
            cursor.execute('''
            SELECT * FROM notifications 
            WHERE user_id = %s AND is_read = 0 
            ORDER BY created_at DESC
            ''', (user_id,))
        else:
            cursor.execute('''
            SELECT * FROM notifications 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT 50
            ''', (user_id,))
            
        rows = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) as cnt FROM notifications WHERE user_id = %s AND is_read = 0", (user_id,))
        unread_cnt = cursor.fetchone()['cnt']
        
        conn.close()
        
        notifs = []
        for r in rows:
            notifs.append({
                "id": r['id'],
                "title": r['title'],
                "message": r['message'],
                "type": r['type'],
                "is_read": bool(r['is_read']),
                "created_at": r['created_at']
            })
            
        return jsonify({
            "status": "success",
            "notifications": notifs,
            "unread_count": unread_cnt
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/notifications/read', methods=['POST'])
def mark_all_notifications_read():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = %s", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "All notifications marked as read."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
def mark_single_notification_read(nid):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute("SELECT user_id FROM notifications WHERE id = %s", (nid,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Notification not found."}), 404
        if row['user_id'] != user_id:
            conn.close()
            return jsonify({"status": "error", "message": "Access denied."}), 403
            
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = %s", (nid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Notification marked as read."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/notifications/<int:nid>', methods=['DELETE'])
def delete_notification(nid):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute("SELECT user_id FROM notifications WHERE id = %s", (nid,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Notification not found."}), 404
        if row['user_id'] != user_id:
            conn.close()
            return jsonify({"status": "error", "message": "Access denied."}), 403
            
        cursor.execute("DELETE FROM notifications WHERE id = %s", (nid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Notification deleted."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================
# PHASE 7 – DYNAMIC DASHBOARD METRICS API
# ==========================================

@app.route('/api/dashboard/metrics', methods=['GET'])
def get_dashboard_metrics():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        username = session['username']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Bank Balance
        cursor.execute("SELECT BAL FROM NEWBANK WHERE ID = %s", (user_id,))
        bank_row = cursor.fetchone()
        bank_balance = bank_row['BAL'] if bank_row else 0.0
        
        # 2. Wallet Balance
        # Check if smart_wallet table exists
        wallet_balance = 0.0
        try:
            cursor.execute("SELECT balance FROM smart_wallet WHERE user_id = %s", (user_id,))
            wallet_row = cursor.fetchone()
            if wallet_row:
                wallet_balance = wallet_row['balance']
        except Exception:
            pass
            
        # 3. Monthly Spends (Last 30 days)
        cursor.execute("SELECT AMOUNT, TIMESTAMP FROM NEWT WHERE SENDER = %s AND STATUS = 'APPROVED'", (username,))
        tx_rows = cursor.fetchall()
        
        import datetime
        thirty_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        monthly_spends = 0.0
        
        for tx in tx_rows:
            try:
                tx_time = datetime.datetime.strptime(tx['TIMESTAMP'], "%Y-%m-%d %H:%M:%S")
                if tx_time >= thirty_days_ago:
                    monthly_spends += tx['AMOUNT']
            except Exception:
                pass
                
        # 4. Security Score calculation
        security_score = 40 # Base score
        
        # Face Biometrics enrolled (+30%)
        cursor.execute("SELECT COUNT(*) as cnt FROM face_enrollments WHERE user_id = %s", (user_id,))
        has_face = cursor.fetchone()['cnt'] > 0
        if has_face:
            security_score += 30
            
        # Trusted device (+15%)
        cursor.execute("SELECT COUNT(*) as cnt FROM login_history WHERE user_id = %s AND is_trusted = 1", (user_id,))
        has_trusted = cursor.fetchone()['cnt'] > 0
        if has_trusted:
            security_score += 15
            
        # No biometric failure events (+15%)
        cursor.execute('''
        SELECT COUNT(*) as cnt FROM biometric_security_events 
        WHERE user_id = %s AND (event_type LIKE '%%FAILED%%' OR event_type LIKE '%%MISMATCH%%')
        ''', (user_id,))
        failures_count = cursor.fetchone()['cnt']
        if failures_count == 0:
            security_score += 15
        else:
            security_score = max(10, security_score - (failures_count * 10))
            
        conn.close()
        return jsonify({
            "status": "success",
            "metrics": {
                "bank_balance": bank_balance,
                "wallet_balance": wallet_balance,
                "monthly_spends": monthly_spends,
                "security_score": min(100, security_score)
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



import json
import secrets
import time
import datetime
import traceback
import sys
import os
from io import BytesIO
from flask import send_file, request, jsonify, session
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.barcode import createBarcodeDrawing

# --- Helper functions ---
def log_audit_event(user_id, action, username, ip_address, device, metadata=None, cursor=None):
    try:
        should_close = False
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
            should_close = True
            
        meta_str = json.dumps(metadata) if metadata else None
        
        # Check if the tables exist and insert
        cursor.execute('''
        INSERT INTO audit_logs (user_id, username, action, ip_address, device, metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
        ''', (user_id, username, action, ip_address, device, meta_str))
        
        if should_close:
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log audit event: {e}", flush=True)

def check_or_register_device(user_id, fingerprint, browser, os_name):
    if not fingerprint:
        return False
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT id FROM trusted_devices 
        WHERE user_id = %s AND device_fingerprint = %s
        ''', (user_id, fingerprint))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        print(f"[ERROR] Device recognition lookup failed: {e}", flush=True)
        return False

def add_trusted_device(user_id, fingerprint, browser, os_name):
    if not fingerprint:
        return
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO trusted_devices (user_id, device_fingerprint, browser, os, last_login_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, device_fingerprint) 
        DO UPDATE SET last_login_at = CURRENT_TIMESTAMP
        ''', (user_id, fingerprint, browser, os_name))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to add trusted device: {e}", flush=True)

# --- API Endpoints ---

@app.route('/api/login/verify-otp', methods=['POST'])
def login_verify_otp():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing payload"}), 400
            
        otp = data.get('otp', '').strip()
        if not otp:
            return jsonify({"status": "error", "message": "OTP is required"}), 400
            
        user_id = session.get('login_pending_user_id')
        otp_hash = session.get('login_otp_hash')
        expires = session.get('login_otp_expires', 0)
        
        if not user_id or not otp_hash:
            return jsonify({"status": "error", "message": "No pending login session."}), 400
            
        if time.time() > expires:
            return jsonify({"status": "error", "message": "Verification code expired."}), 400
            
        if not verify_otp_hmac(otp, otp_hash):
            return jsonify({"status": "error", "message": "Invalid verification code."}), 400
            
        username = session['login_pending_username']
        fingerprint = session['login_pending_fingerprint']
        browser = session['login_pending_browser']
        os_name = session['login_pending_os']
        dev_type = session['login_pending_dev_type']
        ip = session['login_pending_ip']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO trusted_devices (user_id, device_fingerprint, browser, os, last_login_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, device_fingerprint) 
        DO UPDATE SET last_login_at = CURRENT_TIMESTAMP
        ''', (user_id, fingerprint, browser, os_name))
        
        clear_login_attempts(username)
        
        import uuid
        sess_id = uuid.uuid4().hex
        
        session.clear()
        session['username'] = username
        session['user_id'] = user_id
        session['is_admin'] = (username.lower() in ['admin', 'auditor'])
        session['session_id'] = sess_id
        
        cursor.execute('''
        INSERT INTO login_history (user_id, session_id, browser, os, ip_address, device_type, device_fingerprint, is_trusted, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 1, 'ACTIVE')
        ''', (user_id, sess_id, browser, os_name, ip, dev_type, fingerprint))
        
        create_notification(user_id, "New Device Trusted", f"Browser {browser} on {os_name} has been added to your trusted list.", "SECURITY", cursor=cursor)
        log_audit_event(user_id, 'LOGIN', username, ip, f"{browser} ({os_name})", {"status": "SUCCESS", "mfa_verified": True}, cursor)
        
        cursor.execute("SELECT * FROM NEWBANK WHERE ID = %s", (user_id,))
        user = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
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
        
        return jsonify({
            "status": "success",
            "message": "Login successful!",
            "user": res_user
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/devices', methods=['GET'])
def get_trusted_devices():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT id, browser, os, last_login_at 
        FROM trusted_devices 
        WHERE user_id = %s 
        ORDER BY last_login_at DESC
        ''', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        
        devices = []
        for r in rows:
            devices.append({
                "id": r['id'],
                "browser": r['browser'],
                "os": r['os'],
                "last_login_at": str(r['last_login_at'])
            })
        return jsonify({"status": "success", "devices": devices})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/devices/<int:device_id>', methods=['DELETE'])
def delete_trusted_device(device_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id, device_fingerprint FROM trusted_devices WHERE id = %s", (device_id,))
        device = cursor.fetchone()
        if not device or device['user_id'] != user_id:
            conn.close()
            return jsonify({"status": "error", "message": "Device not found."}), 404
            
        cursor.execute("DELETE FROM trusted_devices WHERE id = %s", (device_id,))
        # Also clean login_history flag
        cursor.execute("UPDATE login_history SET is_trusted = 0 WHERE user_id = %s AND device_fingerprint = %s", (user_id, device['device_fingerprint']))
        
        ip = request.remote_addr or '127.0.0.1'
        ua = request.headers.get('User-Agent', '')
        browser, os_name, _ = parse_user_agent(ua)
        log_audit_event(user_id, 'REVOKE_DEVICE', session['username'], ip, f"{browser} ({os_name})", {"device_id": device_id})
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Trusted device revoked successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/security/login-history', methods=['GET'])
def get_login_history():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT login_time, ip_address, browser, os, status 
        FROM login_history 
        WHERE user_id = %s 
        ORDER BY login_time DESC 
        LIMIT 100
        ''', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for r in rows:
            # Add mock country based on IP
            ip = r['ip_address']
            country = "Local Network" if ip.startswith("127.") or ip.startswith("192.") or ip == "::1" else "United States"
            history.append({
                "timestamp": str(r['login_time']),
                "ip_address": r['ip_address'],
                "browser": r['browser'],
                "os": r['os'],
                "status": r['status'],
                "country": country
            })
        return jsonify({"status": "success", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
def get_dashboard_analytics():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Monthly Deposits
        cursor.execute('''
        SELECT SUM(amount) as total FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= date('now', '-30 days')
        ''', (user_id,))
        deposits_sum = cursor.fetchone()['total'] or 0.0
        
        # Monthly Withdrawals
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE SENDER = %s AND TTYPE = 'CASH_OUT' AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        withdrawals_sum = cursor.fetchone()['total'] or 0.0
        
        # Monthly Transfers
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE SENDER = %s AND TTYPE = 'TRANSFER' AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        transfers_sum = cursor.fetchone()['total'] or 0.0
        
        # Fraud Attempts (predicted fraud or blocked status)
        cursor.execute('''
        SELECT COUNT(*) as count FROM NEWT 
        WHERE SENDER = %s AND (STATUS = 'BLOCKED' OR IS_FRAUD_PREDICTED = 1) AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        fraud_attempts = cursor.fetchone()['count'] or 0
        
        # High Risk Transactions (risk score >= 70)
        cursor.execute('''
        SELECT COUNT(*) as count FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        # Fetch risk score count
        cursor.execute("SELECT DECISION_TRACE FROM NEWT WHERE SENDER = %s AND TIMESTAMP >= date('now', '-30 days')", (username,))
        high_risk_count = 0
        for row in cursor.fetchall():
            try:
                trace = json.loads(row['DECISION_TRACE'])
                if trace.get('risk_score', 0) >= 70:
                    high_risk_count += 1
            except:
                pass
                
        # Balance Trend (last 10 transactions balances timeline)
        cursor.execute('''
        SELECT TIMESTAMP, SENDERNEWBAL, RECNEWBAL, SENDER, RECEIVER FROM NEWT 
        WHERE (SENDER = %s OR RECEIVER = %s) AND STATUS = 'APPROVED' 
        ORDER BY TIMESTAMP ASC LIMIT 20
        ''', (username, username))
        trend_rows = cursor.fetchall()
        
        balance_trend = []
        for r in trend_rows:
            bal = r['SENDERNEWBAL'] if r['SENDER'] == username else r['RECNEWBAL']
            balance_trend.append({
                "timestamp": str(r['TIMESTAMP']),
                "balance": bal
            })
            
        conn.close()
        
        return jsonify({
            "status": "success",
            "analytics": {
                "monthly_deposits": round(deposits_sum, 2),
                "monthly_withdrawals": round(withdrawals_sum, 2),
                "monthly_transfers": round(transfers_sum, 2),
                "fraud_attempts": fraud_attempts,
                "high_risk_transactions": high_risk_count,
                "balance_trend": balance_trend
            }
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/analytics/insights', methods=['GET'])
def get_financial_insights():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Monthly spending (debits)
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        monthly_spending = cursor.fetchone()['total'] or 0.0
        
        # Previous month spending for comparison
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-60 days') AND TIMESTAMP < date('now', '-30 days')
        ''', (username,))
        prev_spending = cursor.fetchone()['total'] or 0.0
        
        # Spend comparison sentence
        if prev_spending > 0:
            diff_pct = ((monthly_spending - prev_spending) / prev_spending) * 100
            if diff_pct > 0:
                comparison_msg = f"Your spending increased {diff_pct:.1f}% compared to last month."
            else:
                comparison_msg = f"Your spending decreased {abs(diff_pct):.1f}% compared to last month."
        else:
            comparison_msg = "Establish a baseline this month to unlock comparative insights."
            
        # Monthly income (credits)
        cursor.execute('''
        SELECT SUM(amount) as total FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= date('now', '-30 days')
        ''', (user_id,))
        dep_income = cursor.fetchone()['total'] or 0.0
        
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE RECEIVER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username,))
        rec_income = cursor.fetchone()['total'] or 0.0
        
        monthly_income = dep_income + rec_income
        
        # Savings (Income - Spend)
        savings = max(0.0, monthly_income - monthly_spending)
        
        # Largest expense
        cursor.execute('''
        SELECT AMOUNT, RECEIVER, TTYPE FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ORDER BY AMOUNT DESC LIMIT 1
        ''', (username,))
        large_exp_row = cursor.fetchone()
        largest_expense = large_exp_row['AMOUNT'] if large_exp_row else 0.0
        
        # Average Transaction
        cursor.execute('''
        SELECT AVG(AMOUNT) as avg_val FROM NEWT 
        WHERE (SENDER = %s OR RECEIVER = %s) AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        ''', (username, username))
        avg_tx = cursor.fetchone()['avg_val'] or 0.0
        
        # Most used payment type
        cursor.execute('''
        SELECT TTYPE, COUNT(*) as count FROM NEWT 
        WHERE (SENDER = %s OR RECEIVER = %s) AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
        GROUP BY TTYPE ORDER BY count DESC LIMIT 1
        ''', (username, username))
        mode_row = cursor.fetchone()
        most_used_type = mode_row['TTYPE'] if mode_row else "None"
        
        conn.close()
        
        return jsonify({
            "status": "success",
            "insights": {
                "monthly_spending": round(monthly_spending, 2),
                "monthly_income": round(monthly_income, 2),
                "savings": round(savings, 2),
                "largest_expense": round(largest_expense, 2),
                "average_transaction": round(avg_tx, 2),
                "most_used_payment_type": most_used_type,
                "comparison_message": comparison_msg
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/transaction/<int:tx_id>/receipt', methods=['GET'])
def get_transaction_receipt(tx_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check NEWT
        cursor.execute("SELECT * FROM NEWT WHERE ID = %s AND (SENDER = %s OR RECEIVER = %s)", (tx_id, username, username))
        tx = cursor.fetchone()
        
        if tx:
            conn.close()
            trace = {}
            try:
                trace = json.loads(tx['DECISION_TRACE'])
            except:
                pass
            return jsonify({
                "status": "success",
                "receipt": {
                    "receipt_number": f"RCT-TX-{tx['ID']:06d}",
                    "transaction_id": tx['ID'],
                    "sender": tx['SENDER'],
                    "receiver": tx['RECEIVER'],
                    "type": tx['TTYPE'],
                    "amount": tx['AMOUNT'],
                    "status": tx['STATUS'],
                    "timestamp": str(tx['TIMESTAMP']),
                    "risk_score": trace.get('risk_score', 0),
                    "reference_number": f"REF{tx['ID']}X{int(time.time())}"
                }
            })
            
        # Check deposits
        cursor.execute("SELECT d.*, u.USERNAME FROM deposits d JOIN NEWBANK u ON d.user_id = u.ID WHERE d.id = %s AND u.USERNAME = %s", (tx_id, username))
        dep = cursor.fetchone()
        conn.close()
        
        if dep:
            return jsonify({
                "status": "success",
                "receipt": {
                    "receipt_number": f"RCT-DEP-{dep['id']:06d}",
                    "transaction_id": dep['id'],
                    "sender": "External Source",
                    "receiver": dep['USERNAME'],
                    "type": "DEPOSIT",
                    "amount": dep['amount'],
                    "status": dep['status'],
                    "timestamp": str(dep['created_at']),
                    "risk_score": 0,
                    "reference_number": dep['reference_id']
                }
            })
            
        return jsonify({"status": "error", "message": "Receipt not found."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/transaction/<int:tx_id>/receipt/pdf', methods=['GET'])
def get_transaction_receipt_pdf(tx_id):
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check NEWT
        cursor.execute("SELECT * FROM NEWT WHERE ID = %s AND (SENDER = %s OR RECEIVER = %s)", (tx_id, username, username))
        tx = cursor.fetchone()
        
        is_dep = False
        record = tx
        if not tx:
            cursor.execute("SELECT d.*, u.USERNAME FROM deposits d JOIN NEWBANK u ON d.user_id = u.ID WHERE d.id = %s AND u.USERNAME = %s", (tx_id, username))
            dep = cursor.fetchone()
            if dep:
                is_dep = True
                record = dep
                
        conn.close()
        
        if not record:
            return jsonify({"status": "error", "message": "Transaction receipt not found."}), 404
            
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor("#9b5de5")
        text_color = colors.HexColor("#0f172a")
        
        story = []
        
        title_style = ParagraphStyle(
            'ReceiptTitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=primary_color,
            spaceAfter=15,
            alignment=1
        )
        story.append(Paragraph("SMART BANKING - TRANSACTION RECEIPT", title_style))
        story.append(Spacer(1, 10))
        
        # QR Code Verification link
        ref_num = record['reference_id'] if is_dep else f"REF{record['ID']}X99"
        qr_code = createBarcodeDrawing('QR', value=f"https://smartbanking.com/verify/{ref_num}", width=85, height=85)
        
        receipt_no = f"RCT-DEP-{record['id']:06d}" if is_dep else f"RCT-TX-{record['ID']:06d}"
        tx_type = "DEPOSIT" if is_dep else record['TTYPE']
        amount_val = record['amount'] if is_dep else record['AMOUNT']
        status_val = record['status'] if is_dep else record['STATUS']
        timestamp_val = record['created_at'] if is_dep else record['TIMESTAMP']
        sender_val = "External Gateway" if is_dep else record['SENDER']
        receiver_val = record['USERNAME'] if is_dep else record['RECEIVER']
        
        trace = {}
        if not is_dep:
            try:
                trace = json.loads(record['DECISION_TRACE'])
            except:
                pass
        risk_score_val = trace.get('risk_score', 0)
        
        data = [
            [Paragraph("<b>Receipt Number:</b>", styles['Normal']), Paragraph(receipt_no, styles['Normal'])],
            [Paragraph("<b>Transaction ID:</b>", styles['Normal']), Paragraph(str(tx_id), styles['Normal'])],
            [Paragraph("<b>Transaction Type:</b>", styles['Normal']), Paragraph(tx_type, styles['Normal'])],
            [Paragraph("<b>Sender:</b>", styles['Normal']), Paragraph(sender_val, styles['Normal'])],
            [Paragraph("<b>Receiver:</b>", styles['Normal']), Paragraph(receiver_val, styles['Normal'])],
            [Paragraph("<b>Amount:</b>", styles['Normal']), Paragraph(f"Rs {amount_val:,.2f}", styles['Normal'])],
            [Paragraph("<b>Status:</b>", styles['Normal']), Paragraph(status_val, styles['Normal'])],
            [Paragraph("<b>Date & Time:</b>", styles['Normal']), Paragraph(str(timestamp_val), styles['Normal'])],
            [Paragraph("<b>Security Risk Score:</b>", styles['Normal']), Paragraph(f"{risk_score_val}/100", styles['Normal'])],
            [Paragraph("<b>Reference Number:</b>", styles['Normal']), Paragraph(ref_num, styles['Normal'])],
        ]
        
        table = Table(data, colWidths=[200, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0,0), (-1,-1), text_color),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Center QR code
        qr_table = Table([[qr_code]], colWidths=[500])
        qr_table.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')]))
        story.append(qr_table)
        
        story.append(Spacer(1, 15))
        story.append(Paragraph("<font color='gray' size='8'>This is an electronically generated receipt. Verification barcode is valid. Please contact support for any anomalies.</font>", styles['Normal']))
        
        doc.build(story)
        
        from flask import Response
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment;filename=Receipt_{tx_id}.pdf"}
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/statement/download', methods=['GET'])
def download_bank_statement():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        user_id = session['user_id']
        username = session['username']
        
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        
        # If dates are empty, default to last 30 days
        if not start_date:
            start_date = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
        if not end_date:
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user details
        cursor.execute("SELECT * FROM NEWBANK WHERE ID = %s", (user_id,))
        user = cursor.fetchone()
        
        # Calculate opening balance: current balance minus net change after start_date
        # credits: deposits & receiver transfers
        # debits: sender transfers & cashouts
        cursor.execute('''
        SELECT SUM(amount) as total FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= %s
        ''', (user_id, start_date))
        credits_dep = cursor.fetchone()['total'] or 0.0
        
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE RECEIVER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= %s
        ''', (username, start_date))
        credits_tx = cursor.fetchone()['total'] or 0.0
        
        cursor.execute('''
        SELECT SUM(AMOUNT) as total FROM NEWT 
        WHERE SENDER = %s AND STATUS = 'APPROVED' AND TIMESTAMP >= %s
        ''', (username, start_date))
        debits_tx = cursor.fetchone()['total'] or 0.0
        
        current_bal = user['BAL'] or 0.0
        net_after_start = (credits_dep + credits_tx) - debits_tx
        opening_bal = current_bal - net_after_start
        
        # Fetch transactions in date range
        cursor.execute('''
        SELECT TIMESTAMP as date_val, TTYPE as type_val, SENDER, RECEIVER, AMOUNT, 'NEWT' as tbl 
        FROM NEWT 
        WHERE (SENDER = %s OR RECEIVER = %s) AND STATUS = 'APPROVED' AND TIMESTAMP >= %s AND TIMESTAMP <= %s
        ''', (username, username, start_date + " 00:00:00", end_date + " 23:59:59"))
        tx_rows = cursor.fetchall()
        
        cursor.execute('''
        SELECT timestamp as date_val, 'DEPOSIT' as type_val, 'External Gateway' as SENDER, %s as RECEIVER, amount as AMOUNT, 'deposits' as tbl 
        FROM deposits 
        WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= %s AND timestamp <= %s
        ''', (username, user_id, start_date + " 00:00:00", end_date + " 23:59:59"))
        dep_rows = cursor.fetchall()
        
        # Combine
        all_txs = []
        for r in tx_rows:
            all_txs.append({
                "date": str(r['date_val']),
                "type": r['type_val'],
                "desc": f"Transfer to {r['RECEIVER']}" if r['SENDER'] == username else f"Transfer from {r['SENDER']}",
                "amount": r['AMOUNT'],
                "flow": "DEBIT" if r['SENDER'] == username else "CREDIT"
            })
        for r in dep_rows:
            all_txs.append({
                "date": str(r['date_val']),
                "type": "DEPOSIT",
                "desc": "Deposit Top Up",
                "amount": r['AMOUNT'],
                "flow": "CREDIT"
            })
            
        # Sort chronologically
        all_txs.sort(key=lambda x: x['date'])
        
        # Compute closing balance and run ledger balances
        running_bal = opening_bal
        for t in all_txs:
            if t['flow'] == 'CREDIT':
                running_bal += t['amount']
            else:
                running_bal -= t['amount']
            t['running_balance'] = running_bal
            
        closing_bal = running_bal
        
        conn.close()
        
        # Generate Statement PDF using ReportLab
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor("#9b5de5")
        text_color = colors.HexColor("#0f172a")
        
        story = []
        
        title_style = ParagraphStyle(
            'StatementTitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=primary_color,
            spaceAfter=15,
            alignment=0
        )
        story.append(Paragraph("Smart Banking - Bank Statement", title_style))
        story.append(Paragraph(f"<b>Statement Period:</b> {start_date} to {end_date}", styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Account Summary Info
        summary_data = [
            [Paragraph(f"<b>Account Holder:</b> {user['FIRSTNAME']} {user['LASTNAME']}", styles['Normal']), Paragraph(f"<b>Opening Balance:</b> Rs {opening_bal:,.2f}", styles['Normal'])],
            [Paragraph(f"<b>Account Username:</b> {username}", styles['Normal']), Paragraph(f"<b>Closing Balance:</b> Rs {closing_bal:,.2f}", styles['Normal'])],
            [Paragraph(f"<b>Email Address:</b> {user['EMAIL']}", styles['Normal']), Paragraph(f"<b>Statement Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d')}", styles['Normal'])]
        ]
        summary_table = Table(summary_data, colWidths=[250, 250])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('PADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Transactions Table
        tx_header = [
            Paragraph("<b>Date & Time</b>", styles['Normal']),
            Paragraph("<b>Type</b>", styles['Normal']),
            Paragraph("<b>Description</b>", styles['Normal']),
            Paragraph("<b>Amount (Rs)</b>", styles['Normal']),
            Paragraph("<b>Balance (Rs)</b>", styles['Normal'])
        ]
        
        tx_table_data = [tx_header]
        for t in all_txs:
            amt_str = f"+{t['amount']:,.2f}" if t['flow'] == 'CREDIT' else f"-{t['amount']:,.2f}"
            flow_color = "green" if t['flow'] == 'CREDIT' else "red"
            tx_table_data.append([
                Paragraph(t['date'], styles['Normal']),
                Paragraph(t['type'], styles['Normal']),
                Paragraph(t['desc'], styles['Normal']),
                Paragraph(f"<font color='{flow_color}'>{amt_str}</font>", styles['Normal']),
                Paragraph(f"Rs {t['running_balance']:,.2f}", styles['Normal'])
            ])
            
        tx_table = Table(tx_table_data, colWidths=[120, 70, 150, 80, 80])
        tx_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(tx_table)
        
        doc.build(story)
        
        from flask import Response
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment;filename=Statement_{username}_{start_date}_{end_date}.pdf"}
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/audit-logs', methods=['GET'])
def admin_get_audit_logs():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, user_id, username, action, ip_address, device, metadata, created_at 
        FROM audit_logs 
        ORDER BY created_at DESC 
        LIMIT 250
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for r in rows:
            logs.append({
                "id": r['id'],
                "user_id": r['user_id'],
                "username": r['username'],
                "action": r['action'],
                "ip_address": r['ip_address'],
                "device": r['device'],
                "metadata": r['metadata'],
                "timestamp": str(r['created_at'])
            })
        return jsonify({"status": "success", "logs": logs})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/audit-logs/export', methods=['GET'])
def admin_export_audit_logs_csv():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, user_id, username, action, ip_address, device, metadata, created_at 
        FROM audit_logs 
        ORDER BY created_at DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        import csv
        from io import StringIO
        
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(["Log ID", "User ID", "Username", "Action", "IP Address", "Device/Browser", "Metadata", "Timestamp"])
        
        for r in rows:
            cw.writerow([
                r['id'],
                r['user_id'],
                r['username'],
                r['action'],
                r['ip_address'],
                r['device'],
                r['metadata'],
                str(r['created_at'])
            ])
            
        mem = BytesIO()
        mem.write(si.getvalue().encode('utf-8'))
        mem.seek(0)
        
        from flask import Response
        return Response(
            mem.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=Smart_Banking_System_Audit_Logs.csv"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/trigger-monthly-statements', methods=['POST'])
def admin_trigger_monthly_statements():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT ID, USERNAME, EMAIL, FIRSTNAME, LASTNAME, BAL FROM NEWBANK")
        users = cursor.fetchall()
        
        statement_sent_count = 0
        
        for u in users:
            if not u['EMAIL']:
                continue
                
            user_id = u['ID']
            username = u['USERNAME']
            recipient_email = u['EMAIL']
            
            # Deposits in last 30 days
            cursor.execute('''
            SELECT SUM(amount) as total FROM deposits 
            WHERE user_id = %s AND status = 'APPROVED' AND timestamp >= date('now', '-30 days')
            ''', (user_id,))
            deposits_sum = cursor.fetchone()['total'] or 0.0
            
            # Withdrawals in last 30 days
            cursor.execute('''
            SELECT SUM(AMOUNT) as total FROM NEWT 
            WHERE SENDER = %s AND TTYPE = 'CASH_OUT' AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
            ''', (username,))
            withdrawals_sum = cursor.fetchone()['total'] or 0.0
            
            # Transfers in last 30 days
            cursor.execute('''
            SELECT SUM(AMOUNT) as total FROM NEWT 
            WHERE SENDER = %s AND TTYPE = 'TRANSFER' AND STATUS = 'APPROVED' AND TIMESTAMP >= date('now', '-30 days')
            ''', (username,))
            transfers_sum = cursor.fetchone()['total'] or 0.0
            
            # Fraud attempts in last 30 days
            cursor.execute('''
            SELECT COUNT(*) as count FROM NEWT 
            WHERE SENDER = %s AND (STATUS = 'BLOCKED' OR IS_FRAUD_PREDICTED = 1) AND TIMESTAMP >= date('now', '-30 days')
            ''', (username,))
            fraud_count = cursor.fetchone()['count'] or 0
            
            current_bal = u['BAL'] or 0.0
            net_change = deposits_sum - (withdrawals_sum + transfers_sum)
            opening_bal = current_bal - net_change
            
            subject = f"Your Smart Banking Monthly Activity Summary"
            plain_text = f"""Dear {u['FIRSTNAME']} {u['LASTNAME']},

Here is your monthly account statement summary:

Opening Balance: Rs {opening_bal:,.2f}
Total Deposits: Rs {deposits_sum:,.2f}
Total Withdrawals: Rs {withdrawals_sum:,.2f}
Total Transfers Sent: Rs {transfers_sum:,.2f}
Closing Balance: Rs {current_bal:,.2f}

Fraud Alerts/Attempts: {fraud_count}

Thank you for choosing Smart Banking.
"""
            html_body = build_html_email(f"""
            <p>Dear {u['FIRSTNAME']} {u['LASTNAME']},</p>
            <p>Here is your monthly account statement summary:</p>
            <table style='width:100%; border-collapse: collapse; margin-top: 15px;'>
              <tr style='background:#f8fafc; border-bottom:1px solid #e2e8f0;'><td style='padding:8px;'><b>Opening Balance</b></td><td style='padding:8px; text-align:right;'>Rs {opening_bal:,.2f}</td></tr>
              <tr style='border-bottom:1px solid #e2e8f0;'><td style='padding:8px;'><b>Total Deposits</b></td><td style='padding:8px; text-align:right; color:green;'>+Rs {deposits_sum:,.2f}</td></tr>
              <tr style='border-bottom:1px solid #e2e8f0;'><td style='padding:8px;'><b>Total Withdrawals</b></td><td style='padding:8px; text-align:right; color:red;'>-Rs {withdrawals_sum:,.2f}</td></tr>
              <tr style='border-bottom:1px solid #e2e8f0;'><td style='padding:8px;'><b>Total Transfers Sent</b></td><td style='padding:8px; text-align:right; color:red;'>-Rs {transfers_sum:,.2f}</td></tr>
              <tr style='background:#f8fafc; font-weight:bold;'><td style='padding:8px;'><b>Closing Balance</b></td><td style='padding:8px; text-align:right;'>Rs {current_bal:,.2f}</td></tr>
            </table>
            <p style='margin-top: 15px; color: #ef4444;'><b>Security Flagged Fraud Alerts:</b> {fraud_count}</p>
            """)
            
            dispatch_email_async(recipient_email, subject, plain_text, html_body)
            statement_sent_count += 1
            
        conn.close()
        return jsonify({"status": "success", "message": f"Successfully triggered monthly statements for {statement_sent_count} users."})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# Initialize ML and Face Models at startup
load_ml_model()
load_face_models()



# --- Razorpay Payment Gateway (Test Mode) Endpoints ---

@app.route('/api/payment/create-order', methods=['POST'])
def razorpay_create_order():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    rzp_key_id = os.environ.get('RAZORPAY_KEY_ID')
    rzp_key_secret = os.environ.get('RAZORPAY_KEY_SECRET')
    
    if not rzp_key_id or not rzp_key_secret:
        return jsonify({
            "status": "error", 
            "message": "Razorpay payment gateway is not configured on server (Missing API credentials)."
        }), 400

    try:
        data = request.get_json() or {}
        amount_raw = data.get('amount', 0)
        try:
            amount = clean_and_parse_amount(amount_raw)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid transaction amount format."}), 400
            
        import math
        if amount <= 0 or math.isnan(amount) or math.isinf(amount):
            return jsonify({"status": "error", "message": "Amount must be greater than zero."}), 400
            
        if amount > 200000.0:
            return jsonify({"status": "error", "message": "Maximum single transaction limit is ₹2,00,000."}), 400

        # Convert INR to paise safely
        amount_paise = int(round(amount * 100))
        
        # Internal reference ID
        ref_id = f"DEP-{int(time.time())}-{secrets.token_hex(4).upper()}"
        user_id = session['user_id']
        username = session['username']

        # Call Razorpay SDK / API to create Order
        import razorpay
        client = razorpay.Client(auth=(rzp_key_id, rzp_key_secret))
        order_payload = {
            "amount": amount_paise,
            "currency": "INR",
            "receipt": ref_id[:40],
            "payment_capture": 1
        }
        rzp_order = client.order.create(data=order_payload)
        order_id = rzp_order['id']

        # Calculate hybrid risk score
        risk_score, risk_level, reasons, is_fraud_pred, breakdown, ml_prob = compute_hybrid_risk(
            user_id, username, 'Wallet', amount, 'ADD_MONEY'
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch customer details for prefill
        cursor.execute("SELECT FIRSTNAME, LASTNAME, EMAIL, PHONE FROM NEWBANK WHERE ID = %s", (user_id,))
        user_info = cursor.fetchone()
        cust_name = f"{user_info['FIRSTNAME']} {user_info['LASTNAME']}" if user_info else username
        cust_email = user_info['EMAIL'] if user_info else ""
        cust_phone = user_info['PHONE'] if user_info else ""

        # Store initial deposit record (status = INITIATED)
        cursor.execute("""
        INSERT INTO deposits (reference_id, user_id, amount, method, gateway, status, risk_score, risk_level, remarks, razorpay_order_id, balance_before, balance_after)
        VALUES (%s, %s, %s, 'Razorpay', 'Razorpay Test Gateway', 'INITIATED', %s, %s, 'Razorpay Order Created', %s, 0.0, 0.0)
        """, (ref_id, user_id, amount, risk_score, risk_level, order_id))
        
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "key_id": rzp_key_id,
            "order_id": order_id,
            "amount": amount_paise,
            "amount_inr": amount,
            "currency": "INR",
            "reference_id": ref_id,
            "customer_name": cust_name,
            "customer_email": cust_email,
            "customer_phone": cust_phone
        }), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Failed to create Razorpay order: {str(e)}"}), 500


@app.route('/api/payment/verify', methods=['POST'])
def razorpay_verify_payment():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    rzp_key_id = os.environ.get('RAZORPAY_KEY_ID')
    rzp_key_secret = os.environ.get('RAZORPAY_KEY_SECRET')
    
    if not rzp_key_secret:
        return jsonify({"status": "error", "message": "Razorpay secret key is not configured on server."}), 400

    try:
        data = request.get_json() or {}
        order_id = data.get('razorpay_order_id', '').strip()
        payment_id = data.get('razorpay_payment_id', '').strip()
        signature = data.get('razorpay_signature', '').strip()
        ref_id = data.get('reference_id', '').strip()

        if not order_id or not payment_id or not signature:
            return jsonify({"status": "error", "message": "Missing required Razorpay verification parameters."}), 400

        user_id = session['user_id']
        username = session['username']
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Find deposit by reference_id or razorpay_order_id
        cursor.execute("SELECT * FROM deposits WHERE (reference_id = %s OR razorpay_order_id = %s)", (ref_id, order_id))
        dep = cursor.fetchone()

        if not dep:
            conn.close()
            return jsonify({"status": "error", "message": "Deposit reference record not found."}), 404

        # 1. Ownership check: authenticated user must own the deposit
        if dep['user_id'] != user_id:
            conn.close()
            return jsonify({"status": "error", "message": "Unauthorized: Transaction ownership mismatch."}), 403

        # 2. Order ID match check: supplied order ID must match stored order ID
        if dep['razorpay_order_id'] and dep['razorpay_order_id'] != order_id:
            conn.close()
            return jsonify({"status": "error", "message": "Order ID mismatch."}), 400

        # 3. Idempotency Check: razorpay_payment_id or deposit already APPROVED
        cursor.execute("SELECT * FROM deposits WHERE razorpay_payment_id = %s AND status = 'APPROVED'", (payment_id,))
        already_credited = cursor.fetchone()
        
        if already_credited or dep['status'] == 'APPROVED':
            cursor.execute("SELECT BAL FROM NEWBANK WHERE ID = %s", (user_id,))
            u_bal = cursor.fetchone()
            current_user_bal = u_bal['BAL'] if u_bal else 0.0
            conn.close()
            return jsonify({
                "status": "success",
                "message": "Payment has already been verified and processed.",
                "already_processed": True,
                "reference_id": dep['reference_id'],
                "amount": dep['amount'],
                "new_balance": current_user_bal
            }), 200

        # 4. Server-Side Cryptographic Signature Verification
        import razorpay
        client = razorpay.Client(auth=(rzp_key_id or "", rzp_key_secret))
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }

        sig_valid = False
        try:
            client.utility.verify_payment_signature(params_dict)
            sig_valid = True
        except Exception:
            generated_sig = hmac.new(
                rzp_key_secret.encode('utf-8'),
                f"{order_id}|{payment_id}".encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            sig_valid = hmac.compare_digest(generated_sig, signature)

        # Discard signature — DO NOT store razorpay_signature in database
        if not sig_valid:
            cursor.execute("UPDATE deposits SET status = 'FAILED', remarks = 'Invalid Razorpay Signature' WHERE id = %s", (dep['id'],))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": "Invalid Razorpay payment signature."}), 400

        # 4b. Server-Side Payment & Order State Verification via Razorpay API Client
        try:
            rzp_payment = client.payment.fetch(payment_id)
            if rzp_payment:
                pay_status = str(rzp_payment.get('status', '')).lower()
                pay_order_id = rzp_payment.get('order_id', '')
                pay_amount = rzp_payment.get('amount', 0)

                # Confirm payment belongs to expected Razorpay order
                if pay_order_id and pay_order_id != order_id:
                    cursor.execute("UPDATE deposits SET status = 'FAILED', remarks = 'Razorpay Order-Payment Mismatch' WHERE id = %s", (dep['id'],))
                    conn.commit()
                    conn.close()
                    return jsonify({"status": "error", "message": "Razorpay payment does not match expected order ID."}), 400

                # Confirm acceptable successful/captured payment state
                if pay_status and pay_status not in ['captured', 'authorized']:
                    cursor.execute("UPDATE deposits SET status = 'FAILED', remarks = %s WHERE id = %s", (f"Unsuccessful Payment State: {pay_status}", dep['id']))
                    conn.commit()
                    conn.close()
                    return jsonify({"status": "error", "message": f"Payment state '{pay_status}' is not captured/successful."}), 400

                # Confirm amount consistency (if returned by API)
                expected_paise = int(round(dep['amount'] * 100))
                if pay_amount and int(pay_amount) != expected_paise:
                    cursor.execute("UPDATE deposits SET status = 'FAILED', remarks = 'Razorpay Amount Mismatch' WHERE id = %s", (dep['id'],))
                    conn.commit()
                    conn.close()
                    return jsonify({"status": "error", "message": "Razorpay payment amount does not match deposit order amount."}), 400
        except Exception as fetch_err:
            # Handle mock or network exceptions gracefully if payment.fetch is unhandled
            print(f"[WARN] Razorpay payment.fetch state check warning: {fetch_err}", flush=True)

        # 5. Never accept amount from client — use server-side stored amount
        amount = dep['amount']

        # 5b. High-Value Deposit Check (> ₹20,000)
        if amount > 20000.0:
            cursor.execute("SELECT id FROM face_enrollments WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({
                    "status": "error",
                    "message": "Biometric face enrollment is required to credit wallet top-ups above ₹20,000. Please enroll your face first."
                }), 400

            cursor.execute('''
            UPDATE deposits 
            SET status = 'PENDING_BIOMETRIC', 
                razorpay_payment_id = %s, 
                remarks = 'Razorpay Verified — Pending Biometric Verification (> ₹20,000)'
            WHERE id = %s
            ''', (payment_id, dep['id']))

            cursor.execute('''
            INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
            VALUES (%s, 'WALLET_DEPOSIT_PENDING_BIOMETRIC', 'LOW', %s)
            ''', (user_id, f"Razorpay payment {payment_id} verified for INR {amount}. Biometric Face Verification required before wallet credit."))

            conn.commit()
            conn.close()

            session['mfa_pending_token'] = f"DEP_BIO_{dep['id']}"

            return jsonify({
                "status": "biometric_required",
                "biometric_required": True,
                "reference_id": dep['reference_id'],
                "amount": amount,
                "message": "Razorpay payment verified successfully! Biometric Face Verification is required to credit wallet top-ups above ₹20,000."
            }), 200

        # 6. Database Transaction: Credit wallet & insert ledger entry
        cursor.execute("SELECT BAL, EMAIL FROM NEWBANK WHERE ID = %s", (user_id,))
        user_row = cursor.fetchone()
        current_bal = user_row['BAL'] if user_row else 0.0
        user_email = user_row['EMAIL'] if user_row else ""
        new_bal = current_bal + amount

        cursor.execute("UPDATE NEWBANK SET BAL = %s WHERE ID = %s", (new_bal, user_id))

        cursor.execute("""
        UPDATE deposits 
        SET status = 'APPROVED', 
            balance_before = %s, 
            balance_after = %s, 
            razorpay_payment_id = %s, 
            remarks = 'Razorpay Test Payment Verified'
        WHERE id = %s
        """, (current_bal, new_bal, payment_id, dep['id']))

        decision_trace = {
            "gateway": "Razorpay Test Mode",
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "verified_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        cursor.execute("""
        INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, IS_FRAUD_PREDICTED, DECISION_TRACE)
        VALUES (%s, 'Wallet', 'ADD_MONEY', %s, %s, %s, 0.0, 0.0, 'APPROVED', 0, %s)
        """, (username, amount, current_bal, new_bal, json.dumps(decision_trace)))

        cursor.execute("""
        INSERT INTO biometric_security_events (user_id, event_type, severity, metadata)
        VALUES (%s, 'WALLET_DEPOSIT_SUCCESS', 'LOW', %s)
        """, (user_id, f"Added INR {amount} via Razorpay Test Gateway (Payment ID: {payment_id})"))

        conn.commit()
        conn.close()

        # 7. Post-transaction email notification in try-except
        if user_email:
            try:
                send_deposit_email(user_email, dep['reference_id'], amount, current_bal, new_bal, payment_id=payment_id)
            except Exception as e_mail:
                print(f"[WARN] Post-transaction Razorpay deposit email notification failed: {e_mail}", flush=True)

        return jsonify({
            "status": "success",
            "message": "Payment verified and wallet credited successfully!",
            "reference_id": dep['reference_id'],
            "amount": amount,
            "new_balance": new_bal
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Payment verification error: {str(e)}"}), 500



# --- Admin Fraud Feedback Loop Endpoints ---

@app.route('/api/admin/fraud-feedback', methods=['POST'])
def admin_fraud_feedback():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized: Administrator access required."}), 403

    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload."}), 400

        token = data.get('transaction_token', '').strip()
        label = data.get('label', '').strip().upper()
        notes = data.get('notes', '').strip()

        if label not in ['CONFIRMED_FRAUD', 'LEGITIMATE', 'UNCERTAIN']:
            return jsonify({"status": "error", "message": "Invalid feedback label. Allowed: CONFIRMED_FRAUD, LEGITIMATE, UNCERTAIN."}), 400

        admin_id = session['user_id']
        admin_user = session['username']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch transaction details from pending_transactions or NEWT
        cursor.execute("SELECT * FROM pending_transactions WHERE token = %s", (token,))
        tx = cursor.fetchone()
        
        tx_id = None
        sender = None
        receiver = None
        amount = None
        ttype = None
        risk_score = None
        risk_level = None
        ml_prob = None

        if tx:
            tx_id = tx['id']
            sender = session.get('username', 'system')
            receiver = tx['receiver']
            amount = tx['amount']
            ttype = tx['ttype']
            risk_score = tx['risk_score']
            risk_level = tx['risk_level']
            try:
                trace = json.loads(tx['decision_trace'] or '{}')
                ml_prob = trace.get('ml_probability', 0.0)
            except:
                ml_prob = 0.0

        cursor.execute('''
        INSERT INTO fraud_feedback (transaction_id, transaction_token, admin_user_id, admin_username, sender, receiver, amount, ttype, label, risk_score, risk_level, ml_probability, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (tx_id, token, admin_id, admin_user, sender, receiver, amount, ttype, label, risk_score, risk_level, ml_prob, notes))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Fraud feedback '{label}' submitted successfully for transaction."
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/admin/fraud-feedback/export', methods=['GET'])
def admin_fraud_feedback_export():
    if 'username' not in session or not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized: Administrator access required."}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        SELECT id, transaction_token, sender, receiver, amount, ttype, label, risk_score, risk_level, ml_probability, admin_username, created_at, notes
        FROM fraud_feedback 
        ORDER BY created_at DESC
        ''')
        rows = cursor.fetchall()
        conn.close()

        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "transaction_token", "sender", "receiver", "amount", 
            "ttype", "label", "risk_score", "risk_level", "ml_probability", 
            "admin_username", "created_at", "notes"
        ])

        for r in rows:
            writer.writerow([
                r['id'], r['transaction_token'], r['sender'], r['receiver'], r['amount'],
                r['ttype'], r['label'], r['risk_score'], r['risk_level'], r['ml_probability'],
                r['admin_username'], r['created_at'], r['notes']
            ])

        csv_content = output.getvalue()
        output.close()

        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=fraud_feedback_dataset.csv"}
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    is_dev = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == '1' or not os.environ.get('RENDER')
    socketio.run(app, host='0.0.0.0', port=port, debug=is_dev, use_reloader=False, allow_unsafe_werkzeug=is_dev)
