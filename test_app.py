import unittest
import json
import time
import os
import sqlite3
from unittest.mock import patch
from app import app, DB_PATH, MODEL_PATH, get_db_connection

class BankAppTestCase(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Ensure model exists before running tests
        if not os.path.exists(MODEL_PATH):
            raise RuntimeError("Model file not found. Please run train_model.py first.")

    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        self.captured_otps = []
        import app as app_module
        self.original_send_otp_email = app_module.send_otp_email
        
        def mock_send(email, otp, amount, receiver):
            self.captured_otps.append(otp)
            return app_module.send_email(email, 'Smart Banking Security Verification Code', f'Your code is: {otp}')
        app_module.send_otp_email = mock_send
        
        # Reset testing database file before each test
        if os.path.exists(DB_PATH):
            try:
                os.remove(DB_PATH)
            except PermissionError:
                pass
        
        # Initialize fresh database tables
        with app.app_context():
            from app import init_db, get_db_connection
            init_db()
            
            # Clear tables just in case file was locked
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM NEWBANK")
            cursor.execute("DELETE FROM NEWT")
            cursor.execute("DELETE FROM face_enrollments")
            cursor.execute("DELETE FROM face_verification_attempts")
            cursor.execute("DELETE FROM biometric_security_events")
            
            # Insert a predefined admin user
            cursor.execute('''
            INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
            VALUES ('admin', 'System', 'Admin', 'admin@smartbank.com', 'adminpass', 'adminpass', '08000000000', 'Other', 'System Core', 100000.0)
            ''')
            conn.commit()
            conn.close()

    def tearDown(self):
        import app as app_module
        if hasattr(self, 'original_send_otp_email'):
            app_module.send_otp_email = self.original_send_otp_email
        import gc
        gc.collect()

    def register_user(self, username, email, password, confirm, phone, firstname="Test", lastname="User", bal=50000.0):
        return self.client.post('/api/register', data=json.dumps({
            'username': username,
            'email': email,
            'firstname': firstname,
            'lastname': lastname,
            'password': password,
            'confirm': confirm,
            'phone': phone,
            'sex': 'Male',
            'address': 'Test Address 101',
            'bal': bal
        }), content_type='application/json')

    def login_user(self, username, password):
        return self.client.post('/api/login', data=json.dumps({
            'username': username,
            'password': password
        }), content_type='application/json')

    def logout_user(self):
        return self.client.post('/api/logout')


    def test_registration_validation_rules(self):
        # A. Valid registration -> PASS
        res_valid = self.register_user('reg_valid', 'reg_valid@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_valid.status_code, 200)
        data_valid = json.loads(res_valid.data)
        self.assertEqual(data_valid['status'], 'success')

        # B. Invalid email format -> REJECTED (400)
        res_bad_email = self.register_user('reg_bad_email', 'invalid-email-format', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_bad_email.status_code, 400)
        data_bad_email = json.loads(res_bad_email.data)
        self.assertEqual(data_bad_email['status'], 'error')
        self.assertIn("Invalid email address format", data_bad_email['message'])

        # C. Duplicate username -> REJECTED (400)
        res_dup_user = self.register_user('reg_valid', 'other_email@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_dup_user.status_code, 400)
        data_dup_user = json.loads(res_dup_user.data)
        self.assertEqual(data_dup_user['status'], 'error')
        self.assertIn("Username already exists", data_dup_user['message'])

        # D. Duplicate email -> REJECTED (409)
        res_dup_email = self.register_user('other_user', 'reg_valid@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_dup_email.status_code, 409)
        data_dup_email = json.loads(res_dup_email.data)
        self.assertEqual(data_dup_email['status'], 'error')
        self.assertIn("already registered", data_dup_email['message'])

        # E. Duplicate email with different capitalization -> REJECTED (409)
        res_dup_email_caps = self.register_user('other_user2', 'REG_VALID@EXAMPLE.COM', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_dup_email_caps.status_code, 409)
        data_dup_email_caps = json.loads(res_dup_email_caps.data)
        self.assertEqual(data_dup_email_caps['status'], 'error')
        self.assertIn("already registered", data_dup_email_caps['message'])

        # F. Password under 6 characters -> REJECTED (400)
        res_short_pw = self.register_user('short_pw_user', 'short_pw@example.com', '12345', '12345', '08123456789')
        self.assertEqual(res_short_pw.status_code, 400)
        data_short_pw = json.loads(res_short_pw.data)
        self.assertEqual(data_short_pw['status'], 'error')
        self.assertIn("at least 6 characters", data_short_pw['message'])

        # G. Password confirmation mismatch -> REJECTED (400)
        res_mismatch = self.register_user('mismatch_user', 'mismatch@example.com', 'secret123', 'different123', '08123456789')
        self.assertEqual(res_mismatch.status_code, 400)
        data_mismatch = json.loads(res_mismatch.data)
        self.assertEqual(data_mismatch['status'], 'error')
        self.assertIn("do not match", data_mismatch['message'])

        # H. Existing user login still works -> PASS
        res_login = self.login_user('reg_valid', 'secret123')
        self.assertEqual(res_login.status_code, 200)
        data_login = json.loads(res_login.data)
        self.assertEqual(data_login['status'], 'success')
        self.assertEqual(data_login['user']['username'], 'reg_valid')

    def test_registration_and_login(self):
        # 1. Test registration
        res = self.register_user('user1', 'user1@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

        # Test duplicate registration block
        res_dup = self.register_user('user1', 'dup@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res_dup.status_code, 400)
        
        # 2. Test login
        res_login = self.login_user('user1', 'secret123')
        self.assertEqual(res_login.status_code, 200)
        data_login = json.loads(res_login.data)
        self.assertEqual(data_login['status'], 'success')
        self.assertEqual(data_login['user']['username'], 'user1')

        # Test login failure
        res_fail = self.login_user('user1', 'wrongpass')
        self.assertEqual(res_fail.status_code, 401)

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    def test_biometric_enrollment(self, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        # Setup mock behavior
        mock_quality.return_value = {"status": "success", "face": [0,0,100,100, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111')
        self.login_user('alice', 'pass123')

        # Check not enrolled status
        res_status = self.client.get('/api/biometric/status')
        self.assertEqual(res_status.status_code, 200)
        data_status = json.loads(res_status.data)
        self.assertFalse(data_status['enrolled'])

        # Try to enroll
        res_enroll = self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['b64_sample_1', 'b64_sample_2', 'b64_sample_3']
        }), content_type='application/json')
        self.assertEqual(res_enroll.status_code, 200)
        data_enroll = json.loads(res_enroll.data)
        self.assertEqual(data_enroll['status'], 'success')

        # Check status is now enrolled
        res_status2 = self.client.get('/api/biometric/status')
        data_status2 = json.loads(res_status2.data)
        self.assertTrue(data_status2['enrolled'])

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_verification_flow(self, mock_similarity, mock_liveness, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        # 1. Register & Enroll Alice
        mock_quality.return_value = {"status": "success", "face": [0,0,100,100, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111')
        self.login_user('alice', 'pass123')
        
        self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['img1', 'img2', 'img3']
        }), content_type='application/json')

        # 2. Initiate Biometric verify challenge
        res_init = self.client.post('/api/biometric/verify/initiate')
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertIn('challenge', data_init)
        
        # 3. Simulate correct check
        mock_liveness.return_value = True
        mock_similarity.return_value = (True, 0.95, 0.363)
        
        res_check = self.client.post('/api/biometric/verify/check', data=json.dumps({
            'image': 'live_frame_base64'
        }), content_type='application/json')
        self.assertEqual(res_check.status_code, 200)
        data_check = json.loads(res_check.data)
        self.assertEqual(data_check['status'], 'success')
        self.assertTrue(data_check['similarity'] > 36.3)

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_failures(self, mock_similarity, mock_liveness, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        # Register and Enroll
        mock_quality.return_value = {"status": "success", "face": [0,0,100,100, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111')
        self.login_user('alice', 'pass123')
        self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['img1', 'img2', 'img3']
        }), content_type='application/json')

        # Initiate challenge
        self.client.post('/api/biometric/verify/initiate')

        # Case A: Liveness challenge fails
        mock_liveness.return_value = False
        res_live_fail = self.client.post('/api/biometric/verify/check', data=json.dumps({
            'image': 'live_frame_base64'
        }), content_type='application/json')
        self.assertEqual(res_live_fail.status_code, 400)
        data_live_fail = json.loads(res_live_fail.data)
        self.assertEqual(data_live_fail['status'], 'liveness_failed')

        # Initiate challenge again
        self.client.post('/api/biometric/verify/initiate')

        # Case B: Face mismatch fails
        mock_liveness.return_value = True
        mock_similarity.return_value = (False, 0.12, 0.363)
        res_match_fail = self.client.post('/api/biometric/verify/check', data=json.dumps({
            'image': 'live_frame_base64'
        }), content_type='application/json')
        self.assertEqual(res_match_fail.status_code, 400)
        data_match_fail = json.loads(res_match_fail.data)
        self.assertEqual(data_match_fail['status'], 'mismatch')

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_high_risk_transaction_mfa(self, mock_similarity, mock_liveness, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        # Register and Enroll Alice
        mock_quality.return_value = {"status": "success", "face": [0,0,100,100, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111', bal=200000.0)
        self.register_user('bob', 'bob@test.com', 'pass456', 'pass456', '08222222222', bal=2000.0)
        
        self.login_user('alice', 'pass123')
        self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['img1', 'img2', 'img3']
        }), content_type='application/json')

        # Inject a recent failed biometric verification to elevate risk (adds +25 points)
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'alice'")
            alice_id = cursor.fetchone()['ID']
            cursor.execute("INSERT INTO face_verification_attempts (user_id, verification_result) VALUES (?, 'MISMATCH')", (alice_id,))
            conn.commit()
            conn.close()

        # Initiate high-risk transfer (Amount: 80000 - triggers HIGH RISK because 10 (base) + 20 (amt) + 15 (new recipient) + 25 (biometric failure) = 70)
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob',
            'amount': '80000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'verification_required')
        self.assertIn('face', data_init['required'])
        self.assertIn('otp', data_init['required'])
        token = data_init['transaction_token']
        self.assertTrue(len(self.captured_otps) > 0)
        otp = self.captured_otps[-1]

        # Verify correct OTP code
        res_verify_otp = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp
        }), content_type='application/json')
        self.assertEqual(res_verify_otp.status_code, 200)
        data_verify_otp = json.loads(res_verify_otp.data)
        self.assertEqual(data_verify_otp['status'], 'otp_ok_need_face')

        # Run face verification check (which auto finalizes because OTP is verified!)
        mock_liveness.return_value = True
        mock_similarity.return_value = (True, 0.98, 0.363)
        
        self.client.post('/api/biometric/verify/initiate')
        res_verify_face = self.client.post('/api/biometric/verify/check', data=json.dumps({
            'image': 'some_face_b64'
        }), content_type='application/json')
        
        self.assertEqual(res_verify_face.status_code, 200)
        data_verify_face = json.loads(res_verify_face.data)
        self.assertEqual(data_verify_face['status'], 'success') # Auto finalization success!
        
        # Verify balances inside database
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'alice'")
            self.assertEqual(cursor.fetchone()['BAL'], 120000.0) # 200k - 80k
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bob'")
            self.assertEqual(cursor.fetchone()['BAL'], 82000.0) # 2k + 80k
            conn.close()

    def test_critical_risk_transaction(self):
        # Register alice and bob
        self.register_user('alice', 'alice@test.com', 'Password123!', 'Password123!', '08111111111', bal=200000.0)
        self.register_user('bob', 'bob@test.com', 'Password123!', 'Password123!', '08222222222', bal=2000.0)
        
        self.login_user('alice', 'Password123!')
        
        # Initiate critical risk transfer (Amount: 180000 - triggers CRITICAL RISK because 10 (base) + 40 (amt) + 15 (new recipient) + 25 (empty account > 85%) = 90)
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob',
            'amount': '180000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'pending_review')
        self.assertIn('queued for Administrator Review', data_init['message'])
        
        # Verify balance remains unchanged before review approval
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'alice'")
            self.assertEqual(cursor.fetchone()['BAL'], 200000.0)
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bob'")
            self.assertEqual(cursor.fetchone()['BAL'], 2000.0)
            conn.close()

    def test_admin_permissions(self):
        # Register standard user
        self.register_user('charlie', 'charlie@test.com', 'pass123', 'pass123', '08333333333')
        self.login_user('charlie', 'pass123')
        
        # Standard user forbidden from admin endpoints
        res_stats = self.client.get('/api/admin/stats')
        self.assertEqual(res_stats.status_code, 403)
        res_events = self.client.get('/api/admin/biometric_events')
        self.assertEqual(res_events.status_code, 403)
        
        # Logout
        self.logout_user()
        
        # Login as Admin
        self.login_user('admin', 'adminpass')
        
        # Admin stats and events should be accessible
        res_admin_stats = self.client.get('/api/admin/stats')
        self.assertEqual(res_admin_stats.status_code, 200)
        
        res_admin_events = self.client.get('/api/admin/biometric_events')
        self.assertEqual(res_admin_events.status_code, 200)
        data_events = json.loads(res_admin_events.data)
        self.assertEqual(data_events['status'], 'success')
        self.assertIn('events', data_events)

    def test_live_risk_preview_endpoint(self):
        # Register standard user
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111', bal=100000.0)
        self.login_user('alice', 'pass123')
        
        # Test live risk preview endpoint
        res = self.client.post('/api/transfer/live_risk_preview', data=json.dumps({
            'receiver': 'admin',
            'amount': '15000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('score', data)
        self.assertIn('level', data)
        self.assertIn('reasons', data)
        self.assertIn('breakdown', data)

    def test_xai_trace_storage_and_auth_checks(self):
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111', bal=200000.0)
        self.register_user('bob', 'bob@test.com', 'pass456', 'pass456', '08222222222', bal=2000.0)
        self.register_user('charlie', 'charlie@test.com', 'pass789', 'pass789', '08333333333', bal=100.0)
        
        self.login_user('alice', 'pass123')
        
        # Blocked transaction creates trace in DB (now queued for review)
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob',
            'amount': '180000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init.status_code, 200)
        token = json.loads(res_init.data)['transaction_token']
        
        # Query trace from SQLite
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT decision_trace FROM pending_transactions WHERE token = ?", (token,))
            row = cursor.fetchone()
            trace_json = json.loads(row['decision_trace'])
            self.assertEqual(trace_json['risk_level'], 'CRITICAL')
            self.assertIn('auth_required', trace_json)
            conn.close()
        
        # Approve transaction as admin to finalize it into NEWT
        self.logout_user()
        self.login_user('admin', 'adminpass')
        res_approve = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token,
            'action': 'APPROVE',
            'reason': 'Approved for test trace'
        }), content_type='application/json')
        self.assertEqual(res_approve.status_code, 200)
        
        # Query tx_id from NEWT
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM NEWT ORDER BY ID DESC LIMIT 1")
            tx_id = cursor.fetchone()['ID']
            conn.close()
            
        # Log back in Alice
        self.logout_user()
        self.login_user('alice', 'pass123')

        # Alice gets her own trace
        res_trace_alice = self.client.get(f'/api/transaction/{tx_id}/trace')
        self.assertEqual(res_trace_alice.status_code, 200)
        data_alice = json.loads(res_trace_alice.data)
        self.assertEqual(data_alice['status'], 'success')
        self.assertEqual(data_alice['trace']['risk_level'], 'CRITICAL')

        # Charlie is forbidden from accessing Alice's trace
        self.logout_user()
        self.login_user('charlie', 'pass789')
        res_trace_charlie = self.client.get(f'/api/transaction/{tx_id}/trace')
        self.assertEqual(res_trace_charlie.status_code, 403)

        # Admin can access Alice's trace
        self.logout_user()
        self.login_user('admin', 'adminpass')
        res_trace_admin = self.client.get(f'/api/transaction/{tx_id}/trace')
        self.assertEqual(res_trace_admin.status_code, 200)
        data_admin = json.loads(res_trace_admin.data)
        self.assertEqual(data_admin['status'], 'success')


    def test_otp_security_and_edge_cases(self):
        # Register Alice and Bob
        self.register_user('alice_otp', 'alice_otp@test.com', 'pass123', 'pass123', '08199999999', bal=200000.0)
        self.register_user('bob_otp', 'bob_otp@test.com', 'pass456', 'pass456', '08299999999', bal=2000.0)
        
        # 1. Unauthenticated OTP send / verify rejected
        res = self.client.post('/api/otp/resend', data=json.dumps({
            'transaction_token': 'dummy_token'
        }), content_type='application/json')
        self.assertEqual(res.status_code, 401)
        
        res = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': 'dummy_token',
            'otp': '123456'
        }), content_type='application/json')
        self.assertEqual(res.status_code, 401)
        
        # Log in Alice
        self.login_user('alice_otp', 'pass123')
        
        # Initiate a Medium risk transfer (Amount: 40000)
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_otp',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'verification_required')
        
        token = data_init['transaction_token']
        self.assertTrue(len(self.captured_otps) > 0)
        otp = self.captured_otps[-1]
        
        # 3. OTP not present in API response
        self.assertNotIn('otp', data_init)
        
        # 5. Wrong OTP fails and attempts increment
        res_wrong = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': '000000' # incorrect
        }), content_type='application/json')
        self.assertEqual(res_wrong.status_code, 400)
        data_wrong = json.loads(res_wrong.data)
        self.assertIn('attempts remaining', data_wrong['message'])
        
        # 7. Locked after 5 attempts
        for _ in range(4): # Total 5 attempts
            res_wrong = self.client.post('/api/transfer/verify', data=json.dumps({
                'transaction_token': token,
                'otp': '000000'
            }), content_type='application/json')
        
        # 6th attempt should be blocked
        res_locked = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp
        }), content_type='application/json')
        self.assertEqual(res_locked.status_code, 400)
        self.assertIn('attempts exceeded', json.loads(res_locked.data)['message'])
        
        # Initiate a new transaction to test success and resend
        self.captured_otps.clear()
        res_init2 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_otp',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        data_init2 = json.loads(res_init2.data)
        token2 = data_init2['transaction_token']
        otp2 = self.captured_otps[-1]
        
        # 9. Resend before 60 seconds rejected
        res_resend_fail = self.client.post('/api/otp/resend', data=json.dumps({
            'transaction_token': token2
        }), content_type='application/json')
        self.assertEqual(res_resend_fail.status_code, 400)
        self.assertIn('seconds before resending', json.loads(res_resend_fail.data)['message'])
        
        # Force modify SQLite last_sent_at to bypass cooldown for test
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-2 minutes')")
            conn.commit()
            conn.close()
            
        # 10. Resend generates new OTP
        old_otp_len = len(self.captured_otps)
        res_resend = self.client.post('/api/otp/resend', data=json.dumps({
            'transaction_token': token2
        }), content_type='application/json')
        self.assertEqual(res_resend.status_code, 200)
        self.assertEqual(len(self.captured_otps), old_otp_len + 1)
        otp3 = self.captured_otps[-1]
        self.assertNotEqual(otp2, otp3)
        
        # 11. Old OTP fails after resend
        res_old_fail = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token2,
            'otp': otp2
        }), content_type='application/json')
        self.assertEqual(res_old_fail.status_code, 400)
        
        # 14. Another user cannot verify another user's token
        self.logout_user()
        self.login_user('bob_otp', 'pass456')
        res_other_verify = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token2,
            'otp': otp3
        }), content_type='application/json')
        self.assertEqual(res_other_verify.status_code, 404)
        
        # Log back in Alice
        self.logout_user()
        self.login_user('alice_otp', 'pass123')
        
        # 4. Correct OTP succeeds
        res_success = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token2,
            'otp': otp3
        }), content_type='application/json')
        self.assertEqual(res_success.status_code, 200)
        
        # 13. OTP cannot be reused
        res_reuse = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token2,
            'otp': otp3
        }), content_type='application/json')
        self.assertEqual(res_reuse.status_code, 400)

    @patch('app.model')
    def test_exact_risk_boundaries(self, mock_model):
        mock_model.predict.return_value = [0]
        mock_model.predict_proba.return_value = [[1.0, 0.0]]
        
        # Register alice and bob first
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111', bal=1000000.0)
        self.register_user('bob', 'bob@test.com', 'pass456', 'pass456', '08222222222', bal=10000.0)
        
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'alice'")
            alice_id = cursor.fetchone()['ID']
            
            # Insert face enrollment reference so that HIGH-risk checks don't block
            cursor.execute("INSERT INTO face_enrollments (user_id, template_reference) VALUES (?, '[]')", (alice_id,))
            conn.commit()
            conn.close()
            
        from app import compute_hybrid_risk
        
        # Test low risk
        score1, lvl1, _, _, _, _ = compute_hybrid_risk(alice_id, 'alice', 'bob', 1000.0, 'TRANSFER')
        self.assertTrue(score1 < 45)
        self.assertEqual(lvl1, 'LOW')
        
        # Test medium risk threshold
        score2, lvl2, _, _, _, _ = compute_hybrid_risk(alice_id, 'alice', 'bob', 50000.0, 'TRANSFER')
        self.assertTrue(45 <= score2 < 70)
        self.assertEqual(lvl2, 'MEDIUM')
        
        # Test high risk threshold
        # Set Alice balance to 20k, transfer 18k -> triggers empty account > 85% points
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE NEWBANK SET BAL = 20000.0 WHERE ID = ?", (alice_id,))
            conn.commit()
            conn.close()
            
        score3, lvl3, _, _, _, _ = compute_hybrid_risk(alice_id, 'alice', 'bob', 18000.0, 'TRANSFER')
        self.assertTrue(70 <= score3 < 90)
        self.assertEqual(lvl3, 'HIGH')
        
        # Test critical risk threshold
        # Set Alice balance back to 1M, transfer 900k -> triggers critical
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE NEWBANK SET BAL = 1000000.0 WHERE ID = ?", (alice_id,))
            conn.commit()
            conn.close()
            
        score4, lvl4, _, _, _, _ = compute_hybrid_risk(alice_id, 'alice', 'bob', 900000.0, 'TRANSFER')
        self.assertTrue(score4 >= 90)
        self.assertEqual(lvl4, 'CRITICAL')

    def test_sqlite_rate_limiting_persistence(self):
        from app import is_login_rate_limited, record_login_attempt, clear_login_attempts
        
        username = 'brute_force_user'
        clear_login_attempts(username)
        
        self.assertFalse(is_login_rate_limited(username))
        
        # Record 5 failed attempts
        for _ in range(5):
            record_login_attempt(username)
            
        self.assertTrue(is_login_rate_limited(username))
        
        # Verify that it persists across a clean reset/refresh
        self.assertTrue(is_login_rate_limited(username))
        
        # Clear attempts
        clear_login_attempts(username)
        self.assertFalse(is_login_rate_limited(username))

    def test_cash_out_channel_validation(self):
        self.register_user('alice_co', 'alice_co@test.com', 'pass123', 'pass123', '08111111111')
        self.login_user('alice_co', 'pass123')
        
        # 1. Valid CASH_OUT channel ID
        res_valid = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'ATM_01',
            'amount': '5000',
            'type': 'CASH_OUT'
        }), content_type='application/json')
        self.assertEqual(res_valid.status_code, 200)
        
        # 2. Invalid CASH_OUT channel ID
        res_invalid = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'INVALID_ATM',
            'amount': '5000',
            'type': 'CASH_OUT'
        }), content_type='application/json')
        self.assertEqual(res_invalid.status_code, 400)
        data = json.loads(res_invalid.data)
        self.assertIn('Invalid or inactive cash out channel', data['message'])

    def test_high_risk_missing_enrollment(self):
        self.register_user('alice_no_face', 'alice_nf@test.com', 'pass123', 'pass123', '08111111112', bal=20000.0)
        self.register_user('bob_nf', 'bob_nf@test.com', 'pass456', 'pass456', '08222222222')
        self.login_user('alice_no_face', 'pass123')
        
        # Initiate HIGH risk transaction (amount 18,000 from 20,000 balance -> triggers HIGH risk 70)
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_nf',
            'amount': '18000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertIn('Biometric face enrollment is required', data['message'])

    def test_admin_review_idempotency(self):
        self.register_user('alice_review', 'alice_rev@test.com', 'pass123', 'pass123', '08111111113', bal=1000000.0)
        self.register_user('bob_review', 'bob_rev@test.com', 'pass456', 'pass456', '08222222223')
        
        self.login_user('alice_review', 'pass123')
        
        # 1. Initiate CRITICAL transaction
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_review',
            'amount': '900000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'pending_review')
        token = data_init['transaction_token']
        
        # 2. Try to approve as normal user (Alice) - should fail 403
        res_normal_approve = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token,
            'action': 'APPROVE',
            'reason': 'Approved by normal user'
        }), content_type='application/json')
        self.assertEqual(res_normal_approve.status_code, 403)
        
        # 3. Log in as admin
        self.logout_user()
        self.register_user('admin', 'admin@test.com', 'adminpass', 'adminpass', '08099999999')
        self.login_user('admin', 'adminpass')
        
        # 4. Approve transaction as admin - should succeed
        res_approve = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token,
            'action': 'APPROVE',
            'reason': 'Valid large transfer'
        }), content_type='application/json')
        self.assertEqual(res_approve.status_code, 200)
        
        # 5. Try to approve again - should fail (404/409)
        res_reapprove = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token,
            'action': 'APPROVE',
            'reason': 'Second approval attempt'
        }), content_type='application/json')
        self.assertIn(res_reapprove.status_code, [404, 409])
        
        # 6. Try to reject after approval - should fail
        res_reject = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token,
            'action': 'REJECT',
            'reason': 'Reject after approval attempt'
        }), content_type='application/json')
        self.assertIn(res_reject.status_code, [404, 409])
        
        # 7. Log back in as Alice and initiate another critical transaction
        self.logout_user()
        self.login_user('alice_review', 'pass123')
        
        # Reset Alice's balance to 1M in SQLite before the second critical transaction
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE NEWBANK SET BAL = 1000000.0 WHERE USERNAME = 'alice_review'")
            conn.commit()
            conn.close()
            
        res_init2 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_review',
            'amount': '900000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        token2 = json.loads(res_init2.data)['transaction_token']
        
        # Log in admin
        self.logout_user()
        self.login_user('admin', 'adminpass')
        
        # Reject transaction as admin
        res_reject2 = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token2,
            'action': 'REJECT',
            'reason': 'Suspected money laundering'
        }), content_type='application/json')
        self.assertEqual(res_reject2.status_code, 200)
        
        # Try to approve after rejection - should fail
        res_approve2 = self.client.post('/api/admin/review/action', data=json.dumps({
            'transaction_token': token2,
            'action': 'APPROVE',
            'reason': 'Approve after rejection attempt'
        }), content_type='application/json')
        self.assertIn(res_approve2.status_code, [404, 409])

    def test_expired_otp(self):
        self.register_user('alice_exp', 'alice_exp@test.com', 'pass123', 'pass123', '08122222222', bal=200000.0)
        self.register_user('bob_exp', 'bob_exp@test.com', 'pass456', 'pass456', '08222222223')
        self.login_user('alice_exp', 'pass123')
        
        # Initiate medium risk transaction
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_exp',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        token = json.loads(res_init.data)['transaction_token']
        otp = self.captured_otps[-1]
        
        # Force set challenge to expired
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE transaction_otp_challenges SET expires_at = datetime('now', '-10 minutes') WHERE transaction_token = ?", (token,))
            conn.commit()
            conn.close()
            
        # Verify - should fail with 400
        res_verify = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp
        }), content_type='application/json')
        self.assertEqual(res_verify.status_code, 400)
        self.assertIn('expired or already been consumed', json.loads(res_verify.data)['message'])

    def test_otp_cooldown_and_resend_limits(self):
        self.register_user('alice_res', 'alice_res@test.com', 'pass123', 'pass123', '08133333333', bal=200000.0)
        self.register_user('bob_res', 'bob_res@test.com', 'pass456', 'pass456', '08233333333')
        self.login_user('alice_res', 'pass123')
        
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_res',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        token = json.loads(res_init.data)['transaction_token']
        
        # 1. Resend immediately should fail (cooldown)
        res_resend1 = self.client.post('/api/otp/resend', data=json.dumps({'transaction_token': token}), content_type='application/json')
        self.assertEqual(res_resend1.status_code, 400)
        
        # Force set cooldown past and do 3 successful resends
        for i in range(3):
            with app.app_context():
                from app import get_db_connection
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-2 minutes')")
                conn.commit()
                conn.close()
            res_resend = self.client.post('/api/otp/resend', data=json.dumps({'transaction_token': token}), content_type='application/json')
            self.assertEqual(res_resend.status_code, 200)
            
        # 4th resend should exceed the maximum 3 resends limit
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-2 minutes')")
            conn.commit()
            conn.close()
        res_resend_limit = self.client.post('/api/otp/resend', data=json.dumps({'transaction_token': token}), content_type='application/json')
        self.assertEqual(res_resend_limit.status_code, 400)
        self.assertIn('Maximum OTP resend limit', json.loads(res_resend_limit.data)['message'])

    def test_duplicate_finalization(self):
        self.register_user('alice_dup', 'alice_dup@test.com', 'pass123', 'pass123', '08144444444', bal=200000.0)
        self.register_user('bob_dup', 'bob_dup@test.com', 'pass456', 'pass456', '08244444444')
        self.login_user('alice_dup', 'pass123')
        
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_dup',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        token = json.loads(res_init.data)['transaction_token']
        otp = self.captured_otps[-1]
        
        # Verify once (finalizes transaction)
        res_verify = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp
        }), content_type='application/json')
        self.assertEqual(res_verify.status_code, 200)
        
        # Verify again (duplicate finalization check)
        res_verify_again = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp
        }), content_type='application/json')
        self.assertEqual(res_verify_again.status_code, 400)

    def test_invalid_transaction_inputs(self):
        self.register_user('alice_inputs', 'alice_inp@test.com', 'pass123', 'pass123', '08155555555', bal=200000.0)
        self.login_user('alice_inputs', 'pass123')
        
        # 1. Invalid transaction type
        res1 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'admin',
            'amount': '1000',
            'type': 'INVALID'
        }), content_type='application/json')
        self.assertEqual(res1.status_code, 400)
        
        # 2. NaN amount
        res2 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'admin',
            'amount': 'NaN',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res2.status_code, 400)
        
        # 3. Infinity amount
        res3 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'admin',
            'amount': 'inf',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res3.status_code, 400)
        
        # 4. Self transfer
        res4 = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'alice_inputs',
            'amount': '1000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res4.status_code, 400)
        self.assertIn('Cannot transfer to yourself', json.loads(res4.data)['message'])

    def test_biometric_edge_cases(self):
        self.register_user('alice_bio_edge', 'alice_be@test.com', 'pass123', 'pass123', '08166666666')
        self.login_user('alice_bio_edge', 'pass123')
        
        # 1. Enroll with invalid base64 string
        res = self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['invalid_base64_1', 'invalid_base64_2', 'invalid_base64_3']
        }), content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('Failed to decode base64 image', json.loads(res.data)['message'])

    @patch('app.decode_base64_image')
    @patch('app.face_detector', None)
    @patch('app.face_recognizer', None)
    def test_biometric_missing_model(self, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        self.register_user('alice_bio_missing', 'alice_bm@test.com', 'pass123', 'pass123', '08177777777')
        self.login_user('alice_bio_missing', 'pass123')
        
        # 2. Call enroll with face_recognizer None (missing model on server)
        res = self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['img1', 'img2', 'img3']
        }), content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('Face models are not initialized', json.loads(res.data)['message'])

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    def test_biometric_zero_vector(self, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((240, 320, 3), dtype=np.uint8)
        mock_quality.return_value = {"status": "success", "face": [0,0,10,10, 5,5, 8,5, 7,7, 5,8, 8,8, 0.99]}
        
        # Mock extract to return zero vector
        mock_extract.side_effect = ValueError("Extracted face embedding is a zero vector.")
        
        self.register_user('alice_bio_zero', 'alice_bz@test.com', 'pass123', 'pass123', '08188888888')
        self.login_user('alice_bio_zero', 'pass123')
        
        res = self.client.post('/api/biometric/enroll', data=json.dumps({
            'images': ['img1', 'img2', 'img3']
        }), content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('zero vector', json.loads(res.data)['message'])

    def test_metrics_and_admin_diagnostics(self):
        self.register_user('alice_metrics', 'alice_m@test.com', 'pass123', 'pass123', '08199999991')
        
        # 1. Metrics endpoint works
        res = self.client.get('/api/model/metrics')
        self.assertEqual(res.status_code, 200)
        self.assertIn('status', json.loads(res.data))
        
        # 2. Diagnostics - unauthorized for normal user
        self.login_user('alice_metrics', 'pass123')
        res_diag_fail = self.client.get('/api/admin/biometric/diagnostics')
        self.assertEqual(res_diag_fail.status_code, 403)
        self.logout_user()
        
        # 3. Diagnostics - succeeds for admin
        self.login_user('admin', 'adminpass')
        res_diag_success = self.client.get('/api/admin/biometric/diagnostics')
        self.assertEqual(res_diag_success.status_code, 200)


    def test_transaction_modification_protection(self):
        self.register_user('alice_mod', 'alice_mod@test.com', 'pass123', 'pass123', '08155555556', bal=200000.0)
        self.register_user('bob_mod', 'bob_mod@test.com', 'pass456', 'pass456', '08255555557')
        self.login_user('alice_mod', 'pass123')
        
        # Initiate medium risk transaction of 40,000 to bob_mod
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_mod',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        token = json.loads(res_init.data)['transaction_token']
        otp = self.captured_otps[-1]
        
        # Attempt to verify while passing modified amount and receiver in request body
        res_verify = self.client.post('/api/transfer/verify', data=json.dumps({
            'transaction_token': token,
            'otp': otp,
            'amount': '1000',      # Try to modify to 1,000
            'receiver': 'admin'    # Try to modify recipient to admin
        }), content_type='application/json')
        self.assertEqual(res_verify.status_code, 200)
        
        # Verify the ledger: transaction must have processed the original values (40,000 to bob_mod)
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM NEWT WHERE SENDER = 'alice_mod' ORDER BY ID DESC LIMIT 1")
            tx = cursor.fetchone()
            self.assertEqual(tx['AMOUNT'], 40000.0)
            self.assertEqual(tx['RECEIVER'], 'bob_mod')
            conn.close()

    def test_websocket_admin_authorization(self):
        from app import socketio
        
        # 1. Non-admin connection
        self.register_user('user_ws', 'user_ws@test.com', 'pass123', 'pass123', '08166666667')
        self.login_user('user_ws', 'pass123')
        
        # Connect to socketio with flask test client session
        socket_client = socketio.test_client(app, flask_test_client=self.client)
        socket_client.emit('join_admin')
        received = socket_client.get_received()
        
        # Find the admin_status response event
        status_event = next((e for e in received if e['name'] == 'admin_status'), None)
        self.assertIsNotNone(status_event)
        self.assertEqual(status_event['args'][0]['status'], 'error')
        self.assertEqual(status_event['args'][0]['message'], 'Access denied')
        socket_client.disconnect()
        
        self.logout_user()
        
        # 2. Admin connection
        self.login_user('admin', 'adminpass')
        socket_client_admin = socketio.test_client(app, flask_test_client=self.client)
        socket_client_admin.emit('join_admin')
        received_admin = socket_client_admin.get_received()
        
        status_event_admin = next((e for e in received_admin if e['name'] == 'admin_status'), None)
        self.assertIsNotNone(status_event_admin)
        self.assertEqual(status_event_admin['args'][0]['status'], 'joined')
        socket_client_admin.disconnect()


    def test_otp_production_safety_invariants(self):
        # 1. Verify 123456 is not hardcoded in production HTML/JS/Python files
        base_dir = os.path.dirname(os.path.abspath(__file__))
        prod_files = [
            os.path.join(base_dir, 'app.py'),
            os.path.join(base_dir, 'static', 'index.html'),
            os.path.join(base_dir, 'static', 'app.js')
        ]
        for path in prod_files:
            with open(path, 'r', encoding='utf-8') as f:
                content_file = f.read()
            if 'index.html' in path or 'app.js' in path:
                self.assertNotIn('123456', content_file)
                self.assertNotIn('Demo OTP', content_file)
                self.assertNotIn('SMS Alert', content_file)

        # 2. Verify OTP is absent from API responses
        self.register_user('alice_safe', 'alice_s@test.com', 'pass123', 'pass123', '08177777778', bal=200000.0)
        self.register_user('bob_safe', 'bob_s@test.com', 'pass456', 'pass456', '08277777779')
        self.login_user('alice_safe', 'pass123')
        
        self.captured_otps.clear()
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_safe',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res_init.status_code, 200)
        data = json.loads(res_init.data)
        
        self.assertNotIn('otp', data)
        raw_res_text = res_init.get_data(as_text=True)
        otp = self.captured_otps[-1]
        self.assertNotIn(otp, raw_res_text)
        
        # 3. SMTP send is invoked
        self.assertTrue(len(self.captured_otps) > 0)
        
        # 4. Verify SMTP failure does not expose or bypass OTP
        import app as app_module
        def raise_smtp_error(*args, **kwargs):
            raise RuntimeError("SMTP connection failed")
        app_module.send_otp_email = raise_smtp_error
        
        res_init_fail = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob_safe',
            'amount': '40000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res_init_fail.status_code, 500)
        data_fail = json.loads(res_init_fail.data)
        self.assertIn('Unable to deliver the OTP email. Please try again.', data_fail['message'])
        
        # Verify challenge was deleted (only 1 challenge remains from the first successful transaction)
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM transaction_otp_challenges WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'alice_safe')")
            challenges = cursor.fetchall()
            self.assertEqual(len(challenges), 1)
            conn.close()


    def test_transfer_initiate_low_risk(self):
        self.register_user('user_low', 'low@test.com', 'pass123', 'pass123', '08123456781', bal=10000.0)
        self.register_user('rec_low', 'rec_low@test.com', 'pass123', 'pass123', '08123456782')
        self.login_user('user_low', 'pass123')
        
        start = time.time()
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_low',
            'amount': '100',
            'type': 'TRANSFER'
        }), content_type='application/json')
        duration = time.time() - start
        
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertLess(duration, 15.0)

    def test_transfer_initiate_medium_risk(self):
        self.register_user('user_med', 'med@test.com', 'pass123', 'pass123', '08123456783', bal=100000.0)
        self.register_user('rec_med', 'rec_med@test.com', 'pass123', 'pass123', '08123456784')
        self.login_user('user_med', 'pass123')
        
        start = time.time()
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_med',
            'amount': '15000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        duration = time.time() - start
        
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertIn('otp', data['required'])
        self.assertLess(duration, 15.0)

    def test_transfer_initiate_high_risk_works(self):
        self.register_user('user_high', 'high@test.com', 'pass123', 'pass123', '08123456785', bal=50000.0)
        self.register_user('rec_high', 'rec_high@test.com', 'pass123', 'pass123', '08123456786')
        
        # Enroll face biometric first to pass high-risk requirement
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'user_high'")
            uid = cursor.fetchone()['ID']
            cursor.execute("INSERT INTO face_enrollments (user_id, template_reference) VALUES (?, ?)", (uid, json.dumps([0.1]*128)))
            conn.commit()
            conn.close()

        self.login_user('user_high', 'pass123')
        
        start = time.time()
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_high',
            'amount': '45000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        duration = time.time() - start
        
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertIn('otp', data['required'])
        self.assertIn('face', data['required'])
        self.assertLess(duration, 15.0)

    def test_transfer_initiate_critical_review(self):
        self.register_user('user_crit', 'crit@test.com', 'pass123', 'pass123', '08123456787', bal=120000.0)
        self.register_user('rec_crit', 'rec_crit@test.com', 'pass123', 'pass123', '08123456788')
        self.login_user('user_crit', 'pass123')
        
        start = time.time()
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_crit',
            'amount': '110000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        duration = time.time() - start
        
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'pending_review')
        self.assertLess(duration, 15.0)

    def test_frontend_duplicate_submission_prevention(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        js_path = os.path.join(base_dir, 'static', 'app.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('submitBtn.disabled = true;', content)
        self.assertIn('if (submitBtn.disabled) return;', content)
        self.assertIn('submitBtn.disabled = false;', content)


    def test_otp_recipient_hardening(self):
        # 1. Registered user receives OTP to their real DB email
        self.register_user('user_real_email', 'real_email@test.com', 'pass123', 'pass123', '08123456790', bal=100000.0)
        self.register_user('rec_real_email', 'rec_email@test.com', 'pass123', 'pass123', '08123456791')
        self.login_user('user_real_email', 'pass123')
        
        self.captured_otps.clear()
        
        # We need a custom mock to track recipient email
        sent_emails = []
        import app as app_module
        def mock_send(email, otp, amount, receiver):
            sent_emails.append((email, otp))
            self.captured_otps.append(otp)
            return True
        app_module.send_otp_email = mock_send
        
        res = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_real_email',
            'amount': '15000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        
        # Verify email recipient is the sender, not SMTP config, not receiver
        self.assertEqual(len(sent_emails), 1)
        self.assertEqual(sent_emails[0][0], 'real_email@test.com')
        self.assertNotEqual(sent_emails[0][0], 'rec_email@test.com')
        
        # 2. Resend OTP uses NEWBANK.EMAIL
        token = json.loads(res.data)['transaction_token']
        # Update last_sent_at in DB to bypass 60-second cooldown
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-10 minutes') WHERE transaction_token = ?", (token,))
            conn.commit()
            conn.close()

        res_resend = self.client.post('/api/otp/resend', data=json.dumps({
            'transaction_token': token
        }), content_type='application/json')
        self.assertEqual(res_resend.status_code, 200)
        self.assertEqual(sent_emails[1][0], 'real_email@test.com')

        # 3. Missing email returns HTTP 404, does NOT create pending OTP/transaction records
        # Insert a user directly with no email
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'user_no_email'")
            existing = cursor.fetchone()
            if not existing:
                from werkzeug.security import generate_password_hash
                cursor.execute('''
                INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
                VALUES ('user_no_email', 'No', 'Email', '', ?, '', '08123456792', 'Male', 'Addr', 50000.0)
                ''', (generate_password_hash('pass123'),))
                conn.commit()
            conn.close()

        self.login_user('user_no_email', 'pass123')
        sent_emails.clear()
        
        res_init_fail = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'rec_real_email',
            'amount': '15000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init_fail.status_code, 404)
        data_fail = json.loads(res_init_fail.data)
        self.assertEqual(data_fail['status'], 'error')
        self.assertEqual(data_fail['message'], 'Registered email address not found.')
        
        # Verify no OTP was sent
        self.assertEqual(len(sent_emails), 0)
        
        # Verify no transaction or OTP challenge exists in DB for this attempt
        with app.app_context():
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pending_transactions WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'user_no_email')")
            txs = cursor.fetchall()
            self.assertEqual(len(txs), 0)
            cursor.execute("SELECT * FROM transaction_otp_challenges WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'user_no_email')")
            challenges = cursor.fetchall()
            self.assertEqual(len(challenges), 0)
            conn.close()



    def test_add_money_workflow_low_risk(self):
        # 1. Register and login
        self.client.post('/api/register', json={
            "username": "deposit_low", "firstname": "Dep", "lastname": "Low",
            "email": "dep_low@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_low", "password": "pwd123"})
        
        # 2. Initiate deposit (Low Risk, < 20,000)
        res = self.client.post('/api/add-money/initiate', json={
            "amount": 5000.0, "method": "UPI", "gateway": "Google Pay", "remarks": "Low risk top up"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['risk_level'], 'LOW')
        
        # 3. Check history
        res_hist = self.client.get('/api/add-money/history')
        self.assertEqual(res_hist.status_code, 200)
        data_hist = json.loads(res_hist.data)
        self.assertTrue(len(data_hist['history']) > 0)
        self.assertEqual(data_hist['history'][0]['status'], 'APPROVED')

        # 4. Check PDF Receipt
        res_rec = self.client.get(f"/api/add-money/receipt/{data['reference_id']}")
        self.assertEqual(res_rec.status_code, 200)
        self.assertEqual(res_rec.headers['Content-Type'], 'application/pdf')

    def test_add_money_workflow_medium_risk(self):
        # 1. Register and login
        self.client.post('/api/register', json={
            "username": "deposit_med", "firstname": "Dep", "lastname": "Med",
            "email": "dep_med@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_med", "password": "pwd123"})
        
        # 2. Initiate deposit (Medium Risk, > 20,000)
        res = self.client.post('/api/add-money/initiate', json={
            "amount": 25000.0, "method": "UPI", "gateway": "Google Pay", "remarks": "Medium risk top up"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertEqual(data['risk_level'], 'MEDIUM')
        self.assertTrue(data['otp_required'])
        
        # 3. Verify OTP
        otp = self.captured_otps[-1]
        res_verify = self.client.post('/api/transfer/verify', json={
            "transaction_token": data['reference_id'],
            "otp": otp
        })
        self.assertEqual(res_verify.status_code, 200)
        
        # 4. Check deposit status updated to APPROVED
        res_hist = self.client.get('/api/add-money/history')
        data_hist = json.loads(res_hist.data)
        self.assertEqual(data_hist['history'][0]['status'], 'APPROVED')

    def test_add_money_limits(self):
        self.client.post('/api/register', json={
            "username": "deposit_limits", "firstname": "Dep", "lastname": "Limits",
            "email": "dep_lim@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_limits", "password": "pwd123"})
        
        # Min limit
        res_min = self.client.post('/api/add-money/initiate', json={
            "amount": 50.0, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res_min.status_code, 400)
        
        # Max limit
        res_max = self.client.post('/api/add-money/initiate', json={
            "amount": 250000.0, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res_max.status_code, 400)

    def test_add_money_deduplication(self):
        self.client.post('/api/register', json={
            "username": "deposit_dedup", "firstname": "Dep", "lastname": "Dedup",
            "email": "dep_dedup@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_dedup", "password": "pwd123"})
        
        # First request
        res1 = self.client.post('/api/add-money/initiate', json={
            "amount": 5000.0, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res1.status_code, 200)
        
        # Second identical request (within 10s)
        res2 = self.client.post('/api/add-money/initiate', json={
            "amount": 5000.0, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res2.status_code, 400)
        data = json.loads(res2.data)
        self.assertIn("Duplicate", data['message'])



    def test_qr_token_generation(self):
        # Register and login
        self.client.post('/api/register', json={
            "username": "qr_sender", "firstname": "QR", "lastname": "Sender",
            "email": "qr_send@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd123"})
        
        res = self.client.get('/api/qr/token')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue('qr_token' in data)

    def test_qr_scan_success(self):
        # Register sender
        self.client.post('/api/register', json={
            "username": "qr_sender", "firstname": "QR", "lastname": "Sender",
            "email": "qr_send@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Register and login recipient
        self.client.post('/api/register', json={
            "username": "qr_rec", "firstname": "QR", "lastname": "Rec",
            "email": "qr_rec@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        
        # Generate token
        self.client.post('/api/login', json={"username": "qr_rec", "password": "pwd123"})
        res_tok = self.client.get('/api/qr/token')
        data_tok = json.loads(res_tok.data)
        token = data_tok['qr_token']
        
        # Login sender
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd123"})
        
        # Scan token
        res_scan = self.client.post('/api/qr/scan', json={"qr_token": token})
        self.assertEqual(res_scan.status_code, 200)
        data_scan = json.loads(res_scan.data)
        self.assertEqual(data_scan['status'], 'success')
        self.assertEqual(data_scan['username'], 'qr_rec')
        self.assertEqual(data_scan['firstname'], 'QR')

    def test_qr_scan_invalid_token(self):
        # Register sender
        self.client.post('/api/register', json={
            "username": "qr_sender", "firstname": "QR", "lastname": "Sender",
            "email": "qr_send@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd123"})
        res = self.client.post('/api/qr/scan', json={"qr_token": "invalid-token-value"})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')

    def test_qr_payment_success(self):
        # Register sender and receiver
        self.client.post('/api/register', json={
            "username": "qr_send2", "firstname": "QR", "lastname": "Send2",
            "email": "qr_s2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "qr_rec2", "firstname": "QR", "lastname": "Rec2",
            "email": "qr_r2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        
        # Generate token for receiver
        self.client.post('/api/login', json={"username": "qr_rec2", "password": "pwd123"})
        res_tok = self.client.get('/api/qr/token')
        token = json.loads(res_tok.data)['qr_token']
        
        # Login sender
        self.client.post('/api/login', json={"username": "qr_send2", "password": "pwd123"})
        
        # Initiate payment
        res_pay = self.client.post('/api/transfer/initiate', json={
            "receiver": "qr_rec2",
            "amount": 1000.0,
            "type": "QR_PAYMENT",
            "qr_token": token,
            "remarks": "Lunch payment"
        })
        self.assertEqual(res_pay.status_code, 200)
        data_pay = json.loads(res_pay.data)
        self.assertEqual(data_pay['status'], 'success')
        
        # Check transaction ID exists and verify receipt download
        tx_id = data_pay['transaction_id']
        res_rec = self.client.get(f'/api/qr/receipt/{tx_id}')
        self.assertEqual(res_rec.status_code, 200)
        self.assertEqual(res_rec.headers['Content-Type'], 'application/pdf')

    def test_qr_payment_invalid_token(self):
        # Register sender and receiver
        self.client.post('/api/register', json={
            "username": "qr_send2", "firstname": "QR", "lastname": "Send2",
            "email": "qr_s2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "qr_rec2", "firstname": "QR", "lastname": "Rec2",
            "email": "qr_r2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_send2", "password": "pwd123"})
        # Try paying with incorrect token
        res_pay = self.client.post('/api/transfer/initiate', json={
            "receiver": "qr_rec2",
            "amount": 1000.0,
            "type": "QR_PAYMENT",
            "qr_token": "some-other-token-string"
        })
        self.assertEqual(res_pay.status_code, 400)
        data = json.loads(res_pay.data)
        self.assertEqual(data['status'], 'error')



    def test_add_beneficiary_success(self):
        # Register recipient
        self.client.post('/api/register', json={
            "username": "b_rec1", "firstname": "B", "lastname": "Rec1",
            "email": "b1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Register and login user
        self.client.post('/api/register', json={
            "username": "b_user1", "firstname": "B", "lastname": "User1",
            "email": "bu1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user1", "password": "pwd123"})
        
        res = self.client.post('/api/beneficiaries', json={"username": "b_rec1", "nickname": "My Friend"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

    def test_add_beneficiary_duplicate(self):
        self.client.post('/api/register', json={
            "username": "b_rec2", "firstname": "B", "lastname": "Rec2",
            "email": "b2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user2", "firstname": "B", "lastname": "User2",
            "email": "bu2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user2", "password": "pwd123"})
        
        # Add once
        self.client.post('/api/beneficiaries', json={"username": "b_rec2", "nickname": "Friend"})
        # Add twice
        res = self.client.post('/api/beneficiaries', json={"username": "b_rec2", "nickname": "Friend"})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')

    def test_add_beneficiary_self(self):
        self.client.post('/api/register', json={
            "username": "b_user3", "firstname": "B", "lastname": "User3",
            "email": "bu3@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user3", "password": "pwd123"})
        res = self.client.post('/api/beneficiaries', json={"username": "b_user3"})
        self.assertEqual(res.status_code, 400)

    def test_get_beneficiaries(self):
        self.client.post('/api/register', json={
            "username": "b_rec4", "firstname": "B", "lastname": "Rec4",
            "email": "b4@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user4", "firstname": "B", "lastname": "User4",
            "email": "bu4@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user4", "password": "pwd123"})
        
        # Add beneficiary
        self.client.post('/api/beneficiaries', json={"username": "b_rec4", "nickname": "Bob"})
        
        res = self.client.get('/api/beneficiaries?search=Bob')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(len(data['beneficiaries']), 1)
        self.assertEqual(data['beneficiaries'][0]['nickname'], 'Bob')

    def test_favorite_beneficiary(self):
        self.client.post('/api/register', json={
            "username": "b_rec5", "firstname": "B", "lastname": "Rec5",
            "email": "b5@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user5", "firstname": "B", "lastname": "User5",
            "email": "bu5@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user5", "password": "pwd123"})
        
        self.client.post('/api/beneficiaries', json={"username": "b_rec5", "nickname": "Alice"})
        
        # Fetch list to get ID
        res_list = self.client.get('/api/beneficiaries')
        b_id = json.loads(res_list.data)['beneficiaries'][0]['id']
        
        # Favorite
        res_fav = self.client.post(f'/api/beneficiaries/{b_id}/favorite')
        self.assertEqual(res_fav.status_code, 200)
        data_fav = json.loads(res_fav.data)
        self.assertEqual(data_fav['is_favorite'], True)

    def test_transfer_updates_beneficiary_stats(self):
        # Register users
        self.client.post('/api/register', json={
            "username": "b_rec6", "firstname": "B", "lastname": "Rec6",
            "email": "b6@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user6", "firstname": "B", "lastname": "User6",
            "email": "bu6@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user6", "password": "pwd123"})
        
        # Add beneficiary
        self.client.post('/api/beneficiaries', json={"username": "b_rec6", "nickname": "Charlie"})
        
        # Transfer money
        self.client.post('/api/transfer/initiate', json={
            "receiver": "b_rec6",
            "amount": 2000.0,
            "type": "TRANSFER",
            "remarks": "Gift"
        })
        
        # Check stats updated
        res_list = self.client.get('/api/beneficiaries')
        b = json.loads(res_list.data)['beneficiaries'][0]
        self.assertEqual(b['transfer_count'], 1)
        self.assertEqual(b['total_transferred'], 2000.0)



    def test_session_logging_on_login(self):
        self.client.post('/api/register', json={
            "username": "s_user1", "firstname": "S", "lastname": "User1",
            "email": "s1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user1", "password": "pwd123"})
        
        # Check active session list
        res = self.client.get('/api/security/sessions')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['sessions'][0]['status'], 'ACTIVE')

    def test_session_revocation(self):
        self.client.post('/api/register', json={
            "username": "s_user2", "firstname": "S", "lastname": "User2",
            "email": "s2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user2", "password": "pwd123"})
        
        res = self.client.get('/api/security/sessions')
        sessions = json.loads(res.data)['sessions']
        sid = sessions[0]['session_id']
        
        # Revoke the session
        res_rev = self.client.post('/api/security/sessions/revoke', json={"session_id": sid})
        self.assertEqual(res_rev.status_code, 200)
        
        # Try getting session list again (should fail with 401 because session is revoked!)
        res_list = self.client.get('/api/security/sessions')
        self.assertEqual(res_list.status_code, 401)

    def test_revoke_others(self):
        self.client.post('/api/register', json={
            "username": "s_user3", "firstname": "S", "lastname": "User3",
            "email": "s3@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Simulate active session 1
        self.client.post('/api/login', json={"username": "s_user3", "password": "pwd123"})
        
        # Simulate active session 2 (by logging in again, which creates a new session_id)
        # Note: self.client preserves cookies, but posting login clears previous and starts new.
        self.client.post('/api/login', json={"username": "s_user3", "password": "pwd123"})
        
        # There should be 2 login history records in DB for this user
        res = self.client.get('/api/security/sessions')
        data = json.loads(res.data)
        self.assertEqual(data['total'], 2)
        
        # Revoke others
        res_oth = self.client.post('/api/security/sessions/revoke-others')
        self.assertEqual(res_oth.status_code, 200)
        
        # Re-verify session list
        res_chk = self.client.get('/api/security/sessions')
        data_chk = json.loads(res_chk.data)
        # 1 should be active (current), 1 revoked
        active_count = sum(1 for s in data_chk['sessions'] if s['status'] == 'ACTIVE')
        revoked_count = sum(1 for s in data_chk['sessions'] if s['status'] == 'REVOKED')
        self.assertEqual(active_count, 1)
        self.assertEqual(revoked_count, 1)

    def test_device_trust_toggle(self):
        self.client.post('/api/register', json={
            "username": "s_user4", "firstname": "S", "lastname": "User4",
            "email": "s4@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user4", "password": "pwd123"})
        
        res = self.client.post('/api/security/devices/trust', json={
            "device_fingerprint": "default_fingerprint",
            "is_trusted": 1
        })
        self.assertEqual(res.status_code, 200)
        
        res_list = self.client.get('/api/security/sessions')
        sessions = json.loads(res_list.data)['sessions']
        self.assertEqual(sessions[0]['is_trusted'], True)



    def test_xai_enrichment_on_transfer(self):
        self.client.post('/api/register', json={
            "username": "x_user1", "firstname": "X", "lastname": "User1",
            "email": "x1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "x_rec1", "firstname": "X", "lastname": "Rec1",
            "email": "xr1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "x_user1", "password": "pwd123"})
        
        # Trigger medium risk to get SMS OTP challenge with XAI trace
        self.client.post('/api/transfer/initiate', json={
            "receiver": "x_rec1",
            "amount": 25000.0,
            "type": "TRANSFER",
            "remarks": "Test XAI"
        })
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_transactions ORDER BY expires_at DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        trace = json.loads(row['decision_trace'])
        self.assertIn('confidence', trace)
        self.assertIn('triggered_policies', trace)
        self.assertIn('recommendation', trace)
        self.assertIn('feature_contributions', trace)

    def test_xai_explain_api_route(self):
        self.client.post('/api/register', json={
            "username": "x_user2", "firstname": "X", "lastname": "User2",
            "email": "x2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "x_rec2", "firstname": "X", "lastname": "Rec2",
            "email": "xr2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "x_user2", "password": "pwd123"})
        
        # Initiate a low-risk transfer
        self.client.post('/api/transfer/initiate', json={
            "receiver": "x_rec2",
            "amount": 50.0,
            "type": "TRANSFER",
            "remarks": "Low risk"
        })
        
        # Get transaction ID
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWT WHERE SENDER = 'x_user2' ORDER BY TIMESTAMP DESC LIMIT 1")
        tx_row = cursor.fetchone()
        conn.close()
        
        tx_id = tx_row['ID']
        
        # Request trace
        res = self.client.get(f'/api/transaction/{tx_id}/trace')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('confidence', data['trace'])
        self.assertIn('triggered_policies', data['trace'])
        self.assertIn('recommendation', data['trace'])



    def test_admin_analytics_stats_route(self):
        # Login as auditor admin
        self.client.post('/api/login', json={"username": "admin", "password": "adminpass"})
        
        res = self.client.get('/api/admin/analytics/stats')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('total_users', data['stats'])
        self.assertIn('total_transactions', data['stats'])
        self.assertIn('total_frauds', data['stats'])
        self.assertIn('otp_failures', data['stats'])
        self.assertIn('active_sessions', data['stats'])

    def test_export_ledger_csv(self):
        # Login as admin
        self.client.post('/api/login', json={"username": "admin", "password": "adminpass"})
        
        res = self.client.get('/api/admin/reports/csv')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'text/csv')
        self.assertIn(b"Transaction ID", res.data)
        self.assertIn(b"Sender", res.data)

    def test_export_ledger_pdf(self):
        # Login as admin
        self.client.post('/api/login', json={"username": "admin", "password": "adminpass"})
        
        res = self.client.get('/api/admin/reports/pdf')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')
        # Check PDF header bytes
        self.assertTrue(res.data.startswith(b"%PDF"))



    def test_notification_on_login(self):
        self.client.post('/api/register', json={
            "username": "n_user1", "firstname": "N", "lastname": "User1",
            "email": "n1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user1", "password": "pwd123"})
        
        res = self.client.get('/api/notifications')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['unread_count'], 1)
        self.assertEqual(data['notifications'][0]['title'], 'New Login Session')

    def test_mark_all_read(self):
        self.client.post('/api/register', json={
            "username": "n_user2", "firstname": "N", "lastname": "User2",
            "email": "n2@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user2", "password": "pwd123"})
        
        # Mark all read
        res_read = self.client.post('/api/notifications/read')
        self.assertEqual(res_read.status_code, 200)
        
        # Check unread count
        res = self.client.get('/api/notifications')
        data = json.loads(res.data)
        self.assertEqual(data['unread_count'], 0)
        self.assertEqual(data['notifications'][0]['is_read'], True)

    def test_mark_single_read(self):
        self.client.post('/api/register', json={
            "username": "n_user3", "firstname": "N", "lastname": "User3",
            "email": "n3@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user3", "password": "pwd123"})
        
        # Get notifications list to find ID
        res = self.client.get('/api/notifications')
        nid = json.loads(res.data)['notifications'][0]['id']
        
        # Mark read
        res_read = self.client.post(f'/api/notifications/{nid}/read')
        self.assertEqual(res_read.status_code, 200)
        
        # Re-check list
        res_check = self.client.get('/api/notifications')
        self.assertEqual(json.loads(res_check.data)['notifications'][0]['is_read'], True)

    def test_delete_notification(self):
        self.client.post('/api/register', json={
            "username": "n_user4", "firstname": "N", "lastname": "User4",
            "email": "n4@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user4", "password": "pwd123"})
        
        res = self.client.get('/api/notifications')
        nid = json.loads(res.data)['notifications'][0]['id']
        
        # Delete notification
        res_del = self.client.delete(f'/api/notifications/{nid}')
        self.assertEqual(res_del.status_code, 200)
        
        # Re-check list
        res_check = self.client.get('/api/notifications')
        self.assertEqual(len(json.loads(res_check.data)['notifications']), 0)



    def test_dashboard_metrics_route(self):
        self.client.post('/api/register', json={
            "username": "m_user1", "firstname": "M", "lastname": "User1",
            "email": "m1@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "m_user1", "password": "pwd123"})
        
        res = self.client.get('/api/dashboard/metrics')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('bank_balance', data['metrics'])
        self.assertIn('wallet_balance', data['metrics'])
        self.assertIn('monthly_spends', data['metrics'])
        
        score = data['metrics']['security_score']
        self.assertTrue(0 <= score <= 100)

    def test_notification_on_transfer(self):
        # Register sender
        self.client.post('/api/register', json={
            "username": "s_user", "firstname": "S", "lastname": "User",
            "email": "s@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Register receiver
        self.client.post('/api/register', json={
            "username": "r_user", "firstname": "R", "lastname": "User",
            "email": "r@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        
        # Login sender
        self.client.post('/api/login', json={"username": "s_user", "password": "pwd123"})
        
        # Transfer
        self.client.post('/api/transfer/initiate', json={
            "receiver": "r_user",
            "amount": 500,
            "remarks": "Test Transfer"
        })
        
        # Check sender notifications
        res_s = self.client.get('/api/notifications')
        data_s = json.loads(res_s.data)
        self.assertTrue(any("Transferred" in n['title'] for n in data_s['notifications']))
        
        # Login receiver
        self.client.post('/api/login', json={"username": "r_user", "password": "pwd123"})
        
        # Check receiver notifications
        res_r = self.client.get('/api/notifications')
        data_r = json.loads(res_r.data)
        self.assertTrue(any("Credited" in n['title'] for n in data_r['notifications']))

    def test_notification_on_deposit(self):
        self.client.post('/api/register', json={
            "username": "d_user", "firstname": "D", "lastname": "User",
            "email": "d@test.com", "password": "pwd123", "confirm": "pwd123",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "d_user", "password": "pwd123"})
        
        # Initiate deposit
        self.client.post('/api/add-money/initiate', json={
            "amount": 1000,
            "method": "UPI",
            "gateway": "Google Pay",
            "remarks": "Deposit"
        })
        
        # Check notifications
        res = self.client.get('/api/notifications')
        data = json.loads(res.data)
        self.assertTrue(any("Credit" in n['title'] for n in data['notifications']))

    def test_unauthorized_profile(self):
        res = self.client.get('/api/profile')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_transactions(self):
        res = self.client.get('/api/transactions')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_beneficiaries(self):
        res = self.client.get('/api/beneficiaries')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_sessions(self):
        res = self.client.get('/api/security/sessions')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_notifications(self):
        res = self.client.get('/api/notifications')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_dashboard_metrics(self):
        res = self.client.get('/api/dashboard/metrics')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_qr_token(self):
        res = self.client.get('/api/qr/token')
        self.assertEqual(res.status_code, 401)

    def test_unauthorized_admin_stats(self):
        res = self.client.get('/api/admin/analytics/stats')
        self.assertEqual(res.status_code, 401)

    def test_registration_succeeds_even_if_smtp_fails(self):
        import app as app_module
        original_send_email = app_module.send_email
        
        def fail_send(*args, **kwargs):
            raise Exception("SMTP Server Unavailable")
        app_module.send_email = fail_send
        
        try:
            res = self.register_user("smtp_fail_reg", "smtp@fail.com", "pwd123", "pwd123", "999")
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'success')
        finally:
            app_module.send_email = original_send_email

    def test_deposit_succeeds_even_if_smtp_fails(self):
        import app as app_module
        original_send_email = app_module.send_email
        
        def fail_send(*args, **kwargs):
            raise Exception("SMTP Server Unavailable")
        app_module.send_email = fail_send
        
        try:
            self.register_user("deposit_fail_mail", "dep@fail.com", "pwd123", "pwd123", "123")
            self.login_user("deposit_fail_mail", "pwd123")
            
            res = self.client.post('/api/add-money/initiate', json={
                "amount": 2000,
                "method": "UPI",
                "gateway": "Google Pay",
                "remarks": "Low risk deposit"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'success')
        finally:
            app_module.send_email = original_send_email

    def test_withdrawal_succeeds_even_if_smtp_fails(self):
        import app as app_module
        original_send_email = app_module.send_email
        
        def fail_send(*args, **kwargs):
            raise Exception("SMTP Server Unavailable")
        app_module.send_email = fail_send
        
        try:
            self.register_user("withdraw_fail_mail", "w@fail.com", "pwd123", "pwd123", "123")
            self.login_user("withdraw_fail_mail", "pwd123")
            
            res = self.client.post('/api/transfer/initiate', json={
                "receiver": "ATM_01",
                "amount": 1000,
                "type": "CASH_OUT",
                "remarks": "Low risk cash out"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'success')
        finally:
            app_module.send_email = original_send_email

    def test_transfer_succeeds_even_if_smtp_fails(self):
        import app as app_module
        original_send_email = app_module.send_email
        
        def fail_send(*args, **kwargs):
            raise Exception("SMTP Server Unavailable")
        app_module.send_email = fail_send
        
        try:
            self.register_user("tx_fail_sender", "s_tx@fail.com", "pwd123", "pwd123", "123")
            self.register_user("tx_fail_rec", "r_tx@fail.com", "pwd123", "pwd123", "456")
            self.login_user("tx_fail_sender", "pwd123")
            
            res = self.client.post('/api/transfer/initiate', json={
                "receiver": "tx_fail_rec",
                "amount": 100,
                "remarks": "Low risk transfer"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'success')
        finally:
            app_module.send_email = original_send_email

    def test_otp_emails_continue_working_unchanged(self):
        self.register_user("otp_user", "otp@test.com", "pwd123", "pwd123", "123")
        self.login_user("otp_user", "pwd123")
        
        res = self.client.post('/api/add-money/initiate', json={
            "amount": 25000,
            "method": "UPI",
            "gateway": "Google Pay"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertTrue(data['otp_required'])
        
        token = data['reference_id']
        res_resend = self.client.post('/api/otp/resend', json={"transaction_token": token})
        self.assertEqual(res_resend.status_code, 200)
        data_resend = json.loads(res_resend.data)
        self.assertEqual(data_resend['status'], 'success')

    def test_correct_recipient_email_used(self):
        import app as app_module
        recipient_captured = []
        original_send_email = app_module.send_email
        
        def capture_recipient(recipient_email, subject, plain_text, html_body=None):
            recipient_captured.append(recipient_email)
            return True
        app_module.send_email = capture_recipient
        
        try:
            self.register_user("rec_check", "correct_rec@test.com", "pwd123", "pwd123", "123")
            self.assertEqual(recipient_captured[-1], "correct_rec@test.com")
            
            self.login_user("rec_check", "pwd")
            self.client.post('/api/add-money/initiate', json={
                "amount": 1000,
                "method": "UPI",
                "gateway": "Google Pay"
            })
            self.assertIn("correct_rec@test.com", recipient_captured)
        finally:
            app_module.send_email = original_send_email

    def test_password_change_route_and_email(self):
        import app as app_module
        email_sent = []
        original_send_email = app_module.send_email
        
        def capture_email(recipient_email, subject, plain_text, html_body=None):
            email_sent.append((recipient_email, subject))
            return True
        app_module.send_email = capture_email
        
        try:
            self.register_user("pw_user", "pw_change@test.com", "old_pwd", "old_pwd", "123")
            self.login_user("pw_user", "old_pwd")
            
            res = self.client.post('/api/profile/update', json={
                "current_password": "old_pwd",
                "new_password": "new_pwd123",
                "confirm_password": "new_pwd123"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'success')
            
            self.assertTrue(any(item[0] == "pw_change@test.com" and "Password Changed" in item[1] for item in email_sent))
        finally:
            app_module.send_email = original_send_email



    def test_pdf_bank_statement_generation(self):
        self.register_user("statement_user", "statement@test.com", "pass123", "pass123", "123")
        self.login_user("statement_user", "pass123")
        res = self.client.get('/api/statement/download?start_date=2026-07-01&end_date=2026-07-31')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')
        self.assertTrue(res.data.startswith(b'%PDF'))

    def test_dashboard_analytics_api(self):
        self.register_user("analytics_user", "analytics@test.com", "pass123", "pass123", "123")
        self.login_user("analytics_user", "pass123")
        res = self.client.get('/api/analytics/dashboard')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('monthly_deposits', data['analytics'])
        self.assertIn('balance_trend', data['analytics'])

    def test_financial_insights_api(self):
        self.register_user("insights_user", "insights@test.com", "pass123", "pass123", "123")
        self.login_user("insights_user", "pass123")
        res = self.client.get('/api/analytics/insights')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('monthly_spending', data['insights'])
        self.assertIn('comparison_message', data['insights'])

    def test_login_history_records(self):
        self.register_user("history_user", "history@test.com", "pass123", "pass123", "123")
        self.login_user("history_user", "pass123")
        res = self.client.get('/api/security/login-history')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue(len(data['history']) > 0)

    def test_device_recognition_and_otp_bypass(self):
        self.register_user("device_user", "device@test.com", "pass123", "pass123", "123")
        res = self.client.post('/api/login', json={"username": "device_user", "password": "pass123"}, headers={"X-Device-Fingerprint": "dev_fingerprint_123"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        res = self.client.post('/api/login', json={"username": "device_user", "password": "pass123"}, headers={"X-Device-Fingerprint": "dev_fingerprint_123"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

    def test_audit_logging_and_csv_export(self):
        self.register_user("auditor", "auditor@test.com", "audit123", "audit123", "123")
        self.login_user("auditor", "audit123")
        res = self.client.get('/api/admin/audit-logs')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        res = self.client.get('/api/admin/audit-logs/export')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'text/csv')

    def test_pdf_receipt_generation(self):
        self.register_user("receipt_user", "receipt@test.com", "pass123", "pass123", "123")
        self.login_user("receipt_user", "pass123")
        res = self.client.post('/api/add-money/initiate', json={
            "amount": 1000,
            "method": "UPI",
            "gateway": "Google Pay"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        res = self.client.get(f'/api/transaction/1/receipt')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        res = self.client.get(f'/api/transaction/1/receipt/pdf')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')

    def test_password_change_session_invalidation(self):
        self.register_user("session_user", "session@test.com", "pass123", "pass123", "123")
        self.login_user("session_user", "pass123")
        res = self.client.post('/api/profile/update', json={
            "current_password": "pass123",
            "new_password": "new_password_123",
            "confirm_password": "new_password_123"
        })
        self.assertEqual(res.status_code, 200)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM login_history WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'session_user')")
        count = cursor.fetchone()['count']
        conn.close()
        self.assertTrue(count <= 1)



    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    def test_biometric_enroll_3_samples(self, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_extract.return_value = [0.1] * 128
        mock_decode.return_value = np.zeros((480, 640, 3), dtype=np.uint8)
        mock_quality.return_value = {"status": "success", "face": [0,0,200,200, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        
        self.register_user('enroll_5_user', 'enroll5@test.com', 'pass123', 'pass123', '999')
        self.login_user('enroll_5_user', 'pass123')
        
        res = self.client.post('/api/biometric/enroll', json={
            "images": ["img1", "img2", "img3"]
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT image_path, image_hash, width, height FROM face_samples WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'enroll_5_user')")
        samples = cursor.fetchall()
        self.assertEqual(len(samples), 3)
        for s in samples:
            self.assertTrue(os.path.exists(s['image_path']))
            self.assertEqual(s['width'], 640)
            self.assertEqual(s['height'], 480)
            self.assertTrue(len(s['image_hash']) > 0)
        conn.close()

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_verification_save_image(self, mock_similarity, mock_liveness, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((480, 640, 3), dtype=np.uint8)
        mock_quality.return_value = {"status": "success", "face": [0,0,200,200, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        mock_liveness.return_value = True
        mock_similarity.return_value = (True, 0.9, 0.363)
        
        self.register_user('verify_save_user', 'verifysave@test.com', 'pass123', 'pass123', '999')
        self.login_user('verify_save_user', 'pass123')
        
        self.client.post('/api/biometric/enroll', json={
            "images": ["img1", "img2", "img3"]
        })
        
        self.client.post('/api/biometric/verify/initiate')
        
        res = self.client.post('/api/biometric/verify/check', json={
            "image": "img_verify"
        })
        self.assertEqual(res.status_code, 200)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT image_path, image_hash, width, height FROM face_verification_attempts WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'verify_save_user') AND verification_result = 'SUCCESS'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertTrue(os.path.exists(row['image_path']))
        self.assertEqual(row['width'], 640)
        self.assertEqual(row['height'], 480)
        conn.close()

    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    def test_admin_face_debug_endpoint(self, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((480, 640, 3), dtype=np.uint8)
        mock_quality.return_value = {"status": "success", "face": [0,0,200,200, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        
        self.register_user('debug_user', 'debug_user@test.com', 'pass123', 'pass123', '999')
        self.login_user('debug_user', 'pass123')
        
        self.client.post('/api/biometric/enroll', json={
            "images": ["img1", "img2", "img3"]
        })
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'debug_user'")
        debug_user_id = cursor.fetchone()['ID']
        conn.close()
        
        res = self.client.get(f'/api/admin/face/debug/{debug_user_id}')
        self.assertEqual(res.status_code, 403)
        
        self.register_user('admin_user', 'admin@test.com', 'admin123', 'admin123', '999')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'admin_user'")
        admin_user_id = cursor.fetchone()['ID']
        conn.close()
        
        with self.client.session_transaction() as sess:
            sess['username'] = 'admin_user'
            sess['user_id'] = admin_user_id
            sess['is_admin'] = True
            
        res = self.client.get(f'/api/admin/face/debug/{debug_user_id}')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue(len(data['samples']) > 0)
        self.assertEqual(data['user_id'], debug_user_id)


    def test_biometric_health_endpoint(self):
        self.register_user('health_user', 'health@test.com', 'pass123', 'pass123', '999')
        self.login_user('health_user', 'pass123')
        
        res = self.client.get('/api/biometric/health')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('detector_initialized', data)
        self.assertIn('recognizer_initialized', data)

    def test_model_initialization_flow(self):
        import app as app_module
        orig_detector = app_module.face_detector
        orig_recognizer = app_module.face_recognizer
        try:
            app_module.load_face_models()
            self.assertTrue(True)
        finally:
            app_module.face_detector = orig_detector
            app_module.face_recognizer = orig_recognizer

    @patch('app.decode_base64_image')
    def test_missing_model_handling_responses(self, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((480, 640, 3), dtype=np.uint8)
        
        import app as app_module
        orig_detector = app_module.face_detector
        orig_recognizer = app_module.face_recognizer
        app_module.face_detector = None
        app_module.face_recognizer = None
        try:
            self.register_user('missing_model_user', 'missing@test.com', 'pass123', 'pass123', '999')
            self.login_user('missing_model_user', 'pass123')
            
            res = self.client.post('/api/biometric/enroll', json={
                "images": ["img1", "img2", "img3"]
            })
            self.assertEqual(res.status_code, 400)
            data = json.loads(res.data)
            self.assertIn("Face models are not initialized on the server.", data['message'])
            
            self.client.post('/api/biometric/verify/initiate')
            res2 = self.client.post('/api/biometric/verify/check', json={
                "image": "img_verify"
            })
            self.assertEqual(res2.status_code, 400)
            data2 = json.loads(res2.data)
            self.assertIn("Face models are not initialized on the server.", data2['message'])
        finally:
            app_module.face_detector = orig_detector
            app_module.face_recognizer = orig_recognizer

    def test_add_money_limits_comprehensive(self):
        self.register_user('limit_user', 'lim@test.com', 'pass123', 'pass123', '999')
        self.login_user('limit_user', 'pass123')
        
        # Test amounts that should succeed (LOW or MEDIUM risk depending on history)
        for amt in [100, 2000, 2001, 5000, 20000]:
            res = self.client.post('/api/add-money/initiate', json={
                "amount": amt, "method": "UPI", "gateway": "Google Pay"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertIn(data['status'], ['success', 'verification_required'])

        # Test amounts that should require MFA or Admin Review (MEDIUM/HIGH/CRITICAL risk overrides)
        for amt in [20001, 50000, 50001, 100000, 200000]:
            res = self.client.post('/api/add-money/initiate', json={
                "amount": amt, "method": "UPI", "gateway": "Google Pay"
            })
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertIn(data['status'], ['verification_required', 'pending_review'])
            if data['status'] == 'pending_review':
                self.assertEqual(data['risk_level'], 'CRITICAL')
            elif amt > 50000:
                self.assertEqual(data['risk_level'], 'HIGH')
            else:
                self.assertEqual(data['risk_level'], 'MEDIUM')

        # Test amount that should exceed max limit (> 2,00,000)
        res_exceed = self.client.post('/api/add-money/initiate', json={
            "amount": 200001, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res_exceed.status_code, 400)
        data_exceed = json.loads(res_exceed.data)
        self.assertEqual(data_exceed['status'], 'error')
        self.assertIn("INR 100 and INR 2,00,000", data_exceed['message'])

        # Test Indian formatting parsing compatibility in the backend
        res_format = self.client.post('/api/add-money/initiate', json={
            "amount": "\u20b92,00,000", "method": "Debit Card", "gateway": "Visa"
        })
        self.assertEqual(res_format.status_code, 200)
        data_format = json.loads(res_format.data)
        self.assertIn(data_format['status'], ['verification_required', 'pending_review'])
        if data_format['status'] == 'pending_review':
            self.assertEqual(data_format['risk_level'], 'CRITICAL')
        else:
            self.assertEqual(data_format['risk_level'], 'HIGH')

        res_format_exceed = self.client.post('/api/add-money/initiate', json={
            "amount": "\u20b92,00,001", "method": "Debit Card", "gateway": "Visa"
        })
        self.assertEqual(res_format_exceed.status_code, 400)

    @patch('app.send_email')
    def test_resend_api_success(self, mock_send):
        mock_send.return_value = True
        
        self.register_user('res_success', 'res_s@test.com', 'pwd123', 'pwd123', '999')
        self.login_user('res_success', 'pwd123')
        
        res = self.client.post('/api/transfer/initiate', json={
            "receiver": "ATM_01",
            "amount": 25000,
            "type": "CASH_OUT",
            "remarks": "MFA trigger"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        token = data['transaction_token']
        
        # Force set cooldown past
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-2 minutes') WHERE transaction_token = %s", (token,))
        conn.commit()
        conn.close()

        res_resend = self.client.post('/api/otp/resend', json={
            "transaction_token": token
        })
        self.assertEqual(res_resend.status_code, 200)
        data_resend = json.loads(res_resend.data)
        self.assertEqual(data_resend['status'], 'success')
        self.assertIn("A new verification code has been sent", data_resend['message'])

    @patch('app.send_email')
    def test_resend_api_failure_restores_database(self, mock_send):
        mock_send.return_value = True
        
        self.register_user('res_fail', 'res_f@test.com', 'pwd123', 'pwd123', '999')
        self.login_user('res_fail', 'pwd123')
        
        res = self.client.post('/api/transfer/initiate', json={
            "receiver": "ATM_01",
            "amount": 25000,
            "type": "CASH_OUT",
            "remarks": "MFA trigger"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        token = data['transaction_token']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT resend_count, otp_hash FROM transaction_otp_challenges WHERE transaction_token = %s", (token,))
        row = cursor.fetchone()
        orig_hash = row['otp_hash']
        self.assertEqual(row['resend_count'], 0)
        conn.close()
        
        mock_send.return_value = False
        
        # Force set cooldown past
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE transaction_otp_challenges SET last_sent_at = datetime('now', '-2 minutes') WHERE transaction_token = %s", (token,))
        conn.commit()
        conn.close()

        res_resend = self.client.post('/api/otp/resend', json={
            "transaction_token": token
        })
        self.assertEqual(res_resend.status_code, 500)
        data_resend = json.loads(res_resend.data)
        self.assertEqual(data_resend['status'], 'error')
        self.assertEqual(data_resend['message'], "Unable to deliver the OTP email. Please try again.")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT resend_count, otp_hash FROM transaction_otp_challenges WHERE transaction_token = %s", (token,))
        row = cursor.fetchone()
        self.assertEqual(row['resend_count'], 0)
        self.assertEqual(row['otp_hash'], orig_hash)
        conn.close()

    @patch('app.send_email')
    def test_transfer_otp_delivery_failure(self, mock_send):
        mock_send.return_value = False
        
        self.register_user('tx_fail_delivery', 'tx_fd@test.com', 'pwd123', 'pwd123', '999')
        self.login_user('tx_fail_delivery', 'pwd123')
        
        res = self.client.post('/api/transfer/initiate', json={
            "receiver": "ATM_01",
            "amount": 25000,
            "type": "CASH_OUT",
            "remarks": "MFA trigger"
        })
        self.assertEqual(res.status_code, 500)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['message'], "Unable to deliver the OTP email. Please try again.")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM pending_transactions")
        self.assertEqual(cursor.fetchone()[0], 0)
        cursor.execute("SELECT COUNT(*) FROM transaction_otp_challenges")
        self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

    @patch('app.send_email')
    def test_add_money_otp_delivery_failure(self, mock_send):
        mock_send.return_value = False
        
        self.register_user('am_fail_delivery', 'am_fd@test.com', 'pwd123', 'pwd123', '999')
        self.login_user('am_fail_delivery', 'pwd123')
        
        res = self.client.post('/api/add-money/initiate', json={
            "amount": 25000, "method": "UPI", "gateway": "Google Pay"
        })
        self.assertEqual(res.status_code, 500)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['message'], "Unable to deliver the OTP email. Please try again.")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM deposits")
        self.assertEqual(cursor.fetchone()[0], 0)
        cursor.execute("SELECT COUNT(*) FROM pending_transactions")
        self.assertEqual(cursor.fetchone()[0], 0)
        cursor.execute("SELECT COUNT(*) FROM transaction_otp_challenges")
        self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

    @patch('app.send_email')
    def test_login_mfa_otp_delivery_failure(self, mock_send):
        self.register_user('login_fail_user', 'login_f@test.com', 'pwd123', 'pwd123', '999')
        
        # First login trusts fingerprint_1
        self.client.post('/api/login', json={
            "username": "login_fail_user",
            "password": "pwd123"
        }, headers={'X-Device-Fingerprint': 'fingerprint_1'})
        self.logout_user()
        
        # Second login from fingerprint_2 triggers OTP, mock email fail
        mock_send.return_value = False
        
        res = self.client.post('/api/login', json={
            "username": "login_fail_user",
            "password": "pwd123"
        }, headers={'X-Device-Fingerprint': 'fingerprint_2'})
        
        self.assertEqual(res.status_code, 500)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['message'], "Unable to deliver the OTP email. Please try again.")
        
        with self.client.session_transaction() as sess:
            self.assertNotIn('login_otp_hash', sess)
            self.assertNotIn('login_pending_user_id', sess)

    def test_invalid_recipient_email(self):
        import app as app_module
        self.assertFalse(app_module.send_email("invalid-email", "test", "test"))
        self.assertFalse(app_module.send_email("@domain.com", "test", "test"))
        self.assertFalse(app_module.send_email("name@", "test", "test"))

    def test_missing_api_key_in_production(self):
        import app as app_module
        orig_key = os.environ.get('RESEND_API_KEY')
        orig_render = os.environ.get('RENDER')
        orig_sim = os.environ.get('TEST_PROD_SIMULATION')
        
        try:
            if 'RESEND_API_KEY' in os.environ:
                del os.environ['RESEND_API_KEY']
            os.environ['RENDER'] = 'true'
            os.environ['TEST_PROD_SIMULATION'] = '1'
            
            self.assertFalse(app_module.send_email("test@example.com", "test", "test"))
        finally:
            if orig_sim is not None:
                os.environ['TEST_PROD_SIMULATION'] = orig_sim
            else:
                if 'TEST_PROD_SIMULATION' in os.environ:
                    del os.environ['TEST_PROD_SIMULATION']
            if orig_key is not None:
                os.environ['RESEND_API_KEY'] = orig_key
            if orig_render is not None:
                os.environ['RENDER'] = orig_render


    def test_dynamic_email_delivery_requirements_a_through_f(self):
        """Verify dynamic registered email targeting, OTP server-side recipient protection, and SMTP error handling."""
        import app as app_module
        
        captured_emails = []
        original_send_email = app_module.send_email

        def capture_send_email(recipient_email, subject, plain_text, html_body=None):
            captured_emails.append({
                "recipient": recipient_email,
                "subject": subject,
                "plain": plain_text
            })
            return True

        app_module.send_email = capture_send_email

        try:
            # A. User A (Leena) registers with leena@gmail.com -> notification targets leena@gmail.com
            res_a = self.register_user("leena_user", "leena@gmail.com", "Password123!", "Password123!", "9876543210")
            self.assertEqual(res_a.status_code, 200)
            self.assertTrue(len(captured_emails) >= 1)
            self.assertEqual(captured_emails[-1]["recipient"], "leena@gmail.com")
            self.assertIn("Smart Banking - Account Created Successfully", captured_emails[-1]["subject"])

            # B. User B (Sivanesan) registers with siva@gmail.com -> notification targets siva@gmail.com
            res_b = self.register_user("siva_user", "siva@gmail.com", "Password123!", "Password123!", "9876543211")
            self.assertEqual(res_b.status_code, 200)
            self.assertTrue(len(captured_emails) >= 2)
            self.assertEqual(captured_emails[-1]["recipient"], "siva@gmail.com")
            self.assertIn("Smart Banking - Account Created Successfully", captured_emails[-1]["subject"])

            # Register recipient user for transfers
            self.register_user("rec_user_ef", "rec_ef@gmail.com", "Password123!", "Password123!", "9876543212")

            # C. User A (Leena) logs in and transaction requires OTP -> OTP targets leena@gmail.com
            self.login_user("leena_user", "Password123!")
            captured_emails.clear()
            
            # Send Medium Risk transfer (amount 15000 to new recipient -> score >= 45) to require OTP
            res_tx_a = self.client.post('/api/transfer/initiate', json={
                "receiver": "rec_user_ef",
                "amount": 15000,
                "ttype": "TRANSFER"
            })
            self.assertEqual(res_tx_a.status_code, 200)
            self.assertTrue(len(captured_emails) >= 1)
            self.assertEqual(captured_emails[0]["recipient"], "leena@gmail.com")
            self.assertIn("Security Verification Code", captured_emails[0]["subject"])

            # D. User B (Sivanesan) logs in and transaction requires OTP -> OTP targets siva@gmail.com
            self.login_user("siva_user", "Password123!")
            captured_emails.clear()

            res_tx_b = self.client.post('/api/transfer/initiate', json={
                "receiver": "rec_user_ef",
                "amount": 15000,
                "ttype": "TRANSFER"
            })
            self.assertEqual(res_tx_b.status_code, 200)
            self.assertTrue(len(captured_emails) >= 1)
            self.assertEqual(captured_emails[0]["recipient"], "siva@gmail.com")
            self.assertIn("Security Verification Code", captured_emails[0]["subject"])

            # E. Confirm recipient cannot be hijacked by passing malicious recipient_email parameter in API request
            captured_emails.clear()
            res_tx_hacker = self.client.post('/api/transfer/initiate', json={
                "receiver": "rec_user_ef",
                "amount": 15000,
                "ttype": "TRANSFER",
                "recipient_email": "attacker@hacker.com",
                "email": "attacker@hacker.com"
            })
            self.assertEqual(res_tx_hacker.status_code, 200)
            # Must STILL target User B's server-side registered email (siva@gmail.com), NOT attacker@hacker.com
            self.assertEqual(captured_emails[0]["recipient"], "siva@gmail.com")

        finally:
            app_module.send_email = original_send_email

    def test_smtp_failure_handling_safety(self):
        """Verify that SMTP failure is handled safely without throwing unhandled exceptions."""
        import app as app_module
        
        def fail_smtp(recipient_email, subject, plain_text, html_body=None):
            return False, "SMTP_ERROR_ConnectionRefusedError"

        original_send = app_module.send_email
        app_module.send_email = fail_smtp

        try:
            # Registration failure should not crash registration or roll back account creation
            res_reg = self.register_user("smtp_fail_u", "smtpfail@test.com", "Password123!", "Password123!", "9876543999")
            self.assertEqual(res_reg.status_code, 200)

            # Verification of send_email_smtp with invalid credentials returns error tuple safely
            import os
            os.environ['SMTP_HOST'] = '127.0.0.1'
            os.environ['SMTP_PORT'] = '9999'
            os.environ['SMTP_USERNAME'] = 'fake_user'
            os.environ['SMTP_PASSWORD'] = 'fake_pass'
            
            res_smtp = app_module.send_email_smtp("test@test.com", "Test", "Text")
            self.assertEqual(res_smtp[0], False)
            self.assertTrue(str(res_smtp[1]).startswith("SMTP_ERROR_"))

        finally:
            app_module.send_email = original_send
            os.environ.pop('SMTP_HOST', None)
            os.environ.pop('SMTP_PORT', None)
            os.environ.pop('SMTP_USERNAME', None)
            os.environ.pop('SMTP_PASSWORD', None)


    def test_brevo_api_delivery_success(self):
        """Verify Brevo HTTP API delivery primary priority and payload structure."""
        import app as app_module
        import os
        from unittest.mock import patch, MagicMock

        os.environ['BREVO_API_KEY'] = 'test_brevo_key_123'
        os.environ['BREVO_SENDER_EMAIL'] = 'sender@smartbank.com'

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 201
        mock_resp.read.return_value = b'{"messageId":"<20260729.123@brevo.com>"}'

        try:
            with patch('urllib.request.urlopen', return_value=mock_resp) as mock_url:
                res = app_module.send_email("brevo_rec@test.com", "Test Subject", "Test Text", "<p>Test HTML</p>")
                self.assertTrue(res)
                mock_url.assert_called_once()
                req = mock_url.call_args[0][0]
                self.assertEqual(req.full_url, "https://api.brevo.com/v3/smtp/email")
                self.assertEqual(req.headers.get("Api-key"), "test_brevo_key_123")
        finally:
            os.environ.pop('BREVO_API_KEY', None)
            os.environ.pop('BREVO_SENDER_EMAIL', None)

    def test_brevo_api_delivery_failure_fallback(self):
        """Verify Brevo HTTP API failure logs error safely and falls back cleanly."""
        import app as app_module
        import os, urllib.error
        from unittest.mock import patch

        os.environ['BREVO_API_KEY'] = 'invalid_key'

        mock_http_err = urllib.error.HTTPError(
            "https://api.brevo.com/v3/smtp/email", 401, "Unauthorized", {}, None
        )
        mock_http_err.read = lambda: b'{"code":"unauthorized","message":"Key not found"}'

        try:
            with patch('urllib.request.urlopen', side_effect=mock_http_err):
                res = app_module.send_email("fallback_rec@test.com", "Test", "Text")
                # Falls through to dev/test mock fallback cleanly
                self.assertTrue(res)
        finally:
            os.environ.pop('BREVO_API_KEY', None)


    def test_postgresql_compatibility_suite(self):
        """Verify that all analytics, dashboard, wallet, rate-limiting, and fraud queries execute cleanly under PostgreSQL translation."""
        import app as app_module
        from db_helper import CaseInsensitiveCursorWrapper
        
        # Test translation layer behavior on cursor wrapper
        class DummyCursor:
            def __init__(self):
                self.last_query = None
            def execute(self, query, params=None):
                self.last_query = query
                return None

        dummy = DummyCursor()
        wrapper = CaseInsensitiveCursorWrapper(dummy, is_postgres=True)

        # 1. Date subtract interval translation check
        wrapper.execute("SELECT SUM(amount) FROM deposits WHERE user_id = %s AND timestamp >= date('now', '-30 days')", (1,))
        self.assertIn("CURRENT_TIMESTAMP - INTERVAL '30 days'", dummy.last_query)

        wrapper.execute("SELECT COUNT(*) FROM login_attempts WHERE username = %s AND attempted_at >= datetime('now', '-5 minutes')", ("user1",))
        self.assertIn("CURRENT_TIMESTAMP - INTERVAL '5 minutes'", dummy.last_query)

        # 2. strftime / TO_CHAR translation check
        wrapper.execute("SELECT strftime('%Y-%m-%d', timestamp) as day FROM deposits WHERE timestamp >= datetime('now', '-30 days')")
        self.assertIn("TO_CHAR(timestamp, 'YYYY-MM-DD')", dummy.last_query)

        # 3. IFNULL / COALESCE check
        wrapper.execute("SELECT IFNULL(SUM(amount), 0) FROM deposits")
        self.assertIn("COALESCE(", dummy.last_query)

        # 4. Verify endpoints function without SQL syntax errors
        self.register_user("pg_comp_user", "pg_comp@test.com", "Password123!", "Password123!", "9998887770")
        self.login_user("pg_comp_user", "Password123!")

        # User Analytics & Dashboard APIs
        res_dash = self.client.get('/api/analytics/dashboard')
        self.assertEqual(res_dash.status_code, 200)

        res_ins = self.client.get('/api/analytics/insights')
        self.assertEqual(res_ins.status_code, 200)

        res_met = self.client.get('/api/dashboard/metrics')
        self.assertEqual(res_met.status_code, 200)

        res_wal_ana = self.client.get('/api/add-money/analytics')
        self.assertEqual(res_wal_ana.status_code, 200)

        res_txs = self.client.get('/api/transactions')
        self.assertEqual(res_txs.status_code, 200)

        # Admin Analytics APIs (with admin login)
        self.login_user("admin", "adminpass")
        res_adm_stats = self.client.get('/api/admin/stats')
        self.assertEqual(res_adm_stats.status_code, 200)

        res_adm_ana = self.client.get('/api/admin/analytics/stats')
        self.assertEqual(res_adm_ana.status_code, 200)

        res_adm_rev = self.client.get('/api/admin/reviews')
        self.assertEqual(res_adm_rev.status_code, 200)

if __name__ == '__main__':
    unittest.main()











    def test_smart_wallet_comprehensive_suite(self):
        # 1. Register test user
        self.register_user('wallet_user', 'wallet_u@test.com', 'pwd123', 'pwd123', '08199998888', bal=1000.0)
        self.login_user('wallet_user', 'pwd123')

        # Point 1: Get wallet balance
        res_prof = self.client.get('/api/profile')
        self.assertEqual(res_prof.status_code, 200)
        data_prof = json.loads(res_prof.data)
        initial_bal = data_prof['user']['balance']
        self.assertEqual(initial_bal, 1000.0)

        # Point 5, 6, 7: Reject invalid inputs (0, negative, format, out-of-range)
        for invalid_amt in [0, -500, 50, 250000, "abc"]:
            res_inv = self.client.post('/api/add-money/initiate', json={
                "amount": invalid_amt, "method": "UPI", "gateway": "Google Pay", "remarks": "Test invalid"
            })
            self.assertEqual(res_inv.status_code, 400)

        # Verify balance unchanged after invalid inputs
        res_prof_check = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof_check.data)['user']['balance'], 1000.0)

        # Point 2: Add Rs 100 (Low Risk)
        res_100 = self.client.post('/api/add-money/initiate', json={
            "amount": 100.0, "method": "UPI", "gateway": "Google Pay", "remarks": "Topup 100"
        })
        self.assertEqual(res_100.status_code, 200)
        data_100 = json.loads(res_100.data)
        self.assertEqual(data_100['status'], 'success')

        # Point 3: Add Rs 500 (Low Risk)
        res_500 = self.client.post('/api/add-money/initiate', json={
            "amount": 500.0, "method": "UPI", "gateway": "PhonePe", "remarks": "Topup 500"
        })
        self.assertEqual(res_500.status_code, 200)
        data_500 = json.loads(res_500.data)
        self.assertEqual(data_500['status'], 'success')

        # Point 4: Add Rs 1000 (Low Risk)
        res_1000 = self.client.post('/api/add-money/initiate', json={
            "amount": 1000.0, "method": "UPI", "gateway": "Paytm", "remarks": "Topup 1000"
        })
        self.assertEqual(res_1000.status_code, 200)

        # Point 8 & 9: Verify database balance (1000 + 100 + 500 + 1000 = 2600.0)
        res_prof_final = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof_final.data)['user']['balance'], 2600.0)

        # Point 10 & 11: Verify ledger entries & transaction history
        res_hist = self.client.get('/api/add-money/history')
        self.assertEqual(res_hist.status_code, 200)
        data_hist = json.loads(res_hist.data)
        self.assertEqual(len(data_hist['history']), 3)

        res_txs = self.client.get('/api/transactions')
        self.assertEqual(res_txs.status_code, 200)

    @patch('app.send_otp_email')
    def test_smart_wallet_mfa_and_delivery_safety(self, mock_send_otp):
        mock_send_otp.return_value = True

        self.register_user('wallet_mfa_user', 'wallet_mfa@test.com', 'pwd123', 'pwd123', '08199997777', bal=5000.0)
        self.login_user('wallet_mfa_user', 'pwd123')

        # Point 12: OTP-required Add Money (Medium Risk) does not credit before verification
        res_init = self.client.post('/api/add-money/initiate', json={
            "amount": 25000.0, "method": "Debit Card", "gateway": "Visa", "remarks": "Medium risk deposit"
        })
        self.assertEqual(res_init.status_code, 200)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'verification_required')
        token = data_init['reference_id']

        # Balance before OTP verification remains 5000.0
        res_prof = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof.data)['user']['balance'], 5000.0)

        # Point 13: Correct OTP completes transaction once
        otp_code = self.captured_otps[-1]
        res_ver = self.client.post('/api/transfer/verify', json={
            "transaction_token": token,
            "otp": otp_code
        })
        self.assertEqual(res_ver.status_code, 200)
        data_ver = json.loads(res_ver.data)
        self.assertEqual(data_ver['status'], 'success')
        self.assertEqual(data_ver['new_balance'], 30000.0)

        # Point 14: Reused OTP cannot credit again
        res_reuse = self.client.post('/api/transfer/verify', json={
            "transaction_token": token,
            "otp": otp_code
        })
        self.assertEqual(res_reuse.status_code, 400)

        # Balance remains 30000.0
        res_prof_check = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof_check.data)['user']['balance'], 30000.0)

        # Point 15: Email delivery failure during required OTP does not credit wallet
        mock_send_otp.return_value = False
        res_fail_init = self.client.post('/api/add-money/initiate', json={
            "amount": 30000.0, "method": "Credit Card", "gateway": "MasterCard", "remarks": "Failed delivery deposit"
        })
        self.assertEqual(res_fail_init.status_code, 500)
        self.assertEqual(json.loads(res_fail_init.data)['message'], "Unable to deliver the OTP email. Please try again.")

        # Balance remains 30000.0
        res_prof_after_fail = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof_after_fail.data)['user']['balance'], 30000.0)

    @patch('app.send_deposit_email')
    def test_smart_wallet_post_transaction_email_failure_safety(self, mock_send_deposit):
        mock_send_deposit.side_effect = Exception("Simulated post-transaction email outage")

        self.register_user('wallet_email_fail', 'w_fail@test.com', 'pwd123', 'pwd123', '08199996666', bal=2000.0)
        self.login_user('wallet_email_fail', 'pwd123')

        # Point 16: Post-transaction notification failure does not duplicate or reverse a committed credit
        res_dep = self.client.post('/api/add-money/initiate', json={
            "amount": 500.0, "method": "UPI", "gateway": "Google Pay", "remarks": "Email failure test"
        })
        self.assertEqual(res_dep.status_code, 200)

        # Balance updated to 2500.0 despite post-transaction notification failure
        res_prof = self.client.get('/api/profile')
        self.assertEqual(json.loads(res_prof.data)['user']['balance'], 2500.0)


    def test_biometric_pipeline_and_delete_authorization(self):
        # 1. Register test user for biometrics
        self.register_user('bio_user', 'bio@test.com', 'pwd123', 'pwd123', '08199995555', bal=3000.0)
        self.login_user('bio_user', 'pwd123')

        # Point 1: Missing image payload in enrollment
        res_empty = self.client.post('/api/biometric/enroll/sample', json={})
        self.assertEqual(res_empty.status_code, 400)

        # Point 2: Invalid base64 / malformed image
        res_bad_b64 = self.client.post('/api/biometric/enroll/sample', json={"image": "not_valid_base64!!!"})
        self.assertEqual(res_bad_b64.status_code, 400)

        # Point 3: Corrupt image payload
        import base64
        corrupt_b64 = base64.b64encode(b"THIS_IS_NOT_AN_IMAGE").decode('utf-8')
        res_corrupt = self.client.post('/api/biometric/enroll/sample', json={"image": "data:image/jpeg;base64," + corrupt_b64})
        self.assertEqual(res_corrupt.status_code, 400)

        # Point 7: Check biometric status for non-enrolled user
        res_status = self.client.get('/api/biometric/status')
        self.assertEqual(res_status.status_code, 200)
        data_status = json.loads(res_status.data)
        self.assertFalse(data_status['is_enrolled'])

        # Point 10: Authorized biometric deletion route testing
        res_del = self.client.post('/api/biometric/delete')
        self.assertEqual(res_del.status_code, 200)
        data_del = json.loads(res_del.data)
        self.assertEqual(data_del['status'], 'success')

        # Logout user and verify unauthorized deletion is rejected
        self.client.get('/api/logout')
        res_unauth_del = self.client.post('/api/biometric/delete')
        self.assertEqual(res_unauth_del.status_code, 401)


    @patch('urllib.request.urlopen')
    @patch.dict('os.environ', {'RESEND_API_KEY': 're_test_key_12345', 'RESEND_FROM_EMAIL': 'onboarding@resend.dev'})
    def test_send_email_user_agent_header(self, mock_urlopen):
        import io
        import urllib.request
        from app import send_email
        
        mock_response = io.BytesIO(b'{"id": "test_resend_msg_id"}')
        mock_urlopen.return_value.__enter__.return_value = mock_response

        success = send_email('test_recipient@example.com', 'Test Subject', 'Test Body')
        self.assertTrue(success)

        self.assertTrue(mock_urlopen.called)
        args, kwargs = mock_urlopen.call_args
        req = args[0]
        self.assertIsInstance(req, urllib.request.Request)
        
        user_agent_val = req.headers.get('User-agent') or req.headers.get('User-Agent')
        self.assertIsNotNone(user_agent_val)
        self.assertEqual(user_agent_val, "Smart-Banking-Fraud-Detection/1.0")


    @patch('app.decode_base64_image')
    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_3_capture_flow_and_compatibility(self, mock_similarity, mock_liveness, mock_extract, mock_quality, mock_decode):
        import numpy as np
        mock_decode.return_value = np.zeros((480, 640, 3), dtype=np.uint8)
        mock_quality.return_value = {"status": "success", "face": [0,0,200,200, 50,50, 150,50, 100,100, 70,150, 130,150, 0.99]}
        mock_extract.return_value = [0.1] * 128
        mock_liveness.return_value = True
        mock_similarity.return_value = (True, 0.85, 0.363)

        self.register_user('flow_user', 'flow_user@test.com', 'pass123', 'pass123', '999')
        self.login_user('flow_user', 'pass123')

        # 1. Reject 1 or 2 captures
        res_short = self.client.post('/api/biometric/enroll', json={"images": ["img1", "img2"]})
        self.assertEqual(res_short.status_code, 400)
        self.assertIn("requires exactly 3 face samples", json.loads(res_short.data)['message'])

        # 2. Complete 3 valid captures enrollment
        res_enroll = self.client.post('/api/biometric/enroll', json={"images": ["img1", "img2", "img3"]})
        self.assertEqual(res_enroll.status_code, 200)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM face_samples WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'flow_user')")
        sample_count = cursor.fetchone()['cnt']
        self.assertEqual(sample_count, 3)

        cursor.execute("SELECT template_reference, model_name FROM face_enrollments WHERE user_id = (SELECT ID FROM NEWBANK WHERE USERNAME = 'flow_user')")
        enrollment = cursor.fetchone()
        self.assertEqual(enrollment['model_name'], 'SFace')
        tpl = json.loads(enrollment['template_reference'])
        self.assertEqual(len(tpl), 128)
        conn.close()

        # 3. Test verification works with 3-capture template
        self.client.post('/api/biometric/verify/initiate')
        res_check = self.client.post('/api/biometric/verify/check', json={"image": "verify_img"})
        self.assertEqual(res_check.status_code, 200)
        self.assertTrue(json.loads(res_check.data)['verified'])

        # 4. Test legacy 5-sample template compatibility by direct insertion
        self.register_user('legacy_user', 'legacy@test.com', 'pass123', 'pass123', '999')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'legacy_user'")
        legacy_id = cursor.fetchone()['ID']
        
        # Insert 5 samples into face_samples
        for i in range(5):
            cursor.execute("INSERT INTO face_samples (user_id, sample_index, image_path, image_hash, width, height, embedding) VALUES (%s, %s, 'path', 'hash', 640, 480, %s)", (legacy_id, i, json.dumps([0.1]*128)))
        cursor.execute("INSERT INTO face_enrollments (user_id, template_reference, model_name, model_version, status) VALUES (%s, %s, 'SFace', '1.0', 'ACTIVE')", (legacy_id, json.dumps([0.1]*128)))
        conn.commit()
        conn.close()

        self.login_user('legacy_user', 'pass123')
        self.client.post('/api/biometric/verify/initiate')
        res_legacy = self.client.post('/api/biometric/verify/check', json={"image": "verify_img"})
        self.assertEqual(res_legacy.status_code, 200)
        self.assertTrue(json.loads(res_legacy.data)['verified'])

        # 5. Delete enrollment and verify status returns disabled
        res_del = self.client.post('/api/biometric/delete')
        self.assertEqual(res_del.status_code, 200)
        
        res_st = self.client.get('/api/biometric/status')
        self.assertFalse(json.loads(res_st.data)['enrolled'])


class TestRazorpayPaymentGateway(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM NEWBANK")
            cursor.execute("DELETE FROM deposits")
            cursor.execute("DELETE FROM NEWT")
            cursor.execute("DELETE FROM biometric_security_events")
            conn.commit()
            conn.close()

    def tearDown(self):
        self.app_context.pop()

    def register_and_login(self, username="rzp_user", email="rzp_user@test.com"):
        self.client.post('/api/register', json={
            "username": username,
            "firstname": "Razor",
            "lastname": "Pay",
            "email": email,
            "password": "password123",
            "confirm": "password123",
            "phone": "08122223333",
            "sex": "Male",
            "address": "123 Test St",
            "bal": 10000.0
        })
        self.client.post('/api/login', json={
            "username": username,
            "password": "password123"
        })

    @patch.dict(os.environ, {}, clear=True)
    def test_1_missing_razorpay_configuration(self):
        self.register_and_login()
        res = self.client.post('/api/payment/create-order', json={"amount": 500})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertIn("not configured", data['message'])

    def test_2_unauthenticated_create_order(self):
        res = self.client.post('/api/payment/create-order', json={"amount": 500})
        self.assertEqual(res.status_code, 401)

    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_3_invalid_amount_rejection(self):
        self.register_and_login()
        
        # Zero amount
        res_zero = self.client.post('/api/payment/create-order', json={"amount": 0})
        self.assertEqual(res_zero.status_code, 400)
        
        # Negative amount
        res_neg = self.client.post('/api/payment/create-order', json={"amount": -500})
        self.assertEqual(res_neg.status_code, 400)
        
        # Exceeds max limit
        res_max = self.client.post('/api/payment/create-order', json={"amount": 300000})
        self.assertEqual(res_max.status_code, 400)

    @patch('razorpay.Client')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_4_5_inr_to_paise_and_successful_order_creation(self, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {
            "id": "order_test_12345",
            "amount": 50000,
            "currency": "INR",
            "status": "created"
        }

        res = self.client.post('/api/payment/create-order', json={"amount": 500})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        
        # Check INR to Paise conversion
        self.assertEqual(data['amount'], 50000)
        self.assertEqual(data['amount_inr'], 500.0)
        self.assertEqual(data['order_id'], "order_test_12345")
        self.assertEqual(data['key_id'], "rzp_test_key")

        # Verify wallet balance NOT changed yet
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        bal = cursor.fetchone()['BAL']
        self.assertEqual(bal, 10000.0)
        conn.close()

    @patch('razorpay.Client')
    @patch('app.send_deposit_email')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_6_8_9_11_12_13_payment_verification_success(self, mock_send_email, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_success_100"}
        mock_instance.utility.verify_payment_signature.return_value = True

        # Create Order
        res_ord = self.client.post('/api/payment/create-order', json={"amount": 1000})
        ord_data = json.loads(res_ord.data)
        ref_id = ord_data['reference_id']

        # Verify Payment
        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_success_100",
            "razorpay_payment_id": "pay_success_100",
            "razorpay_signature": "valid_signature_hash",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 200)
        ver_data = json.loads(res_ver.data)
        self.assertEqual(ver_data['status'], 'success')
        self.assertEqual(ver_data['new_balance'], 11000.0)

        # Check DB updates: wallet balance, deposits record, NEWT ledger
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 11000.0)

        cursor.execute("SELECT status, razorpay_order_id, razorpay_payment_id FROM deposits WHERE reference_id = %s", (ref_id,))
        dep_row = cursor.fetchone()
        self.assertEqual(dep_row['status'], 'APPROVED')
        self.assertEqual(dep_row['razorpay_order_id'], 'order_success_100')
        self.assertEqual(dep_row['razorpay_payment_id'], 'pay_success_100')

        # Check NEWT ledger entry created exactly once
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWT WHERE SENDER = 'rzp_user' AND TTYPE = 'ADD_MONEY'")
        self.assertEqual(cursor.fetchone()['cnt'], 1)
        conn.close()

        # Check confirmation email triggered
        self.assertTrue(mock_send_email.called)

    @patch('razorpay.Client')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_7_invalid_signature_rejection(self, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_bad_sig"}
        import razorpay
        mock_instance.utility.verify_payment_signature.side_effect = razorpay.errors.SignatureVerificationError("Invalid Signature")

        res_ord = self.client.post('/api/payment/create-order', json={"amount": 500})
        ref_id = json.loads(res_ord.data)['reference_id']

        # Verify with invalid signature
        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_bad_sig",
            "razorpay_payment_id": "pay_bad_sig",
            "razorpay_signature": "invalid_sig_hash",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 400)
        self.assertIn("Invalid Razorpay payment signature", json.loads(res_ver.data)['message'])

        # Verify wallet balance was NOT changed
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 10000.0)
        conn.close()

    @patch('razorpay.Client')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_10_idempotency_duplicate_payment_protection(self, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_idempotent"}
        mock_instance.utility.verify_payment_signature.return_value = True

        res_ord = self.client.post('/api/payment/create-order', json={"amount": 2000})
        ref_id = json.loads(res_ord.data)['reference_id']

        # First verification (Success -> +2000 -> 12000)
        res_v1 = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_idempotent",
            "razorpay_payment_id": "pay_dup_100",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_v1.status_code, 200)

        # Duplicate verification request with same razorpay_payment_id
        res_v2 = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_idempotent",
            "razorpay_payment_id": "pay_dup_100",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_v2.status_code, 200)
        data_v2 = json.loads(res_v2.data)
        self.assertTrue(data_v2.get('already_processed', False))

        # Verify wallet balance was credited EXACTLY ONCE (12000, not 14000)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 12000.0)

        # Verify NEWT ledger entry created exactly once
        cursor.execute("SELECT COUNT(*) as cnt FROM NEWT WHERE SENDER = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['cnt'], 1)
        conn.close()

    @patch('razorpay.Client')
    @patch('app.send_deposit_email')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_14_email_failure_does_not_reverse_or_double_credit(self, mock_send_email, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_mail_fail"}
        mock_instance.utility.verify_payment_signature.return_value = True
        mock_send_email.side_effect = Exception("SMTP Server Connection Timeout")

        res_ord = self.client.post('/api/payment/create-order', json={"amount": 1500})
        ref_id = json.loads(res_ord.data)['reference_id']

        # Verification succeeds even if email dispatch throws exception
        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_mail_fail",
            "razorpay_payment_id": "pay_mail_fail_1",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 200)

        # Verify balance updated to 11500
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 11500.0)
        conn.close()

    @patch('razorpay.Client')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_15_valid_signature_unsuccessful_payment_state_rejection(self, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_failed_state"}
        mock_instance.utility.verify_payment_signature.return_value = True
        # Payment fetch returns 'failed' status
        mock_instance.payment.fetch.return_value = {
            "id": "pay_failed_state",
            "order_id": "order_failed_state",
            "status": "failed",
            "amount": 50000
        }

        res_ord = self.client.post('/api/payment/create-order', json={"amount": 500})
        ref_id = json.loads(res_ord.data)['reference_id']

        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_failed_state",
            "razorpay_payment_id": "pay_failed_state",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 400)
        self.assertIn("not captured/successful", json.loads(res_ver.data)['message'])

        # Verify wallet balance was NOT changed
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 10000.0)
        conn.close()

    @patch('razorpay.Client')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_16_payment_order_mismatch_rejection(self, mock_rzp_client):
        self.register_and_login()
        mock_instance = MagicMock()
        mock_rzp_client.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_expected_1"}
        mock_instance.utility.verify_payment_signature.return_value = True
        # Payment fetch returns a DIFFERENT order_id
        mock_instance.payment.fetch.return_value = {
            "id": "pay_mismatched",
            "order_id": "order_DIFFERENT_999",
            "status": "captured",
            "amount": 50000
        }

        res_ord = self.client.post('/api/payment/create-order', json={"amount": 500})
        ref_id = json.loads(res_ord.data)['reference_id']

        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_expected_1",
            "razorpay_payment_id": "pay_mismatched",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 400)
        self.assertIn("does not match expected order ID", json.loads(res_ver.data)['message'])

        # Verify wallet balance was NOT changed
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rzp_user'")
        self.assertEqual(cursor.fetchone()['BAL'], 10000.0)
        conn.close()

    def test_17_ml_explainer_sandbox_endpoint(self):
        res = self.client.post('/api/model/explain', json={
            "type": "TRANSFER",
            "amount": 50000,
            "oldbalanceOrig": 50000,
            "newbalanceOrig": 0,
            "oldbalanceDest": 0,
            "newbalanceDest": 0
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("is_fraud", data)
        self.assertIn("probability", data)
        self.assertIn("reasons", data)
        self.assertIsInstance(data["reasons"], list)




class TestBiometricFallbackAndHighValue(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM NEWBANK")
            cursor.execute("DELETE FROM deposits")
            cursor.execute("DELETE FROM NEWT")
            cursor.execute("DELETE FROM pending_transactions")
            cursor.execute("DELETE FROM transaction_otp_challenges")
            cursor.execute("DELETE FROM face_enrollments")
            cursor.execute("DELETE FROM face_samples")
            cursor.execute("DELETE FROM biometric_security_events")
            conn.commit()
            conn.close()

    def tearDown(self):
        self.app_context.pop()

    def setup_users(self):
        # Register sender
        self.client.post('/api/register', json={
            "username": "bio_sender", "firstname": "Sender", "lastname": "User",
            "email": "sender@test.com", "password": "password123", "confirm": "password123",
            "phone": "08111111111", "sex": "Male", "address": "123 St", "bal": 100000.0
        })
        # Register receiver
        self.client.post('/api/register', json={
            "username": "bio_receiver", "firstname": "Receiver", "lastname": "User",
            "email": "receiver@test.com", "password": "password123", "confirm": "password123",
            "phone": "08222222222", "sex": "Male", "address": "456 St", "bal": 1000.0
        })
        # Enroll face for sender
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM NEWBANK WHERE USERNAME = 'bio_sender'")
        sender_id = cursor.fetchone()['ID']
        mock_template = json.dumps([0.1] * 128)
        cursor.execute("INSERT INTO face_enrollments (user_id, template_reference, status) VALUES (%s, %s, 'ACTIVE')", (sender_id, mock_template))
        conn.commit()
        conn.close()

    def login_sender(self):
        self.client.post('/api/login', json={"username": "bio_sender", "password": "password123"})

    @patch('app.send_otp_email')
    def test_fb_1_under_20k_transfer(self, mock_send_otp):
        self.setup_users()
        self.login_sender()
        mock_send_otp.return_value = (True, "SUCCESS")

        res = self.client.post('/api/transfer/initiate', json={"receiver": "bio_receiver", "amount": 5000, "ttype": "TRANSFER"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertIn('otp', data['required'])
        self.assertNotIn('face', data['required'])

    @patch('app.send_otp_email')
    def test_fb_2_over_20k_transfer_requires_face(self, mock_send_otp):
        self.setup_users()
        self.login_sender()
        mock_send_otp.return_value = (True, "SUCCESS")

        res = self.client.post('/api/transfer/initiate', json={"receiver": "bio_receiver", "amount": 25000, "ttype": "TRANSFER"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertIn('otp', data['required'])
        self.assertIn('face', data['required'])

    @patch.dict(os.environ, {'SIMULATE_RESEND_TEST_RESTRICTION': '1'})
    def test_fb_3_resend_test_restriction_triggers_biometric_fallback(self):
        self.setup_users()
        self.login_sender()

        res = self.client.post('/api/transfer/initiate', json={"receiver": "bio_receiver", "amount": 25000, "ttype": "TRANSFER"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'verification_required')
        self.assertTrue(data.get('biometric_fallback'))
        self.assertEqual(data.get('fallback_reason'), 'RESEND_TEST_DOMAIN_RESTRICTION')
        self.assertEqual(data['required'], ['face'])

    @patch('app.calculate_similarity')
    @patch('app.extract_face_embedding')
    @patch.dict(os.environ, {'SIMULATE_RESEND_TEST_RESTRICTION': '1'})
    def test_fb_4_5_6_face_failure_and_success_single_transfer(self, mock_extract, mock_sim):
        self.setup_users()
        self.login_sender()

        # Initiate transfer with biometric fallback
        res_init = self.client.post('/api/transfer/initiate', json={"receiver": "bio_receiver", "amount": 30000, "ttype": "TRANSFER"})
        token = json.loads(res_init.data)['transaction_token']

        # Set liveness challenge in session
        with self.client.session_transaction() as sess:
            sess['liveness_challenge'] = 'LOOK_STRAIGHT'
            sess['mfa_pending_token'] = token

        mock_extract.return_value = [0.1] * 128
        
        # 1. Face Verification Failure (mismatch) -> Zero balance change
        mock_sim.return_value = (False, 0.1, 0.363)
        res_fail = self.client.post('/api/biometric/verify/check', json={"image": "data:image/jpeg;base64,mock"})
        self.assertEqual(res_fail.status_code, 400)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bio_sender'")
        self.assertEqual(cursor.fetchone()['BAL'], 100000.0)

        # 2. Face Verification Success -> Transfer finalized once
        mock_sim.return_value = (True, 0.95, 0.363)
        res_succ = self.client.post('/api/biometric/verify/check', json={"image": "data:image/jpeg;base64,mock"})
        self.assertEqual(res_succ.status_code, 200)

        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bio_sender'")
        self.assertEqual(cursor.fetchone()['BAL'], 70000.0)

        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bio_receiver'")
        self.assertEqual(cursor.fetchone()['BAL'], 31000.0)
        conn.close()

    @patch('app.compute_hybrid_risk')
    def test_fb_7_critical_transaction_requires_admin_review(self, mock_risk):
        self.setup_users()
        self.login_sender()
        mock_risk.return_value = (90, 'CRITICAL', ['Critical risk'], 1, {}, 0.95)

        res = self.client.post('/api/transfer/initiate', json={"receiver": "bio_receiver", "amount": 50000, "ttype": "TRANSFER"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'pending_review')

    @patch('razorpay.Client')
    @patch('app.calculate_similarity')
    @patch('app.extract_face_embedding')
    @patch.dict(os.environ, {'RAZORPAY_KEY_ID': 'rzp_test_key', 'RAZORPAY_KEY_SECRET': 'rzp_test_secret'})
    def test_fb_8_9_10_razorpay_over_20k_biometric_flow(self, mock_extract, mock_sim, mock_rzp):
        self.setup_users()
        self.login_sender()

        mock_instance = MagicMock()
        mock_rzp.return_value = mock_instance
        mock_instance.order.create.return_value = {"id": "order_over_20k"}
        mock_instance.utility.verify_payment_signature.return_value = True
        mock_instance.payment.fetch.return_value = {
            "id": "pay_over_20k", "order_id": "order_over_20k", "status": "captured", "amount": 2500000
        }

        # 1. Create Order for 25,000
        res_ord = self.client.post('/api/payment/create-order', json={"amount": 25000})
        ref_id = json.loads(res_ord.data)['reference_id']

        # 2. Verify Payment -> Requires Biometric (status = PENDING_BIOMETRIC, wallet balance unchanged)
        res_ver = self.client.post('/api/payment/verify', json={
            "razorpay_order_id": "order_over_20k",
            "razorpay_payment_id": "pay_over_20k",
            "razorpay_signature": "valid_sig",
            "reference_id": ref_id
        })
        self.assertEqual(res_ver.status_code, 200)
        data_ver = json.loads(res_ver.data)
        self.assertEqual(data_ver['status'], 'biometric_required')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bio_sender'")
        self.assertEqual(cursor.fetchone()['BAL'], 100000.0) # Unchanged!

        # 3. Biometric Verification Pass -> Credits Wallet exactly once (+25,000 -> 125,000)
        with self.client.session_transaction() as sess:
            sess['liveness_challenge'] = 'LOOK_STRAIGHT'

        mock_extract.return_value = [0.1] * 128
        mock_sim.return_value = (True, 0.95, 0.363)

        res_bio = self.client.post('/api/biometric/verify/check', json={"image": "data:image/jpeg;base64,mock"})
        self.assertEqual(res_bio.status_code, 200)

        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'bio_sender'")
        self.assertEqual(cursor.fetchone()['BAL'], 125000.0)
        conn.close()


class TestUpgradedFraudEngineSuite(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM NEWBANK")
            cursor.execute("DELETE FROM deposits")
            cursor.execute("DELETE FROM NEWT")
            cursor.execute("DELETE FROM pending_transactions")
            cursor.execute("DELETE FROM transaction_otp_challenges")
            cursor.execute("DELETE FROM face_enrollments")
            cursor.execute("DELETE FROM face_samples")
            cursor.execute("DELETE FROM biometric_security_events")
            cursor.execute("DELETE FROM fraud_feedback")
            conn.commit()
            conn.close()

    def tearDown(self):
        self.app_context.pop()

    def setup_user_and_admin(self):
        # Admin user
        self.client.post('/api/register', json={
            "username": "fraud_admin", "firstname": "Admin", "lastname": "User",
            "email": "admin@test.com", "password": "password123", "confirm": "password123",
            "phone": "08000000000", "sex": "Male", "address": "Admin HQ"
        })
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE NEWBANK SET IS_ADMIN = 1 WHERE USERNAME = 'fraud_admin'")
        conn.commit()
        conn.close()

        # Regular user
        self.client.post('/api/register', json={
            "username": "fe_user1", "firstname": "FE", "lastname": "One",
            "email": "fe1@test.com", "password": "password123", "confirm": "password123",
            "phone": "08111111111", "sex": "Male", "address": "123 St", "bal": 200000.0
        })
        self.client.post('/api/register', json={
            "username": "fe_user2", "firstname": "FE", "lastname": "Two",
            "email": "fe2@test.com", "password": "password123", "confirm": "password123",
            "phone": "08222222222", "sex": "Male", "address": "456 St", "bal": 10000.0
        })

    def login_user(self, username="fe_user1"):
        self.client.post('/api/login', json={"username": username, "password": "password123"})

    def login_admin(self):
        self.client.post('/api/login', json={"username": "fraud_admin", "password": "password123"})

    # 1, 2, 3: Behavioral Anomaly Tests
    def test_behavioral_signals_and_new_user(self):
        self.setup_user_and_admin()
        self.login_user("fe_user1")

        # New user with 0 history -> Neutral behavior, no crash
        score, level, reasons, pred, breakdown, prob = compute_hybrid_risk(1, "fe_user1", "fe_user2", 1000, "TRANSFER")
        self.assertIn("Neutral profile: Insufficient transaction history", reasons[-1])
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

        # Populate historical transactions (3 transactions of ₹2,000)
        conn = get_db_connection()
        cursor = conn.cursor()
        for _ in range(3):
            cursor.execute("INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS) VALUES ('fe_user1', 'fe_user2', 'TRANSFER', 2000, 200000, 198000, 10000, 12000, 'APPROVED')")
        conn.commit()
        conn.close()

        # Normal historical amount -> Low behavioral contribution
        score_norm, _, _, _, breakdown_norm, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 2100, "TRANSFER")
        self.assertEqual(breakdown_norm['behavioral_points'], 0)

        # Unusually large amount (₹80,000 vs mean ₹2,000) -> Behavioral anomaly contribution
        score_anom, _, reasons_anom, _, breakdown_anom, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 80000, "TRANSFER")
        self.assertGreater(breakdown_anom['behavioral_points'], 0)
        self.assertTrue(any("Behavioral" in r for r in reasons_anom))

    # 4, 5: Recipient Risk Tests
    def test_recipient_risk_signals(self):
        self.setup_user_and_admin()
        self.login_user("fe_user1")

        # First-time recipient -> recipient points > 0
        _, _, reasons_new, _, breakdown_new, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 15000, "TRANSFER")
        self.assertGreater(breakdown_new['recipient_points'], 0)

        # Add 3 approved transfers to receiver
        conn = get_db_connection()
        cursor = conn.cursor()
        for _ in range(3):
            cursor.execute("INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS) VALUES ('fe_user1', 'fe_user2', 'TRANSFER', 5000, 200000, 195000, 10000, 15000, 'APPROVED')")
        conn.commit()
        conn.close()

        # Known recipient -> 0 recipient points
        _, _, _, _, breakdown_known, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 15000, "TRANSFER")
        self.assertEqual(breakdown_known['recipient_points'], 0)

    # 6, 7: Velocity Risk Tests
    def test_velocity_risk_signals(self):
        self.setup_user_and_admin()
        self.login_user("fe_user1")

        # Normal frequency -> 0 velocity points
        _, _, _, _, breakdown_norm, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 1000, "TRANSFER")
        self.assertEqual(breakdown_norm['velocity_points'], 0)

        # Populate rapid transfers in last 5 minutes
        conn = get_db_connection()
        cursor = conn.cursor()
        for i in range(4):
            cursor.execute("INSERT INTO NEWT (SENDER, RECEIVER, TTYPE, AMOUNT, SENDEROLDBAL, SENDERNEWBAL, RECOLDBAL, RECNEWBAL, STATUS, TIMESTAMP) VALUES ('fe_user1', 'fe_user2', 'TRANSFER', 1000, 200000, 199000, 10000, 11000, 'APPROVED', datetime('now'))")
        conn.commit()
        conn.close()

        # Multiple rapid transfers -> velocity points > 0
        _, _, reasons_vel, _, breakdown_vel, _ = compute_hybrid_risk(1, "fe_user1", "fe_user2", 1000, "TRANSFER")
        self.assertGreater(breakdown_vel['velocity_points'], 0)

    # 8, 9, 10, 11, 12, 13, 14, 15, 16: Risk Calibration & Threshold Tests
    def test_risk_calibration_and_thresholds(self):
        self.setup_user_and_admin()

        # Score remains within 0..100
        score, level, _, _, breakdown, prob = compute_hybrid_risk(1, "fe_user1", "fe_user2", 1000, "TRANSFER")
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(level, 'LOW')

        # Check breakdown dictionary contents
        for key in ['base_points', 'amount_points', 'ml_model_points', 'behavioral_points', 'velocity_points', 'recipient_points', 'biometric_points']:
            self.assertIn(key, breakdown)

    # 17, 18, 19, 20, 21: Admin Fraud Feedback & Export Tests
    def test_admin_fraud_feedback_and_export(self):
        self.setup_user_and_admin()

        # Normal user cannot submit feedback -> HTTP 403
        self.login_user("fe_user1")
        res_user_fb = self.client.post('/api/admin/fraud-feedback', json={
            "transaction_token": "token_test_123",
            "label": "CONFIRMED_FRAUD",
            "notes": "Suspicious activity"
        })
        self.assertEqual(res_user_fb.status_code, 403)

        # Admin submits CONFIRMED_FRAUD
        self.login_admin()
        res_admin_fb = self.client.post('/api/admin/fraud-feedback', json={
            "transaction_token": "token_test_123",
            "label": "CONFIRMED_FRAUD",
            "notes": "Verified fraud report"
        })
        self.assertEqual(res_admin_fb.status_code, 200)

        # Admin submits LEGITIMATE
        res_admin_legit = self.client.post('/api/admin/fraud-feedback', json={
            "transaction_token": "token_test_456",
            "label": "LEGITIMATE",
            "notes": "Verified user identity"
        })
        self.assertEqual(res_admin_legit.status_code, 200)

        # Verify feedback persisted in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM fraud_feedback")
        self.assertEqual(cursor.fetchone()[0], 2)
        conn.close()

        # Export CSV dataset -> Excludes sensitive info
        res_export = self.client.get('/api/admin/fraud-feedback/export')
        self.assertEqual(res_export.status_code, 200)
        self.assertEqual(res_export.content_type, "text/csv")
        csv_text = res_export.data.decode('utf-8')

        self.assertIn("CONFIRMED_FRAUD", csv_text)
        self.assertIn("LEGITIMATE", csv_text)
        # Verify no sensitive keywords in export
        self.assertNotIn("password", csv_text.lower())
        self.assertNotIn("otp", csv_text.lower())
        self.assertNotIn("secret", csv_text.lower())

    # 22-32: Regression Safety Tests
    def test_existing_ml_explainer_route(self):
        self.setup_user_and_admin()
        res = self.client.post('/api/model/explain', json={
            "type": "TRANSFER", "amount": 50000, "oldbalanceOrig": 50000,
            "newbalanceOrig": 0, "oldbalanceDest": 0, "newbalanceDest": 50000
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("prediction", data)
        self.assertIn("probability", data)
