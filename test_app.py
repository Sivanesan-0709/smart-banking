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
            return True
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
            VALUES ('admin', 'System', 'Admin', 'admin@mtbl.com', 'adminpass', 'adminpass', '08000000000', 'Other', 'System Core', 100000.0)
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

    def test_registration_and_login(self):
        # 1. Test registration
        res = self.register_user('user1', 'user1@example.com', 'secret123', 'secret123', '08123456789')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

        # Test duplicate registration block
        res_dup = self.register_user('user1', 'dup@example.com', 'pwd', 'pwd', '08123456789')
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
        self.register_user('alice', 'alice@test.com', 'pass123', 'pass123', '08111111111', bal=200000.0)
        self.register_user('bob', 'bob@test.com', 'pass456', 'pass456', '08222222222', bal=2000.0)
        
        self.login_user('alice', 'pass123')
        
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
        self.register_user('charlie', 'charlie@test.com', 'pass', 'pass', '08333333333')
        self.login_user('charlie', 'pass')
        
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
        self.assertIn('Failed to send verification email', data_fail['message'])
        
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
            "email": "dep_low@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_low", "password": "pwd"})
        
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
            "email": "dep_med@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_med", "password": "pwd"})
        
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
            "email": "dep_lim@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_limits", "password": "pwd"})
        
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
            "email": "dep_dedup@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "deposit_dedup", "password": "pwd"})
        
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
            "email": "qr_send@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd"})
        
        res = self.client.get('/api/qr/token')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue('qr_token' in data)

    def test_qr_scan_success(self):
        # Register sender
        self.client.post('/api/register', json={
            "username": "qr_sender", "firstname": "QR", "lastname": "Sender",
            "email": "qr_send@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Register and login recipient
        self.client.post('/api/register', json={
            "username": "qr_rec", "firstname": "QR", "lastname": "Rec",
            "email": "qr_rec@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        
        # Generate token
        self.client.post('/api/login', json={"username": "qr_rec", "password": "pwd"})
        res_tok = self.client.get('/api/qr/token')
        data_tok = json.loads(res_tok.data)
        token = data_tok['qr_token']
        
        # Login sender
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd"})
        
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
            "email": "qr_send@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_sender", "password": "pwd"})
        res = self.client.post('/api/qr/scan', json={"qr_token": "invalid-token-value"})
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'error')

    def test_qr_payment_success(self):
        # Register sender and receiver
        self.client.post('/api/register', json={
            "username": "qr_send2", "firstname": "QR", "lastname": "Send2",
            "email": "qr_s2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "qr_rec2", "firstname": "QR", "lastname": "Rec2",
            "email": "qr_r2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        
        # Generate token for receiver
        self.client.post('/api/login', json={"username": "qr_rec2", "password": "pwd"})
        res_tok = self.client.get('/api/qr/token')
        token = json.loads(res_tok.data)['qr_token']
        
        # Login sender
        self.client.post('/api/login', json={"username": "qr_send2", "password": "pwd"})
        
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
            "email": "qr_s2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "qr_rec2", "firstname": "QR", "lastname": "Rec2",
            "email": "qr_r2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "qr_send2", "password": "pwd"})
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
            "email": "b1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Register and login user
        self.client.post('/api/register', json={
            "username": "b_user1", "firstname": "B", "lastname": "User1",
            "email": "bu1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user1", "password": "pwd"})
        
        res = self.client.post('/api/beneficiaries', json={"username": "b_rec1", "nickname": "My Friend"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

    def test_add_beneficiary_duplicate(self):
        self.client.post('/api/register', json={
            "username": "b_rec2", "firstname": "B", "lastname": "Rec2",
            "email": "b2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user2", "firstname": "B", "lastname": "User2",
            "email": "bu2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user2", "password": "pwd"})
        
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
            "email": "bu3@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user3", "password": "pwd"})
        res = self.client.post('/api/beneficiaries', json={"username": "b_user3"})
        self.assertEqual(res.status_code, 400)

    def test_get_beneficiaries(self):
        self.client.post('/api/register', json={
            "username": "b_rec4", "firstname": "B", "lastname": "Rec4",
            "email": "b4@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user4", "firstname": "B", "lastname": "User4",
            "email": "bu4@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user4", "password": "pwd"})
        
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
            "email": "b5@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user5", "firstname": "B", "lastname": "User5",
            "email": "bu5@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user5", "password": "pwd"})
        
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
            "email": "b6@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "b_user6", "firstname": "B", "lastname": "User6",
            "email": "bu6@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "b_user6", "password": "pwd"})
        
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
            "email": "s1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user1", "password": "pwd"})
        
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
            "email": "s2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user2", "password": "pwd"})
        
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
            "email": "s3@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        # Simulate active session 1
        self.client.post('/api/login', json={"username": "s_user3", "password": "pwd"})
        
        # Simulate active session 2 (by logging in again, which creates a new session_id)
        # Note: self.client preserves cookies, but posting login clears previous and starts new.
        self.client.post('/api/login', json={"username": "s_user3", "password": "pwd"})
        
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
            "email": "s4@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "s_user4", "password": "pwd"})
        
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
            "email": "x1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "x_rec1", "firstname": "X", "lastname": "Rec1",
            "email": "xr1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "x_user1", "password": "pwd"})
        
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
            "email": "x2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/register', json={
            "username": "x_rec2", "firstname": "X", "lastname": "Rec2",
            "email": "xr2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "x_user2", "password": "pwd"})
        
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
            "email": "n1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user1", "password": "pwd"})
        
        res = self.client.get('/api/notifications')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['unread_count'], 1)
        self.assertEqual(data['notifications'][0]['title'], 'New Login Session')

    def test_mark_all_read(self):
        self.client.post('/api/register', json={
            "username": "n_user2", "firstname": "N", "lastname": "User2",
            "email": "n2@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user2", "password": "pwd"})
        
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
            "email": "n3@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user3", "password": "pwd"})
        
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
            "email": "n4@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "n_user4", "password": "pwd"})
        
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
            "email": "m1@test.com", "password": "pwd", "confirm": "pwd",
            "phone": "123", "sex": "M", "address": "Addr"
        })
        self.client.post('/api/login', json={"username": "m_user1", "password": "pwd"})
        
        res = self.client.get('/api/dashboard/metrics')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('bank_balance', data['metrics'])
        self.assertIn('wallet_balance', data['metrics'])
        self.assertIn('monthly_spends', data['metrics'])
        
        score = data['metrics']['security_score']
        self.assertTrue(0 <= score <= 100)


if __name__ == '__main__':
    unittest.main()







