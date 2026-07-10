import unittest
import json
import os
import sqlite3
from unittest.mock import patch
from app import app, DB_PATH, MODEL_PATH

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
        pass

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

    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    def test_biometric_enrollment(self, mock_extract, mock_quality):
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

    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_verification_flow(self, mock_similarity, mock_liveness, mock_extract, mock_quality):
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

    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_biometric_failures(self, mock_similarity, mock_liveness, mock_extract, mock_quality):
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

    @patch('app.validate_face_quality')
    @patch('app.extract_face_embedding')
    @patch('app.check_liveness_challenge')
    @patch('app.calculate_similarity')
    def test_high_risk_transaction_mfa(self, mock_similarity, mock_liveness, mock_extract, mock_quality):
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
        otp = data_init['otp']

        # Verify correct OTP code
        res_verify_otp = self.client.post('/api/transfer/verify', data=json.dumps({
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
        
        self.assertEqual(res_init.status_code, 400)
        data_init = json.loads(res_init.data)
        self.assertEqual(data_init['status'], 'blocked')
        self.assertIn('CRITICAL threat indicators', data_init['message'])

        # Verify balance remains unchanged
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'alice'")
            self.assertEqual(cursor.fetchone()['BAL'], 200000.0) # Still 200k
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
        
        # Blocked transaction creates trace in DB
        res_init = self.client.post('/api/transfer/initiate', data=json.dumps({
            'receiver': 'bob',
            'amount': '180000',
            'type': 'TRANSFER'
        }), content_type='application/json')
        
        self.assertEqual(res_init.status_code, 400)
        
        # Query trace from SQLite
        with app.app_context():
            from app import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ID, DECISION_TRACE FROM NEWT ORDER BY ID DESC LIMIT 1")
            row = cursor.fetchone()
            tx_id = row['ID']
            trace_json = json.loads(row['DECISION_TRACE'])
            self.assertEqual(trace_json['risk_level'], 'CRITICAL')
            self.assertIn('auth_required', trace_json)
            conn.close()

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

if __name__ == '__main__':
    unittest.main()
