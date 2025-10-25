import unittest
import os
import sys
import sqlite3
import json
import time
import jwt

# Add parent directory to path to import app module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, init_db, generate_and_store_keys, get_private_key_from_db, int_to_base64url

# Use a test database
TEST_DB = "test_totally_not_my_privateKeys.db"


class TestJWKSServer(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up test database before all tests."""
        # Override the DB_FILE in the app module
        import app as app_module
        app_module.DB_FILE = TEST_DB
        
        # Remove existing test database if it exists
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
    
    def setUp(self):
        """Set up test client and database before each test."""
        self.app = app.test_client()
        self.app.testing = True
        
        # Initialize database
        init_db()
        
        # Clear any existing keys
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")
        conn.commit()
        conn.close()
    
    def tearDown(self):
        """Clean up after each test."""
        if os.path.exists(TEST_DB):
            conn = sqlite3.connect(TEST_DB)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys")
            conn.commit()
            conn.close()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test database after all tests."""
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
    
    def test_init_db(self):
        """Test database initialization."""
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        
        # Check if keys table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'keys')
    
    def test_generate_and_store_keys(self):
        """Test key generation and storage."""
        generate_and_store_keys()
        
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        conn.close()
        
        # Should have at least 2 keys (one expired, one valid)
        self.assertGreaterEqual(count, 2)
    
    def test_get_valid_private_key(self):
        """Test retrieving a valid (non-expired) private key."""
        generate_and_store_keys()
        
        kid, private_key, exp = get_private_key_from_db(expired=False)
        
        self.assertIsNotNone(kid)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(exp)
        self.assertGreater(exp, int(time.time()))
    
    def test_get_expired_private_key(self):
        """Test retrieving an expired private key."""
        generate_and_store_keys()
        
        kid, private_key, exp = get_private_key_from_db(expired=True)
        
        self.assertIsNotNone(kid)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(exp)
        self.assertLessEqual(exp, int(time.time()))
    
    def test_int_to_base64url(self):
        """Test integer to base64url conversion."""
        # Test with a known value
        result = int_to_base64url(65537)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)
    
    def test_auth_endpoint_valid(self):
        """Test /auth endpoint without expired parameter."""
        generate_and_store_keys()
        
        response = self.app.post('/auth')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        
        # Verify the token can be decoded (without verification)
        token = data['token']
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn('user', decoded)
        self.assertIn('exp', decoded)
    
    def test_auth_endpoint_expired(self):
        """Test /auth endpoint with expired parameter."""
        generate_and_store_keys()
        
        response = self.app.post('/auth?expired=true')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        
        # Verify the token
        token = data['token']
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn('exp', decoded)
        # The expiry should be in the past or current time
        self.assertLessEqual(decoded['exp'], int(time.time()) + 1)
    
    def test_auth_endpoint_json_payload(self):
        """Test /auth endpoint with JSON payload."""
        generate_and_store_keys()
        
        response = self.app.post(
            '/auth',
            data=json.dumps({"username": "userABC", "password": "password123"}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
    
    def test_jwks_endpoint(self):
        """Test /.well-known/jwks.json endpoint."""
        generate_and_store_keys()
        
        response = self.app.get('/.well-known/jwks.json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)
        
        # Should have at least one valid key
        self.assertGreater(len(data['keys']), 0)
        
        # Check JWK structure
        if len(data['keys']) > 0:
            jwk = data['keys'][0]
            self.assertIn('kty', jwk)
            self.assertIn('use', jwk)
            self.assertIn('kid', jwk)
            self.assertIn('alg', jwk)
            self.assertIn('n', jwk)
            self.assertIn('e', jwk)
            self.assertEqual(jwk['kty'], 'RSA')
            self.assertEqual(jwk['alg'], 'RS256')
    
    def test_jwks_only_valid_keys(self):
        """Test that JWKS endpoint only returns valid (non-expired) keys."""
        generate_and_store_keys()
        
        response = self.app.get('/.well-known/jwks.json')
        data = json.loads(response.data)
        
        # Get all keys from database
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (int(time.time()),))
        valid_count = cursor.fetchone()[0]
        conn.close()
        
        # JWKS should only contain valid keys
        self.assertEqual(len(data['keys']), valid_count)
    
    def test_no_keys_in_database(self):
        """Test endpoints when no keys exist in database."""
        # Don't generate keys
        
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 500)
        
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data['keys']), 0)


if __name__ == '__main__':
    # Run tests with coverage
    unittest.main(verbosity=2)