import sqlite3
import json
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import base64

app = Flask(__name__)

# Database file name as specified
DB_FILE = "totally_not_my_privateKeys.db"


def init_db():
    """Initialize the SQLite database and create the keys table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create the keys table with the exact schema from requirements
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()


def generate_and_store_keys():
    """Generate RSA key pairs and store them in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Check if keys already exist
    cursor.execute("SELECT COUNT(*) FROM keys")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return
    
    # Generate an expired key (expires now or in the past)
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize to PEM format (PKCS1)
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Expired timestamp (current time or past)
    expired_time = int(time.time()) - 1
    
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (expired_pem, expired_time)
    )
    
    # Generate a valid key (expires in 1 hour or more)
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize to PEM format
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Valid timestamp (1 hour from now)
    valid_time = int(time.time()) + 3600
    
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (valid_pem, valid_time)
    )
    
    conn.commit()
    conn.close()


def get_private_key_from_db(expired=False):
    """
    Retrieve a private key from the database.
    
    Args:
        expired: If True, get an expired key. If False, get a valid key.
    
    Returns:
        Tuple of (kid, private_key_object, expiry_timestamp)
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    if expired:
        # Get an expired key
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
            (current_time,)
        )
    else:
        # Get a valid (non-expired) key
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
            (current_time,)
        )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        kid, key_pem, exp = row
        # Deserialize the private key from PEM format
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        return kid, private_key, exp
    
    return None, None, None


def int_to_base64url(value):
    """Convert an integer to base64url encoding."""
    # Convert integer to bytes
    value_hex = format(value, 'x')
    if len(value_hex) % 2:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    # Base64url encode
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


@app.route('/auth', methods=['POST'])
def auth():
    """
    Authenticate user and return a JWT.
    
    Accepts the 'expired' query parameter to issue an expired JWT.
    Handles both HTTP Basic Auth and JSON payload authentication.
    """
    # Check for expired query parameter
    expired = request.args.get('expired') is not None
    
    # Mock authentication - accept any credentials
    # The gradebot will send either HTTP Basic Auth or JSON payload
    # We don't actually validate credentials, just return a JWT
    
    username = None
    
    # Try to get username from JSON payload
    if request.is_json:
        data = request.get_json()
        username = data.get('username', 'userABC')
    
    # Try to get username from HTTP Basic Auth
    elif request.authorization:
        username = request.authorization.username
    
    # Default username if neither provided
    if not username:
        username = 'userABC'
    
    # Get private key from database
    kid, private_key, exp = get_private_key_from_db(expired=expired)
    
    if not private_key:
        return jsonify({"error": "No suitable key found"}), 500
    
    # Create JWT payload
    payload = {
        "user": username,
        "exp": exp,
        "iat": int(time.time())
    }
    
    # Sign JWT with the private key
    # Convert private key to PEM for pyjwt
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    token = jwt.encode(
        payload,
        private_pem,
        algorithm='RS256',
        headers={"kid": str(kid)}
    )
    
    return token  # Return just the token string, not wrapped in JSON


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """
    Serve the JWKS (JSON Web Key Set) containing all valid public keys.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    # Get all valid (non-expired) keys
    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ?",
        (current_time,)
    )
    
    rows = cursor.fetchall()
    conn.close()
    
    keys = []
    
    for kid, key_pem in rows:
        # Deserialize private key
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Get public key from private key
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Create JWK (JSON Web Key)
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "alg": "RS256",
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e)
        }
        
        keys.append(jwk)
    
    return jsonify({"keys": keys})


if __name__ == '__main__':
    # Initialize database and generate keys on startup
    init_db()
    generate_and_store_keys()
    
    # Run the Flask server
    app.run(host='0.0.0.0', port=8080, debug=True)