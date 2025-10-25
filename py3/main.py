from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time

# Server Configuration
HOST_NAME = "localhost"
SERVER_PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"

# Database Setup
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()

# Helper Functions
def serialize_key(key):
    """Convert RSA private key to PEM bytes for DB storage."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_key(pem_data):
    """Convert PEM bytes from DB back to RSA private key."""
    return serialization.load_pem_private_key(pem_data, password=None)

def int_to_base64(value):
    """Convert integer to Base64URL-encoded string (for JWKS 'n' and 'e')."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def ensure_keys_exist():
    """Generate one valid and one expired RSA key if DB is empty."""
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        print("Generating initial keys...")
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())

        # Expired key: already expired 10 seconds ago
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_key(expired_key), now - 10))
        # Valid key: expires 1 hour from now
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_key(valid_key), now + 3600))
        conn.commit()
    

# Ensure DB has the required keys
ensure_keys_exist()

# HTTP Request Handler
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self): self.method_not_allowed()
    def do_PATCH(self): self.method_not_allowed()
    def do_DELETE(self): self.method_not_allowed()
    def do_HEAD(self): self.method_not_allowed()

    def method_not_allowed(self):
        """Send 405 for unsupported HTTP methods."""
        self.send_response(405)
        self.end_headers()

    # POST /auth endpoint
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            now = int(time.time())
            expired = 'expired' in params

            # Select key depending on query
            if expired:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,))
            else:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,))

            row = cursor.fetchone()
            if not row:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No suitable key found.")
                return

            kid, pem_data, exp = row
            key = deserialize_key(pem_data)

            headers = {"kid": str(kid)}
            token_payload = {
                "user": "userABC",
                "exp": exp
            }

            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.method_not_allowed()

    # GET /.well-known/jwks.json
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            now = int(time.time())
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
            rows = cursor.fetchall()

            jwks = {"keys": []}
            for kid, pem_data, exp in rows:
                key = deserialize_key(pem_data)
                numbers = key.private_numbers().public_numbers

                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e)
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.method_not_allowed()

# Server Startup
if __name__ == "__main__":
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        webServer.server_close()
