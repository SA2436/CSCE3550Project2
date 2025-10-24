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

hostName = "localhost"
serverPort = 8080

DB_FILE = "totally_not_my_privateKeys.db"

# Initiate database and create table 
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()

def serialize_key(key):
    """Convert an RSA key to PEM string for DB storage"""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_key(pem_data):
    """Convert PEM string from DB back to RSA private key"""
    return serialization.load_pem_private_key(pem_data, password=None)

def ensure_keys_exist():
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        print("🔑 Generating initial keys...")
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())

        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_key(expired_key), now - 10))
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_key(valid_key), now + 3600))
        conn.commit()
        print("✅ Keys generated and stored.")

ensure_keys_exist()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            expired = 'expired' in params
            now = int(time.time())

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

        self.send_response(405)
        self.end_headers()


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

        self.send_response(405)
        self.end_headers()
conn.close()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
