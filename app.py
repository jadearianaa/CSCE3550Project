from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta, timezone
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

app = Flask(__name__)
db_file = 'totally_not_my_privateKeys.db'

def int_to_base64url(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def init_db():
    """Initialize the SQLite database with the required schema"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute(''' CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def store_key(key_pem, exp_timestamp):
    """Store a private key and its expiration in the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?,?)',
              (key_pem, exp_timestamp))
    
    kid = c.lastrowid
    conn.commit()
    conn.close()
    return kid

def get_valid_key():
    """Get a non-expired private key from the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    c.execute('SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1',
              (current_time,))
    result = c.fetchone()
    conn.close()
    return result

def get_expired_key():
    """Get an expired private key from the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    c.execute('SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1',
              (current_time,))
    result = c.fetchone()
    conn.close()
    return result

def get_valid_keys():
    """Get all non-expired private keys from the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    c.execute('SELECT kid, key, exp FROM keys WHERE exp > ?',
              (current_time,))
    results = c.fetchall()
    conn.close()
    return results

def generate_and_store_keys():
    """Generate and store both valid and expired keys"""
    # Generate expired key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    store_key(pem, exp_timestamp)

    # Generate valid key
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )

    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )
    exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours = 1)).timestamp())
    store_key(pem, exp_timestamp)

    @app.route('/auth', methods=['POST'])
    def auth():
        expired = request.args.get('expired', 'false').lower() == 'true'

        # Retreive key data based on if expired token is requested
        if expired:
            key_data = get_expired_key()
        else:
            key_data = get_valid_key()

        if not key_data:
            return jsonify({"Error: 'No suitable key found"}), 500
        
        kid, key_pem, exp = key_data

        # Load the private key
        private_key = serialization.load_pem_private_key(
            key_pem,
            password = None
        )

        # Create JWT paylod
        payload = {
            'exp': datetime.fromtimestamp(exp, tz = timezone.utc),
            'user': "username"
        }

        # Create JWT headers
        headers = {
            'kid':str(kid)
        }

    # Encode the JWT token using RS256 alg and private key
        token = jwt.encode(
            payload,
            private_key,
            algorithm = 'RS256',
            headers = headers
        )

        return jsonify({'token': token})
    
    @app.route('/.well-known/jwks.json', methods = ['GET'])
    def jwks():
        keys = []
        valid_keys = get_valid_keys()

        for kid, key_pem, exp in valid_keys:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                key_pem,
                password = None
            )
        
            # Get the public key
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()

            # Create JWKS entry
            jwks_key = {
                'kid': str(kid),
                'kty': 'RSA',
                'n': int_to_base64url(public_numbers.n),
                'e': int_to_base64url(public_numbers.e),
                'alg': 'RS256',
                'use': 'sig'
            }
            keys.append(jwks_key)

        return jsonify({'keys': keys})
    
#Initialize database and generate keys on startup
init_db()
generate_and_store_keys()

if __name__ == '__main__':
    app.run(debug = True, port = 8080)

""" 
AI Achknowledgement:
I used Open AI's ChatGPT as a tool to assist with this assignment.
I used its assistance for guidance on proper pytest fixtures and coverage testing setup, 
proper JWT token validation and verification approaches, best practices for writing assertions,
proper datetime handling, and best practices for database initialization.

I used the following prompts:
1. Tips on using pytest coverage output
2. What is a good approach to JWT token validation
3. Assert writing in python (I used an unfamilar language for the project)
4. Using the datetime function in python
5. Best ways to initialize databases using sqlite3



"""
