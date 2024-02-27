from flask import Flask, jsonify, request
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Function to generate RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

# Sample RSA key (replace with your real keys)
private_key, public_key = generate_rsa_key()

sample_key = {
    "kid": "abc123",
    "kty": "RSA",
    "n": public_key.decode('utf-8'),
    "e": "AQAB",  # Exponent (fixed value for RSA)
    "exp": int(time.time()) + 3600  # Set an initial expiration time (1 hour)
}

jwks = {"keys": [sample_key]}

@app.route("/jwks")
def get_jwks():
    return jsonify({"keys": [sample_key]})

@app.route("/auth", methods=["POST"])
def authenticate():
    user_id = request.args.get("user_id")

    # Generate a JWT with an expired key based on the query parameter
    if request.args.get("expired"):
        sample_key["exp"] = int(time.time()) - 3600  # Set an expired key (1 hour ago)

    # Generate and return a simple JWT (replace with real JWT generation)
    jwt_token = generate_jwt(user_id)
    return jsonify({"jwt_token": jwt_token})

def generate_jwt(user_id):
    # Implement your JWT generation logic here (e.g., using a library like PyJWT)
    # This is a simplified example, and you should use a proper JWT library in a real project
    return f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoi{user_id}.eyJleHAiOjE2MjEyNzQyMDAsImlhdCI6MTYyMTI3MDgwMH0.NdKvOaI31dUxgqyMT1XUNe0vVlsbX7HugA_B7d1vI37Y"

if __name__ == "__main__":
    app.run(debug=True, port=8080)
