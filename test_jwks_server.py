from flask import Flask, jsonify, request
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt 

app = Flask(__name__)

#Function to generate RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    #Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    #Get public key
    public_key = private_key.public_key()
    
    #Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

'''
#Fix to make expiration dynamic instead of static
def refresh_sample_key():
    global sample_key
    private_key, public_key = generate_rsa_key()
    sample_key = {
        "kid": "abc123",
        "kty": "RSA",
        "n": public_key.decode('utf-8'),
        "e": "AQAB",  #Exponent (fixed value for RSA)
        "exp": int(time.time()) + 3600  #Set an initial expiration time (1 hour)
    }
'''

#Function to refresh keys
#these are still test values and must be changed for real RSA public key info
def refresh_keys():
    global private_key, public_key, sample_key
    private_key, public_key = generate_rsa_key()
    sample_key = {
        "kid": "abc123",
        "kty": "RSA",
        "n": public_key.decode('utf-8'),
        "e": "AQAB",  #Exponent (fixed value for RSA)
        "exp": int(time.time()) + 3600  #Set an initial expiration time (1 hour)
    }
refresh_keys()

'''
#Sample RSA key - Delete after testing
private_key, public_key = generate_rsa_key()
'''

#determine a better key
SECRET_KEY = "your_secret_key_here"


'''
#Removed due to static use case being replaced with dynamic
sample_key = {
    "kid": "abc123",
    "kty": "RSA",
    "n": public_key.decode('utf-8'),
    "e": "AQAB",  #Exponent (fixed value for RSA)
    "exp": int(time.time()) + 3600  #Set an initial expiration time (1 hour)
}
'''

jwks = {"keys": [sample_key]}

#refresh of the previously static sample key
refresh_key()


@app.route("/jwks")
def get_jwks():
    return jsonify({"keys": [sample_key]})

@app.route("/auth", methods=["POST"])
def authenticate():
    user_id = request.args.get("user_id")

    #Generate a JWT with an expired key based on the query parameter
    if request.args.get("expired"):
        sample_key["exp"] = int(time.time()) - 3600  #Set an expired key (1 hour ago)

    #Generate and return a JWT token
    jwt_token = generate_jwt(user_id)
    return jsonify({"jwt_token": jwt_token})

def generate_jwt(user_id):
    #Generation of payload for the JWT
    payload = {
        "user_id": user_id,
        "exp": int(time.time()) + 3600  #Set expiration time (1 hour from now)
    }
    
    #Generate the JWT token using PyJWT library
    jwt_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256").decode("utf-8")
    
    return jwt_token

if __name__ == "__main__":
    app.run(debug=True, port=8080)
