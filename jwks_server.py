from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt 
import time

app = Flask(__name__)

#Function to generate RSA key pair with kid and exp
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
    
    #Set expiration time (exp) - Example: 1 hour from now
    expiration_time = int(time.time()) + 3600
    
    return private_pem, public_pem, expiration_time

#Generate RSA key pair
private_key, public_key, expiration_time = generate_rsa_key()

#Define the function to generate JWT
def generate_jwt(user_id, private_key, expiration_time):
    #Generation of payload for the JWT
    payload = {
        "user_id": user_id,
        "exp": expiration_time  #Set expiration time
    }
    
    #Generate the JWT token using PyJWT library
    jwt_token = jwt.encode(payload, private_key, algorithm="RS256").decode("utf-8")
    
    return jwt_token

#Define the authentication endpoint
@app.route("/auth", methods=["GET", "POST"])
def authenticate():
    user_id = request.args.get("user_id")

    if request.method == "GET":
        #get token handoff
        jwt_token = generate_jwt(user_id, private_key, expiration_time)
        return jsonify({"jwt_token": jwt_token})
    elif request.method == "POST":
        #verify token
        jwt_token = request.json.get("jwt_token")  #Assuming JWT token is sent in the request body
        decoded_token = jwt.decode(jwt_token, public_key, algorithms=["RS256"])
        #Perform any necessary authentication checks using the decoded token
        
        #Return appropriate response based on authentication result
        if decoded_token.get("user_id") == user_id:            
            return jsonify({"message": "Authentication successful"})
        else:
            return jsonify({"message": "Authentication failed"}), 401

if __name__ == "__main__":
    app.run(debug=False, port=8080)
