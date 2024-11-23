# backend/app.py

from flask import Flask, request, jsonify
from encryption.aes import AESCipher
from encryption.diffie_hellman import DiffieHellman
from encryption.rsa import RSACipher
from otp.otp_manager import OTPManager
from database import db, User, Message
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///secure_chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize cryptographic modules
aes = AESCipher()
rsa = RSACipher()
otp_manager = OTPManager()

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        otp = otp_manager.generate_otp(user.username)
        # In real-world apps, send the OTP via email/SMS
        return jsonify({'message': 'OTP sent', 'otp': otp}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    content = data.get('message')
    
    # Encrypt the message with AES
    encrypted_message = aes.encrypt(content)
    
    # Save to database
    msg = Message(sender=sender, recipient=recipient, content=encrypted_message)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'message': 'Message sent'}), 200

@app.route('/messages/<username>', methods=['GET'])
def get_messages(username):
    messages = Message.query.filter_by(recipient=username).all()
    decrypted_messages = [{'sender': m.sender, 'content': aes.decrypt(m.content)} for m in messages]
    return jsonify({'messages': decrypted_messages}), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
