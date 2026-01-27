import os
import hashlib
import base64
import qrcode
from io import BytesIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class SecurityEngine:
    def __init__(self):
        # 1. AES Encryption Setup
        self.symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(self.symmetric_key)
        
        # 2. RSA Digital Signature Setup
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    # --- Hashing (Salted) ---
    def hash_password(self, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt, key

    def verify_password(self, stored_salt, stored_key, provided_password):
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), stored_salt, 100000)
        return new_key == stored_key

    # --- Encryption (AES) ---
    def encrypt_data(self, data):
        return self.cipher.encrypt(data.encode()).decode() # Return string for storage

    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    # --- Digital Signature ---
    def sign_data(self, data):
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    # --- QR Code Generator (For Web) ---
    def generate_qr_base64(self, data):
        qr = qrcode.QRCode()
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to memory buffer to send to HTML
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()