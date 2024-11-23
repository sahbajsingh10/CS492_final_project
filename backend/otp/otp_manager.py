# backend/otp/otp_manager.py

import random
import time

class OTPManager:
    def __init__(self):
        self.otp_store = {}

    def generate_otp(self, username):
        otp = random.randint(100000, 999999)
        self.otp_store[username] = (otp, time.time())
        return otp

    def verify_otp(self, username, otp):
        stored_otp, timestamp = self.otp_store.get(username, (None, None))
        if not stored_otp or time.time() - timestamp > 300:
            return False  # OTP expired or doesn't exist
        return stored_otp == otp
