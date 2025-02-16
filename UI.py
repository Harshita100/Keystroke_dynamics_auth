import streamlit as st
import hashlib
import requests
import time
import socket
import ssl
import string
import re
import math
import json
import bcrypt
from cryptography.fernet import Fernet
from typing import List, Dict

# ------------------------------
# Backend Functions
# ------------------------------

# Generate a key (store this securely and reuse it)
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt data before storing
def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# Decrypt data when reading
def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Hash password using bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Check if password is compromised using Have I Been Pwned API
def check_hibp(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_prefix = sha1_password[:5]
    sha1_suffix = sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{sha1_prefix}"
    response = requests.get(url)
    
    pwned_list = response.text.split("\r\n")
    pwned_dict = {entry.split(":")[0]: entry.split(":")[1] for entry in pwned_list}
    
    if sha1_suffix in pwned_dict:
        return False, f"Your password has been compromised {pwned_dict[sha1_suffix]} times! Choose a different one."
    else:
        return True, "Your password is safe!"

# Store user credentials securely
def store_password(username, password):
    key = load_key()
    hashed_password = hash_password(password)
    
    try:
        with open("passwords.json", "r") as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data, key)
            users = json.loads(decrypted_data)
    except (FileNotFoundError, json.JSONDecodeError):
        users = {}
    
    users[username] = hashed_password
    
    with open("passwords.json", "w") as file:
        encrypted_data = encrypt_data(json.dumps(users), key)
        file.write(encrypted_data)

# Verify password
def verify_password(username, password):
    key = load_key()
    
    try:
        with open("passwords.json", "r") as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data, key)
            users = json.loads(decrypted_data)
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    
    if username in users:
        return bcrypt.checkpw(password.encode(), users[username].encode())
    
    return False

# Password Policy Validation
class PasswordPolicy:
    def _init_(self,
                 min_length: int = 8,
                 max_length: int = 128,
                 require_lowercase: bool = True,
                 require_uppercase: bool = True,
                 require_digits: bool = True,
                 require_special: bool = True,
                 min_unique_chars: int = 6,
                 forbidden_words: List[str] = None,
                 max_repeated_chars: int = 3):
        
        self.min_length = min_length
        self.max_length = max_length
        self.require_lowercase = require_lowercase
        self.require_uppercase = require_uppercase
        self.require_digits = require_digits
        self.require_special = require_special
        self.min_unique_chars = min_unique_chars
        self.forbidden_words = forbidden_words or ['password', 'admin', '123456']
        self.max_repeated_chars = max_repeated_chars

    def validate(self, password: str) -> Dict[str, bool]:
        return {
            "length": self.min_length <= len(password) <= self.max_length,
            "lowercase": (not self.require_lowercase) or (self.require_lowercase and any(c.islower() for c in password)),
            "uppercase": (not self.require_uppercase) or (self.require_uppercase and any(c.isupper() for c in password)),
            "digits": (not self.require_digits) or (self.require_digits and any(c.isdigit() for c in password)),
            "special": (not self.require_special) or (self.require_special and any(c in string.punctuation for c in password)),
            "unique_chars": len(set(password)) >= self.min_unique_chars,
            "no_forbidden": all(word.lower() not in password.lower() for word in self.forbidden_words),
            "no_repeats": not re.search(r'(.)\1{' + str(self.max_repeated_chars) + ',}', password)
        }

# Password Strength Analyzer
class PasswordStrengthAnalyzer:
    CHAR_SETS = {
        "lowercase": 26,
        "uppercase": 26,
        "digits": 10,
        "special": len(string.punctuation)
    }

    def get_charset_size(self, password: str) -> int:
        size = 0
        if any(c.islower() for c in password):
            size += self.CHAR_SETS["lowercase"]
        if any(c.isupper() for c in password):
            size += self.CHAR_SETS["uppercase"]
        if any(c.isdigit() for c in password):
            size += self.CHAR_SETS["digits"]
        if any(c in string.punctuation for c in password):
            size += self.CHAR_SETS["special"]
        return size

    def calculate_entropy(self, password: str) -> float:
        if not password:
            return 0
        charset_size = self.get_charset_size(password)
        return len(password) * math.log2(charset_size) if charset_size > 0 else 0

    def estimate_cracking_time(self, password: str) -> str:
        charset_size = self.get_charset_size(password)
        if charset_size == 0:
            return "N/A"

        password_length = len(password)
        total_attempts = charset_size ** password_length

        guesses_per_second = 1_000_000_000  # 1 billion guesses per second
        seconds_to_crack = total_attempts / guesses_per_second

        return f"Estimated cracking time: {seconds_to_crack:.2f} seconds"

# ------------------------------
# SSL Client Logic
# ------------------------------

def start_client():
    try:
        # Create a TCP/IP socket
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the server's address and port
        server_address = ('172.16.128.179', 12345)  # Replace with the server's IP address
        print(f"Connecting to {server_address[0]}:{server_address[1]}")
        client.connect(server_address)

        # Create an SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile="client-cert.pem", keyfile="client-key.pem")
        context.load_verify_locations(cafile="server-cert.pem")  # Trust the server's certificate
        context.verify_mode = ssl.CERT_REQUIRED  # Require server to present a certificate

        # Wrap the socket with SSL
        ssl_socket = context.wrap_socket(client, server_hostname="ah")  # Replace with the server's hostname
        print("SSL handshake complete")
        ssl_socket.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# ------------------------------
# User Authentication Portal
# ------------------------------

def user_authentication_portal():
    st.title("Codex Beta")
    st.markdown("---")

    # Login Form
    with st.form("login_form"):
        st.header("Login")
        username = st.text_input("Username/Email")
        password = st.text_input("Password", type="password")

        submitted = st.form_submit_button("Login")

        if submitted:
            # Validate credentials
            if verify_password(username, password):
                # Check password strength
                policy = PasswordPolicy()
                analyzer = PasswordStrengthAnalyzer()
                validation_results = policy.validate(password)
                meets_policy = all(validation_results.values())

                if not meets_policy:
                    st.error("Password does not meet policy requirements.")
                    for req, valid in validation_results.items():
                        if not valid:
                            st.write(f"- {req} requirement failed")
                else:
                    # Check password compromise
                    is_safe, message = check_hibp(password)
                    if not is_safe:
                        st.error(message)
                    else:
                        st.success("Credentials validated. Initiating SSL handshake...")

                        # Simulate SSL handshake
                        time.sleep(2)  # Simulate handshake delay
                        if start_client():
                            st.success("SSL handshake successful. You are now logged in.")
                        else:
                            st.error("SSL handshake failed. Please try again.")
            else:
                st.error("Invalid credentials. Please try again.")

# ------------------------------
# Main App Logic
# ------------------------------

def main():
    # Sidebar Navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["User Authentication Portal"])

    # Display the selected page
    if page == "User Authentication Portal":
        # First, establish SSL connection
        st.write("Establishing SSL connection...")
        if start_client():
            st.success("SSL handshake successful. Proceeding to authentication.")
            user_authentication_portal()
        else:
            st.error("SSL handshake failed. Cannot proceed to authentication.")

# Run the app
if _name_ == "_main_":
    main()