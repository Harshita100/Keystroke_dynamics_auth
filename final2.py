import math
import string
import re
import json
import os
from cryptography.fernet import Fernet
import hashlib
import bcrypt
import requests
from typing import Dict, List

class PasswordPolicy:
    def __init__(self,
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
            "lowercase": (not self.require_lowercase) or any(c.islower() for c in password),
            "uppercase": (not self.require_uppercase) or any(c.isupper() for c in password),
            "digits": (not self.require_digits) or any(c.isdigit() for c in password),
            "special": (not self.require_special) or any(c in string.punctuation for c in password),
            "unique_chars": len(set(password)) >= self.min_unique_chars,
            "no_forbidden": all(word.lower() not in password.lower() for word in self.forbidden_words),
            "no_repeats": not re.search(r'(.)\1{' + str(self.max_repeated_chars) + ',}', password)
        }

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

    def _format_time(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.2f} hours"
        elif seconds < 2628000:
            return f"{seconds / 86400:.2f} days"
        elif seconds < 31536000:
            return f"{seconds / 2628000:.2f} months"
        elif seconds < 31536000000:
            return f"{seconds / 31536000:.2f} years"
        else:
            return f"{seconds / 31536000000:.2f} centuries"

def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return load_key()

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        return generate_key()

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return "{}"

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_hibp(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_prefix = sha1_password[:5]
    sha1_suffix = sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{sha1_prefix}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        pwned_list = response.text.split("\r\n")
        pwned_dict = {entry.split(":")[0]: entry.split(":")[1] for entry in pwned_list}
        
        if sha1_suffix in pwned_dict:
            print(f"\u26A0 Your password has been compromised {pwned_dict[sha1_suffix]} times! Choose a different one.")
            return False
        else:
            print("\u2705 Your password is safe!")
            return True
    except Exception as e:
        print(f"Warning: Could not check password against HIBP: {e}")
        return True

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

def display_current_policy(policy):
    print("\nCurrent Password Policy:")
    print(f"Minimum Length: {policy.min_length}")
    print(f"Maximum Length: {policy.max_length}")
    print(f"Require Lowercase: {policy.require_lowercase}")
    print(f"Require Uppercase: {policy.require_uppercase}")
    print(f"Require Digits: {policy.require_digits}")
    print(f"Require Special Characters: {policy.require_special}")
    print(f"Minimum Unique Characters: {policy.min_unique_chars}")
    print(f"Maximum Repeated Characters: {policy.max_repeated_chars}")
    print(f"Forbidden Words: {', '.join(policy.forbidden_words)}")

def get_policy_changes():
    changes = {}
    print("\nEnter new values (press Enter to keep current value):")

    # Get integer inputs
    for field, prompt in [
        ('min_length', 'Minimum Length'),
        ('max_length', 'Maximum Length'),
        ('min_unique_chars', 'Minimum Unique Characters'),
        ('max_repeated_chars', 'Maximum Repeated Characters')
    ]:
        value = input(f"{prompt}: ").strip()
        if value:
            changes[field] = int(value)

    # Get boolean inputs
    for field, prompt in [
        ('require_lowercase', 'Require Lowercase (y/n)'),
        ('require_uppercase', 'Require Uppercase (y/n)'),
        ('require_digits', 'Require Digits (y/n)'),
        ('require_special', 'Require Special Characters (y/n)')
    ]:
        value = input(f"{prompt}: ").strip().lower()
        if value in ['y', 'n']:
            changes[field] = (value == 'y')

    # Get forbidden words
    forbidden = input("Forbidden Words (comma-separated): ").strip()
    if forbidden:
        changes['forbidden_words'] = [word.strip() for word in forbidden.split(',')]

    return changes

def store_password(username, password):
    if not check_hibp(password):
        return False
    
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
    
    try:
        with open("passwords.json", "w") as file:
            encrypted_data = encrypt_data(json.dumps(users), key)
            file.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Error storing password: {e}")
        return False

def main():
    policy = PasswordPolicy()
    analyzer = PasswordStrengthAnalyzer()
    
    display_current_policy(policy)
    change = input("\nDo you want to change the password policy? (y/n): ").strip().lower()
    if change == 'y':
        changes = get_policy_changes()
        for key, value in changes.items():
            setattr(policy, key, value)
        print("\nPolicy updated successfully!")
        
    username = input("Enter username: ")
    password = input("Enter password to evaluate: ").strip()
    if not password:
        print("Password cannot be empty.")
        return

    validation_results = policy.validate(password)
    meets_policy = all(validation_results.values())
    
    entropy = analyzer.calculate_entropy(password)
    
    print("\nPassword Analysis Results:")
    if not meets_policy:
        print("Status: Weak Password - Does not meet policy requirements")
        print("\nFailed Policy Requirements:")
        requirement_names = {
            "length": f"Length (must be between {policy.min_length} and {policy.max_length})",
            "lowercase": "Lowercase letter required",
            "uppercase": "Uppercase letter required",
            "digits": "Digit required",
            "special": "Special character required",
            "unique_chars": f"Minimum {policy.min_unique_chars} unique characters",
            "no_forbidden": "Contains forbidden words",
            "no_repeats": f"Too many repeated characters (max {policy.max_repeated_chars})"
        }
        for req, valid in validation_results.items():
            if not valid:
                print(f"- {requirement_names[req]}")
    else:
        print("Status: Meets all policy requirements")
        print(f"Entropy: {round(entropy, 2)}")
        
        if store_password(username, password):
            if verify_password(username, password):
                print("Password successfully stored and verified!")
            else:
                print("Error: Failed to verify stored password.")
        else:
            print("Error: Failed to store password.")

if __name__ == "__main__":
    main()