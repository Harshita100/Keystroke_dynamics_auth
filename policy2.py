import math
import string
import re
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
        """Validate password against policy requirements."""
        return {
            "length": self.min_length <= len(password) <= self.max_length,
            "lowercase": not self.require_lowercase or any(c.islower() for c in password),
            "uppercase": not self.require_uppercase or any(c.isupper() for c in password),
            "digits": not self.require_digits or any(c.isdigit() for c in password),
            "special": not self.require_special or any(c in string.punctuation for c in password),
            "unique_chars": len(set(password)) >= self.min_unique_chars,
            "no_forbidden": all(word.lower() not in password.lower() for word in self.forbidden_words),
            "no_repeats": not re.search(r'(.)\1{' + str(self.max_repeated_chars) + ',}', password)
        }

class PasswordStrengthCalculator:
    def __init__(self):
        self.CHAR_SETS = {
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

    def estimate_cracking_time(self, password: str, guesses_per_second: int = 10**9) -> str:
        charset_size = self.get_charset_size(password)
        if charset_size == 0:
            return "N/A"

    # Correct calculation of total attempts
        total_attempts = charset_size ** len(password)
        seconds = total_attempts / guesses_per_second

        if seconds >= (60 * 60 * 24 * 365 * 1000):
            return "More than 1000 years"
        elif seconds >= (60 * 60 * 24 * 365):
            years = seconds / (60 * 60 * 24 * 365)
            return f"{math.floor(years)} years"
        elif seconds >= (60 * 60 * 24 * 30):
            months = seconds / (60 * 60 * 24 * 30)
            return f"{math.floor(months)} months"
        elif seconds >= (60 * 60 * 24):
            days = seconds / (60 * 60 * 24)
            return f"{math.floor(days)} days"
        elif seconds >= (60 * 60):
            hours = seconds / (60 * 60)
            return f"{math.floor(hours)} hours"
        else:
            minutes = max(1, seconds / 60)
            return f"{math.floor(minutes)} minutes"



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

def main():
    # Initialize with default policy
    policy = PasswordPolicy()
    calculator = PasswordStrengthCalculator()
    
    while True:
        display_current_policy(policy)
        
        change = input("\nDo you want to change the password policy? (y/n): ").strip().lower()
        if change == 'y':
            changes = get_policy_changes()
            for key, value in changes.items():
                setattr(policy, key, value)
            print("\nPolicy updated successfully!")
        
        password = input("\nEnter password to evaluate: ").strip()
        if not password:
            print("Password cannot be empty.")
            continue
        
        # Validate against policy
        validation_results = policy.validate(password)
        meets_policy = all(validation_results.values())
        
        # Calculate strength metrics
        entropy = calculator.calculate_entropy(password)
        cracking_time = calculator.estimate_cracking_time(password)
        
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
            print(f"Estimated Cracking Time: {cracking_time}")
        
        again = input("\nEvaluate another password? (y/n): ").strip().lower()
        print(f"User input: {again}")  # Debugging line to see what the user entered
        if again != 'y':
            break


if __name__ == "__main__":
    main()