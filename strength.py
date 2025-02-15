import math
import string

# Character sets used for brute-force attack simulation
CHAR_SETS = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "special": len(string.punctuation),  # Dynamically fetch special characters
}

# Function to determine the character set size used
def get_charset_size(password):
    """Determines the character set size based on the types of characters in the password."""
    size = 0
    if any(c.islower() for c in password):
        size += CHAR_SETS["lowercase"]
    if any(c.isupper() for c in password):
        size += CHAR_SETS["uppercase"]
    if any(c.isdigit() for c in password):
        size += CHAR_SETS["digits"]
    if any(c in string.punctuation for c in password):
        size += CHAR_SETS["special"]
    return size

# Function to calculate entropy
def calculate_entropy(password):
    """Calculates entropy based on password length and character diversity."""
    if not password:
        return 0

    charset_size = get_charset_size(password)
    entropy = len(password) * math.log2(charset_size)  # More realistic formula
    return entropy

# Function to convert seconds into human-readable format with ranges
def format_time(seconds):
    """Converts seconds into human-readable format with ranges (e.g., 5-6 months)."""
    if seconds >= (60 * 60 * 24 * 365 * 1000):  # More than 1000 years
        return "More than a thousand years (Extremely Secure)"

    years = seconds / (60 * 60 * 24 * 365)
    if years >= 1:
        return f"Estimated cracking time: {math.floor(years)}-{math.ceil(years)} years"

    months = seconds / (60 * 60 * 24 * 30)
    if months >= 1:
        return f"Estimated cracking time: {math.floor(months)}-{math.ceil(months)} months"

    days = seconds / (60 * 60 * 24)
    if days >= 1:
        return f"Estimated cracking time: {math.floor(days)}-{math.ceil(days)} days"

    hours = seconds / (60 * 60)
    if hours >= 1:
        return f"Estimated cracking time: {math.floor(hours)}-{math.ceil(hours)} hours"

    minutes = seconds / 60
    return f"Estimated cracking time: {math.floor(minutes)}-{math.ceil(minutes)} minutes"

# Function to estimate brute-force attack time
def estimate_cracking_time(password, guesses_per_second=10**9):
    """Estimates how long it would take to brute-force crack a password."""
    charset_size = get_charset_size(password)
    
    if charset_size == 0:
        return "N/A"

    # Use logarithm to avoid overflow in large keyspaces
    keyspace_log = len(password) * math.log2(charset_size)
    total_attempts = 2 ** keyspace_log  # Avoid direct exponentiation
    seconds = total_attempts / guesses_per_second

    return format_time(seconds)

# Function to evaluate password strength correctly
def evaluate_password(password):
    entropy = calculate_entropy(password)
    cracking_time = estimate_cracking_time(password)

    # Adjust strength classification for better accuracy
    if entropy < 40:
        strength = "Very Weak"
    elif entropy < 50:
        strength = "Weak"
    elif entropy < 70:
        strength = "Moderate"
    else:
        strength = "Strong"

    return {
        "Password": password,
        "Entropy": round(entropy, 2),
        "Strength": strength,
        "Cracking Time": cracking_time,
    }

# Get user input for password with validation
while True:
    user_password = input("Enter your password: ").strip()
    if user_password:
        break
    print("Password cannot be empty. Please enter a valid password.")

# Evaluate the entered password
result = evaluate_password(user_password)

# Display the results
print("\n🔒 Password Strength Analysis 🔒")
print(f"Password: {result['Password']}")
print(f"Entropy: {result['Entropy']}")
print(f"Strength: {result['Strength']}")
print(f"{result['Cracking Time']}")
