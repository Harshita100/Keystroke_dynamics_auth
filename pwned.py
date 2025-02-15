import requests  # type: ignore
import hashlib
import bcrypt    # type: ignore

def check_hibp(password):
    """Check if the password is compromised using Have I Been Pwned API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_prefix = sha1_password[:5]
    sha1_suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{sha1_prefix}"
    response = requests.get(url)

    pwned_list = response.text.split("\r\n")
    pwned_dict = {entry.split(":")[0]: entry.split(":")[1] for entry in pwned_list}

    if sha1_suffix in pwned_dict:
        print(f"⚠️ Your password has been compromised {pwned_dict[sha1_suffix]} times! Choose a different one.")
        return False
    else:
        print("✅ Your password is safe!")
        return True

def hash_password(password):
    """Hash the password securely using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Main Execution
password = input("Enter the password: ")

if check_hibp(password):
    hashed_password = hash_password(password)
    print(f"Your secure hashed password (bcrypt): {hashed_password.decode()}")
