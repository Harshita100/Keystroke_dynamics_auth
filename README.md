# Chrome Extension for Password Authentication with 2-Factor Authentication

## Overview

This Chrome Extension integrates a secure, two-factor authentication (2FA) flow that involves real-time password risk assessment and a secure SSL handshake between the user and the server. The application combines modern technologies to secure user credentials and check against password policy violations, password strength, and data breaches.

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [Features](#features)
3. [System Architecture](#system-architecture)
4. [Installation Instructions](#installation-instructions)
5. [How to Use](#how-to-use)
6. [Code Structure](#code-structure)
7. [Security Considerations](#security-considerations)
8. [Contributing](#contributing)
9. [License](#license)

---

## Tech Stack

### Frontend
- **Streamlit**: A Python library used for quickly creating interactive web applications, which serves as the user interface for authentication and result display.

### Backend
- **Python**: The programming language for implementing business logic and backend functionalities such as user authentication, password analysis, and database interaction.

### Encryption & Security
- **Fernet (cryptography module)**: Provides symmetric encryption/decryption to securely handle passwords and sensitive data using a secret key.
- **bcrypt**: A password-hashing function to securely store and compare hashed passwords.
- **ssl**: Ensures encrypted communication between the user and server by providing SSL/TLS support.
- **hashlib**: Provides hashing algorithms, particularly SHA1, for checking password security and potential breaches.
- **requests**: A library to interact with external services, including checking if passwords have been part of a data breach via the Have I Been Pwned (HIBP) API.

### Password Management
- **PasswordPolicy Class**: A custom class to define password policies (e.g., length, character requirements) and ensure compliance.
- **PasswordStrengthAnalyzer Class**: A custom-built class that evaluates password strength using entropy calculations and estimates the time required to crack the password.

### Data Storage
- **JSON**: A lightweight data format used to store encrypted user credentials and configuration data.
- **os**: Used for managing file creation, reading user credentials from encrypted files, and ensuring the correct storage of the secret encryption key.

### Utilities
- **Regular Expressions (re)**: Used for password validation, such as checking for repeated characters or other policy violations.
- **string**: Helps with handling characters like alphanumeric and special characters in passwords during validation.
- **math**: Provides functions for calculating entropy and estimating password strength.

### User Authentication
- **Manual User Authentication**: The system allows for authenticating users manually through password validation, secure storage, and enforcement of password policies.

### External API Integration
- **Have I Been Pwned (HIBP) API**: Integrates with the HIBP API to check whether a user’s password has been exposed in a known data breach.

---

## Features

- **Two-Factor Authentication (2FA)**: The extension ensures both password validation and 2FA integration, ensuring robust security.
- **Password Strength Analysis**: Calculates password entropy to determine the strength and potential vulnerabilities.
- **Password Policy Enforcement**: Ensures that user passwords adhere to defined policies (length, character types, forbidden words).
- **Breached Password Check**: Automatically checks if the password has been involved in any known data breaches by interacting with the HIBP API.
- **Secure SSL Handshake**: Ensures encrypted communication between the client (user) and the server during data transmission.
- **Real-time Password Risk Assessment**: During the password entry, the system checks the strength and compliance in real-time.
- **Password Hashing and Encryption**: Passwords are securely hashed and encrypted using bcrypt and Fernet to ensure safety in storage and transmission.

---

## System Architecture

1. **User Input**: The user enters their password through the Chrome Extension.
2. **Real-Time Risk Assessment**: The extension evaluates the password for compliance with defined password policies and strength requirements.
3. **2FA Integration**: After initial password validation, the system triggers 2FA to authenticate the user.
4. **SSL/TLS Handshake**: A secure connection is established between the user’s browser and the server using SSL/TLS encryption.
5. **Breached Password Check**: The system queries the HIBP API to ensure the password has not been part of a data breach.
6. **Encryption & Hashing**: Passwords are securely stored with bcrypt hashing and symmetric encryption using Fernet.

---

## Installation Instructions

### Prerequisites
- Python 3.6 or higher
- Streamlit
- Necessary Python libraries (bcrypt, cryptography, ssl, requests, hashlib, etc.)

### Steps:
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/password-auth-2fa-extension.git
   cd password-auth-2fa-extension

# Password Management and Authentication System

## Setup Instructions

### 1. Install Dependencies

Ensure you have the required libraries by running:

```bash
pip install -r requirements.txt
2. Run the Streamlit App
To start the frontend UI, use the following command:

bash
Copy
streamlit run app.py
3. Configure Secret Keys
Ensure that the secret.key file for Fernet encryption is present in the root directory. If not, generate it using:

python
Copy
from cryptography.fernet import Fernet
print(Fernet.generate_key())
4. Set Up SSL (Optional)
If deploying on a server, ensure that SSL certificates are configured for secure communication.

How to Use
1. Access the Chrome Extension
Install the Chrome Extension as you would any standard extension.

2. Input Credentials
When prompted, input your password in the provided field.

3. Password Evaluation
The extension evaluates your password for compliance with strength and policy rules and checks if it has been involved in a breach.

4. 2FA
After validating your password, the system will prompt for a second factor to complete the authentication.

Code Structure
app.py: Main entry point for the Streamlit frontend UI.
password_policy.py: Defines password policy rules and validation methods.
password_analyzer.py: Contains the PasswordStrengthAnalyzer class for calculating password strength.
hibp_checker.py: Queries the Have I Been Pwned (HIBP) API to check for compromised passwords.
security.py: Handles encryption, hashing, and secure storage of user passwords.
config.json: Stores encrypted user credentials and configuration data.
requirements.txt: List of all necessary Python libraries and dependencies.
Security Considerations
Password Hashing: Passwords are hashed with bcrypt, making them resistant to brute force or dictionary attacks.
Encryption: User credentials are encrypted using the Fernet symmetric encryption to secure sensitive data both at rest and in transit.
SSL Encryption: SSL/TLS ensures that all communications between the user and the server are securely encrypted.
Contributing
We welcome contributions! To contribute:

Fork the repository.
Clone your fork.
Create a new branch.
Implement your feature or fix.
Create a pull request.
