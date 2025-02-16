# Chrome Extension: 2FA with Real-Time Password Security Check

## Overview

This Chrome extension enhances the login security for company web pages by integrating two-factor authentication (2FA) with real-time password security checks. The extension checks the entered password against the "Have I Been Pwned" API to ensure it has not been part of any known breaches. Upon successful password validation, the extension establishes a secure SSL handshake between the user and the server to complete the authentication process.

The user interface for the authentication process is built using **Streamlit**, providing an easy-to-use and interactive frontend experience.

Future features will include regular checks for breached passwords and sending notifications to the user when their credentials are compromised.

## Features

- **Real-Time Password Security Check**: During the first authentication step, the extension checks if the entered password has been compromised using the "Have I Been Pwned" API.
- **SSL Handshake**: After password validation, an SSL handshake is performed to ensure secure communication between the user and the server.
- **Two-Factor Authentication (2FA)**: After the password check, a second factor is used to provide additional security.
- **Streamlit Frontend**: The authentication process is presented through an interactive frontend built with Streamlit, providing a seamless and user-friendly experience.
- **Breach Notifications (Future Scope)**: The extension will periodically check passwords for breaches and notify the user if a breach is detected.

## Installation

1. **Clone the Repository**:
   Clone or download the repository to your local machine.

2. **Install Dependencies**:
   You need to install the required Python dependencies, including `streamlit` and others needed for the extension and password breach checking functionality.
   
   Run the following command to install dependencies:
   
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup the Chrome Extension**:
   - Open Chrome and navigate to `chrome://extensions/`.
   - Enable **Developer mode**.
   - Click on **Load unpacked** and select the folder containing the Chrome extension files.

4. **Run the Streamlit App**:
   Start the Streamlit app by running the following command in the project directory:

   ```bash
   streamlit run app.py
   ```

   This will launch a local Streamlit app that serves as the frontend for the authentication process.

5. **Test the Extension**:
   Once everything is set up, go to a supported company page that requires login, and the extension will take over the login process, providing the interactive UI from Streamlit.

## Usage

1. **Password Check**: On logging in, the extension prompts you to enter your password. The entered password is:
   - Checked against the "Have I Been Pwned" API to detect any known breaches.
   - If the password is found in a breach, you'll be alerted to change it.
   - If the password is safe, the system proceeds to the second factor of authentication.
   
2. **SSL Handshake**: Once both authentication steps are complete, the extension establishes an SSL handshake to secure communication between the user and the server.

3. **Streamlit Interface**: The password input, breach status, and authentication steps are presented through the interactive Streamlit frontend, providing an intuitive and engaging user experience.

## Future Scope

- **Regular Password Breach Checks**: The extension will be updated to regularly check the user’s password in the background to ensure it remains secure.
- **Breach Notifications**: Users will receive notifications if their password is found in a new data breach.
- **Biometric Integration**: Future versions may include options for biometric authentication (e.g., fingerprint or face recognition) as part of the 2FA process.
- **Advanced Security Features**: We plan to integrate additional features such as OTP generation and passwordless authentication.

## Dependencies

- **Streamlit**: Streamlit is used to build the interactive frontend for the extension. [Streamlit Documentation](https://docs.streamlit.io/)
- **Have I Been Pwned API**: The extension uses the public "Have I Been Pwned" API to check for compromised passwords. [API Documentation](https://haveibeenpwned.com/API/v3)
- **Chrome APIs**: Standard Chrome APIs are used to interact with web pages, handle user input, and manage background tasks.

To install required dependencies, run:

```bash
pip install streamlit requests
```

## Contributing

We welcome contributions to improve the functionality and security of this extension. If you'd like to contribute, please fork the repository and submit a pull request with your proposed changes.

### Steps to Contribute

1. Fork the repository.
2. Clone the forked repository to your local machine.
3. Make your changes.
4. Push your changes to your fork.
5. Submit a pull request.

### Issues

If you encounter any bugs or have feature requests, feel free to open an issue on the repository.


