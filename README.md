# 🚀 AI-Powered Adaptive Password Hygiene & Biometric Security Monitor

## 🔍 Overview

With increasing credential-based attacks (password leaks, brute force and phishing), traditional password security measures fail to prevent unauthorized access. This project aims to enhance password security using AI-powered real-time monitoring and behavioral biometrics.

## ⚙️ Features

✅ **Keystroke Dynamics-Based Authentication**  
✅ **Real-Time Password Strength & Breach Analysis**  
✅ **Enterprise-Level Security & Policy Compliance**    
✅ **MFA Triggers for Suspicious Login Attempts**  
✅ **Admin-Controlled User Access for Enterprises**  

## 🛠 Tech Stack

### **Frontend - Browser Extension**
- Manifest V3 API (Chrome/Firefox Extension Development)
- JavaScript (Vanilla/React for popup UI)
- D3.js for password strength visualization

### **Backend & AI Models**
- FastAPI / Flask (Python) – AI-based risk assessment API
- TensorFlow / Scikit-learn – Keystroke Dynamics Model

### **Security & Authentication**
- Have I Been Pwned API – Breach Detection
- Custom Password Policy Enforcement – Enterprise rules (configurable)
- User's Google Sheets – Store anonymized biometric trends

### **Deployment & Hosting**
- Vercel / AWS Lambda – Hosting backend API
- GitHub Pages – For extension documentation & landing page

### 📌 Complete System Workflow for Enterprise Security

### ✅ 1. User Registration & Biometric Setup (First-Time Login)
1️⃣ **New User Login Attempt on a Company Device**  
   - The browser extension **detects a login attempt** and **sends an approval request** to the admin panel.  
   - A **60-second approval window** is triggered.  

2️⃣ **Admin Approval Process**  
   - IT Admin **receives a real-time notification** (via email, Slack, or the enterprise security dashboard).  
   - The admin can **approve or deny** the login request.  
   - If **approved**, the user **proceeds to password setup & biometric training**.  

3️⃣ **Keystroke Dynamics Training**  
   - The system **records the user’s typing behavior** while entering their password.  
   - AI analyzes **keystroke patterns, timing, and pressure variations** to create a unique biometric profile.  
   - **Biometric data is securely stored** in Google Sheets.

---

### ✅ 2. Daily Login Workflow (Post Registration)
1️⃣ **User Enters Password on the Company Login Page**  
   - The **browser extension analyzes keystroke dynamics** in real time.  
   - If **typing pattern matches** the trained biometric profile → **Login is allowed.**  
   - If there’s an **anomaly** (e.g., unusual typing speed, pauses, bot-like behavior):  
     - 🔹 **Flags the attempt as suspicious**  
     - 🔹 **Triggers additional MFA verification** (OTP, FaceID, Security Key)  

2️⃣ **Real-Time Risk Score Calculation**  
   - **Password Strength + Keystroke Biometrics** generate a **security risk score**.  
   - **Color-coded risk alerts:**  
     - ✅ **Green:** Safe Login  
     - 🟡 **Yellow:** Moderate Risk (user warned)  
     - 🔴 **Red:** High Risk (MFA required or login blocked)  

---

### ✅ 3. Enterprise Security & Continuous Monitoring
1️⃣ **Security Logs & Anomaly Detection**  
   - **Logs all login attempts & security events** in Google Sheets  
   - Detects **high-risk behavior** (brute force attempts, location anomalies).  

2️⃣ **Admin Dashboard for Enterprise Monitoring**  
   - **Visualizes password risk trends** (Chart.js / D3.js).  
   - **Department-Based Security Analytics** (flag weak passwords by HR, IT, Finance, etc.).  
   - **Breach Alerts via Slack/Email** if enterprise-wide security violations are detected.  

## 🔑 Usage

1. **Enable the browser extension** on a company-approved device.  
2. **Login is only possible on the company's official login page**   
3. When a **new user attempts to log in**, a **request is sent to the admin** for approval.  
   - The **admin must approve within 60 seconds** for the login to proceed.  
4. **After approval**, the user will:  
   - **Enter their password**.  
   - **Train the AI model** on their **keystroke dynamics** (typing behavior).  
   - This biometric data is securely **stored in the user’s Google Sheets** for future authentication.  
5. **For daily logins (after registration):**  
   - The extension verifies **keystroke dynamics** in real-time.  
   - If the typing pattern **matches the trained biometric profile**, login is **granted**.  
   - If an **anomaly is detected** (e.g., different typing speed, unusual pauses), additional **MFA verification** (OTP, FaceID, or Security Key) is required.  
6. **Continuous Enterprise Security Monitoring:**  
   - All login attempts & security incidents are **logged in Google Sheets** (or enterprise database).  
   - The system flags **high-risk behavior** (e.g., brute-force attempts, login from unauthorized locations).  
   - Admins receive **real-time security alerts** if suspicious activity is detected.  


## 🚀 Future Improvements
- 🔹 Customising the strength assessment according to the comapany's policies
- 🔹 More advanced keystroke behavioral models
- 🔹 Integrate with Dark Web monitoring APIs
- 🔹 Use Google Safe Browsing API to flag phishing domains

### **Maintained by:**
👨‍💻 Codex Betas

