# 📌 CrypticComm – Secure Messaging Platform

## 🔎 Overview
**CrypticComm** is a secure communication platform designed to allow users to send and receive confidential messages with real-time classification of confidentiality levels. The system integrates **Machine Learning (BERT)** to analyze the sensitivity of messages and recommends the most suitable encryption technique before sending.  

This project was built with the goal of combining **modern cryptography**, **machine learning**, and **user-friendly UI** to ensure safe and reliable digital communication.  

---

## 🎯 Objectives
- ✅ Provide a **secure messaging system** with end-to-end encryption.  
- ✅ **Classify messages** automatically into *High, Medium, or Low* confidentiality levels.  
- ✅ Display **encryption recommendations** based on classification.  
- ✅ Generate **SHA-256 hash values** for message integrity verification.  
- ✅ Maintain an **Inbox system** with unread message counts.  
- ✅ Provide **Contacts dropdown** for quick access to registered users.  

---

## 🧠 Machine Learning Component
**Model Used**: `BERT (Bidirectional Encoder Representations from Transformers)`  

**Purpose**:  
- Analyzes input messages.  
- Maps them to confidentiality levels (*High / Medium / Low*).  
- Suggests appropriate **encryption algorithms** (e.g., Fernet, RSA, AES).  

---

## ⚙️ Tech Stack

### 🔹 Frontend
- **HTML5, CSS3, Bootstrap 5** → Responsive UI with modern styling.  
- **JavaScript (Vanilla JS)** → Handles classification requests, hashing, and dynamic UI updates.  
- **SweetAlert2** → Beautiful alerts for success, errors, and warnings.  

### 🔹 Backend
- **Django (Python)** → Web framework managing users, authentication, and messaging.  
- **REST APIs** → For classification (`/ml/classify/`) and secure message transmission (`/send_message/`).  

### 🔹 Machine Learning
- **BERT model (Hugging Face Transformers)** → Used for natural language classification.  
- **Scikit-learn / PyTorch** → For preprocessing, fine-tuning, and deployment of ML pipeline.  

### 🔹 Security & Cryptography
- **SHA-256** → Generates unique message hash values for integrity verification.  
- **Fernet / AES / RSA** → Encryption methods recommended based on message confidentiality.  
- **CSRF Protection (Django)** → Secures POST requests.  

---

## 📂 Features at a Glance
- 🔐 **Secure Login & Logout system**  
- 📬 **Inbox with unread message count**  
- 📜 **Confidentiality classification (via ML)**  
- 🛡️ **Encryption suggestion based on classification**  
- 🧾 **Hash value generation for integrity check**  
- 👥 **Registered contacts dropdown for quick messaging**  
- 🎨 **Modern UI** with gradient backgrounds & Bootstrap components  

---

## ✅ Conclusion
**CrypticComm** successfully integrates secure communication with machine learning–based message classification to provide a modern, reliable, and user-friendly messaging platform.  

By leveraging **BERT for confidentiality detection**, robust **cryptographic techniques**, and a clean **Django + Bootstrap architecture**, the project ensures that sensitive information is transmitted safely and efficiently.  

This system demonstrates how **AI and cybersecurity can work together** to enhance digital communication, making it suitable for academic, professional, and organizational use.  

With further enhancements like **real-time chat, stronger key management, and analytics dashboards**, CrypticComm can evolve into a fully production-ready secure communication platform.  
