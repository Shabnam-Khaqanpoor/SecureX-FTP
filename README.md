# SecureX-FTP

## 🔒 Secure & Flexible FTP Server with TLS Encryption
SecureX-FTP is a secure FTP server supporting **FTPS (FTP Secure over TLS/SSL)** with built-in encryption, ensuring safe and authenticated file transfers. It is designed for flexible deployment without requiring external dependencies like OpenSSL.

---

## 🚀 Features
✅ **Supports FTPS** with built-in TLS encryption  
✅ **SSL/TLS encryption** for data protection  
✅ **User authentication** with permission-based access  
✅ **Automatic certificate generation** for FTPS security  
✅ **Logging & monitoring** of file activities  
✅ **Cross-platform compatibility** (Linux, Windows, Mac)  
✅ **Standalone operation** without OpenSSL or OpenSSH  

---

## 📁 Project Structure
```
SecureX-FTP/
│── FTPServer.py             # Core FTP server implementation
│── FTPClient.py             # Client-side FTP script
│── utilities.py             # Helper functions for FTP operations
│── Encryption_Methods/      # SSL/TLS encryption modules
│   │── SSL_Encryption.py
│   │── TLS_Encryption.py
│   │── SSL_TLS_Encryption.py
│── Certificate_and_Key/     # Certificates and key management
│   │── cert.pem             # SSL certificate
│   │── key.pem              # SSL private key
│   │── ssl_certificate_generator.py  # Script to generate certificates
│── client-folder/           # User directories (client-side)
│── server-folder/           # Server directories with permissions
│── README.md                # Project documentation
```

---

## 🔧 Installation & Setup

### **1️⃣ Prerequisites**
Ensure you have:
- Python 3.x (Required)
- No external dependencies needed

### **2️⃣ Clone the Repository**
```bash
git clone https://github.com/Shabnam-Khaqanpoor/SecureX-FTP.git
cd SecureX-FTP
```

### **3️⃣ Generate SSL/TLS Certificates (For FTPS Mode)**
Run the certificate generator script:
```bash
python Certificate_and_Key/ssl_certificate_generator.py
```
This will create `cert.pem` and `key.pem` inside `Certificate_and_Key/`.

### **4️⃣ Running the Server**
Start the FTP server with FTPS enabled:
```bash
python FTPServer.py
```

---

## 📌 Usage

### **Connecting via FTPS**
Using an FTPS client like FileZilla.

### **Using the Client Script**
Run the client script to connect and transfer files:
```bash
python FTPClient.py
```

---
