# SecureX-FTP

## 🔒 Secure & Flexible FTP Server (SFTP & FTPS)
SecureX-FTP is a secure FTP server supporting **SFTP (SSH File Transfer Protocol)** and **FTPS (FTP Secure over TLS)**. It ensures encrypted communication, authentication, and safe file transfers.

---

## 🚀 Features
✅ Supports both **SFTP** and **FTPS** for secure file transfers  
✅ **SSL/TLS encryption** for data protection  
✅ **User authentication** with permission-based access  
✅ **Certificate management** for FTPS security  
✅ **Logging & monitoring** of file activities  
✅ **Cross-platform compatibility** (Linux, Windows, Mac)  

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
- Python 3.x
- OpenSSL (for FTPS encryption)
- OpenSSH (for SFTP support)

### **2️⃣ Clone the Repository**
```bash
git clone https://github.com/your-username/SecureX-FTP.git
cd SecureX-FTP
```

### **3️⃣ Generate SSL/TLS Certificates (For FTPS Mode)**
Run the certificate generator script:
```bash
python Certificate_and_Key/ssl_certificate_generator.py
```
This will create `cert.pem` and `key.pem` inside `Certificate_and_Key/`.

### **4️⃣ Running the Server**
Start the FTP server in FTPS mode:
```bash
python FTPServer.py --ftps
```
Start the server in SFTP mode:
```bash
python FTPServer.py --sftp
```

---

## 📌 Usage

### **Connecting via SFTP**
Use an SFTP client like FileZilla or OpenSSH:
```bash
sftp user@your-server.com
```

### **Connecting via FTPS**
Using an FTPS client:
```bash
ftp -tls user@your-server.com
```

### **Using the Client Script**
Run the client script to connect and transfer files:
```bash
python FTPClient.py --server your-server.com --mode sftp
```

---

## 🛠️ Contribution Guidelines
1️⃣ Fork the repository  
2️⃣ Create a new branch (`feature-xyz`)  
3️⃣ Commit changes with meaningful messages  
4️⃣ Submit a pull request  

