# Elliptic-Curve-Cryptography
This project provides an API service using FastAPI to encrypt and decrypt files securely with Elliptic Curve Cryptography (ECC) and AES. It ensures data confidentiality by combining asymmetric and symmetric encryption methods.



# Elliptic Curve Cryptography (ECC) File Encryption Project

## Project Introduction
This project implements a file encryption and decryption application based on **Elliptic Curve Cryptography (ECC)**, and uses **FastAPI** to provide API services, allowing users to encrypt and decrypt audio and other files to ensure data security.

### **Technology Stack**
- Python 3.10+
- FastAPI
- Cryptography
- Uvicorn

---

## **Features**
1. **Generate an ECC key pair**  
   - Generate public and private keys and store them in PEM format.

2. **File encryption**  
   - Use ECC for key exchange and AES for file encryption.
   - Storage format of encrypted data  
     ```
     [PEM public key length (4 bytes)] + [PEM public key] + [IV (16 bytes)] + [ciphertext]
     ```
   
3. **File Decryption**
   - Parse the encrypted file, extract the key and restore the original file.

---

## **Installation and run**

### **1. Clone the project**
```bash
git clone https://github.com/yourusername/ecc-file-encryption.git
cd ecc-file-encryption


4. Run the FastAPI Server

uvicorn app.config:app --reload

The server will run at http://127.0.0.1:8000
