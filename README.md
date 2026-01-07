# ITRI615 Cryptography Project

## 📌 Project Overview
This project is a **desktop-based encryption and decryption application** developed as a **group assignment**
for the ITRI615 Cryptography module at North-West University.

The application demonstrates the practical implementation of classical and hybrid
cryptographic algorithms through file-based encryption and decryption using a GUI.

---

## 🎯 Objectives
- Apply cryptography theory in a real-world application
- Implement multiple encryption and decryption algorithms
- Enforce correct key management and validation
- Demonstrate secure file handling practices

---

## 🔐 Implemented Algorithms
- Vernam Cipher (One-Time Pad)
- Vigenère Cipher
- Columnar Transposition Cipher
- Product Cipher
- Custom Hybrid Encryption Algorithm

---

## 👥 Team Contributions
This was a **group project**, with each member responsible for specific cryptographic components.

### ✨ My Contribution (Monica Serwala)
- Designed and implemented the **Vernam Cipher (One-Time Pad)**
- Developed XOR-based encryption and decryption logic
- Implemented secure random key generation
- Enforced key-length validation to ensure cryptographic correctness
- Integrated the Vernam Cipher into the application workflow

---

## 🔑 Vernam Cipher (One-Time Pad)
The Vernam Cipher is a symmetric key encryption method where each byte of the plaintext
is XORed with a corresponding byte from a randomly generated key of equal length.

### Key Properties:
- Perfect secrecy when used correctly
- Key length must be equal to or greater than the plaintext
- Key must be random, secret, and used only once

---

## 🛠️ Technologies Used
- Python
- Tkinter (GUI)
- Cryptography Algorithms
- File I/O
- Git & GitHub
- Visual Studio

---

## ▶️ How to Use the Application
### Encryption
1. Select a plaintext file using the **Browse** button
2. Generate a key or manually enter one
3. Choose the encryption algorithm
4. Click **Encrypt** to produce an encrypted `.enc` file

### Decryption
1. Select the encrypted `.enc` file
2. Enter the same key used during encryption
3. Click **Decrypt** to restore the original file

---

## 📄 Documentation
Detailed technical documentation is included in the `Documentation/` folder, explaining:
- Encryption and decryption logic
- Algorithm design
- Key generation strategies
- Security considerations

---

## ⚠️ Disclaimer
This project was developed for **academic purposes** as part of a university group assignment.
All contributors are acknowledged for their respective roles.
The application is not intended for production-grade security use.

---

## 📚 Institution
North-West University  
BSc Honours Computer Science & Information Technology
