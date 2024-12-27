# 🔐 Python Secure Password Manager

A robust and secure command-line password manager built with Python that emphasizes security and ease of use. This project demonstrates implementation of cryptographic principles and secure password management practices.

## 🚀 Features

- **Strong Encryption**: Uses AES-256 encryption for password storage
- **Secure Password Generation**: Creates strong random passwords with customizable length
- **Master Password Protection**: All data is encrypted with a master password
- **User-Friendly CLI**: Simple command-line interface for all operations
- **Secure Storage**: Passwords are never stored in plain text
- **Salt-based Key Derivation**: Uses PBKDF2 with SHA256 for key generation

## 🛠️ Technical Implementation

- **Encryption**: Utilizes the `cryptography` library for AES-256 encryption
- **Key Derivation**: Implements PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Secure Random Generation**: Uses `secrets` module for cryptographically strong random generation
- **Data Storage**: Encrypted data stored in binary format
- **Password Requirements**: Ensures generated passwords include uppercase, lowercase, numbers, and special characters

## 🔧 Setup
1. Clone the repository:
```bash
git clone https://github.com/SecOpsGrogu1/Password-manager.git
cd Password-manager
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

Run the password manager:
```bash
python password_manager.py
```

### Available Commands:
- `add`: Add a new password entry
- `get`: Retrieve a stored password
- `list`: List all stored password entries
- `generate`: Generate a strong password
- `quit`: Exit the program

## 🔒 Security Features

1. **Master Password Protection**
   - All stored data is encrypted with your master password
   - Salt-based key derivation prevents rainbow table attacks

2. **Strong Encryption**
   - AES-256 encryption for all stored data
   - Unique salt for each password manager instance

3. **Secure Password Generation**
   - Cryptographically secure random number generation
   - Configurable password length
   - Ensures password complexity requirements

## 👨‍💻 Author

SecOpsGrogu1

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](https://github.com/SecOpsGrogu1/Password-manager/issues).
