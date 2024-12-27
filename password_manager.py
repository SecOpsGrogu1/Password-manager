import base64
import os
import json
import getpass
import secrets
import string
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self):
        self.salt = b''
        self.key = None
        self.fernet = None
        self.passwords = {}
        self.filename = 'passwords.enc'
        self.initialize()

    def initialize(self):
        """Initialize the password manager with a master password."""
        if os.path.exists(self.filename):
            self._load_salt()
            master_password = getpass.getpass("Enter your master password: ")
            self.key = self._generate_key(master_password)
            self.fernet = Fernet(self.key)
            self._load_passwords()
        else:
            master_password = getpass.getpass("Create a master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            
            if master_password != confirm_password:
                raise ValueError("Passwords do not match!")
            
            self.salt = os.urandom(16)
            self.key = self._generate_key(master_password)
            self.fernet = Fernet(self.key)
            self._save_salt()
            self._save_passwords()

    def _generate_key(self, password: str) -> bytes:
        """Generate an encryption key from the master password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _save_salt(self):
        """Save the salt to a file."""
        with open('salt.bin', 'wb') as f:
            f.write(self.salt)

    def _load_salt(self):
        """Load the salt from file."""
        with open('salt.bin', 'rb') as f:
            self.salt = f.read()

    def _save_passwords(self):
        """Save encrypted passwords to file."""
        encrypted_data = self.fernet.encrypt(json.dumps(self.passwords).encode())
        with open(self.filename, 'wb') as f:
            f.write(encrypted_data)

    def _load_passwords(self):
        """Load and decrypt passwords from file."""
        try:
            with open(self.filename, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data.decode())
        except Exception as e:
            print("Error: Invalid master password or corrupted data.")
            exit(1)

    def add_password(self, service: str, username: str, password: str):
        """Add a new password entry."""
        self.passwords[service] = {
            'username': username,
            'password': password
        }
        self._save_passwords()
        print(f"Password for {service} has been saved.")

    def get_password(self, service: str) -> Optional[Dict[str, str]]:
        """Retrieve a password entry."""
        return self.passwords.get(service)

    def list_services(self):
        """List all stored services."""
        return list(self.passwords.keys())

    def generate_password(self, length: int = 16) -> str:
        """Generate a strong random password."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(c in string.punctuation for c in password)):
                return password

def main():
    print("Welcome to the Secure Password Manager!")
    pm = PasswordManager()
    
    while True:
        print("\nAvailable commands:")
        print("1. add - Add a new password")
        print("2. get - Retrieve a password")
        print("3. list - List all services")
        print("4. generate - Generate a strong password")
        print("5. quit - Exit the program")
        
        command = input("\nEnter command: ").lower()
        
        if command == 'add':
            service = input("Enter service name: ")
            username = input("Enter username: ")
            use_generated = input("Generate password? (y/n): ").lower() == 'y'
            
            if use_generated:
                length = int(input("Enter password length (default 16): ") or 16)
                password = pm.generate_password(length)
                print(f"Generated password: {password}")
            else:
                password = getpass.getpass("Enter password: ")
            
            pm.add_password(service, username, password)

        elif command == 'get':
            service = input("Enter service name: ")
            entry = pm.get_password(service)
            if entry:
                print(f"\nService: {service}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
            else:
                print(f"No entry found for {service}")

        elif command == 'list':
            services = pm.list_services()
            if services:
                print("\nStored services:")
                for service in services:
                    print(f"- {service}")
            else:
                print("No passwords stored yet.")

        elif command == 'generate':
            length = int(input("Enter password length (default 16): ") or 16)
            password = pm.generate_password(length)
            print(f"\nGenerated password: {password}")

        elif command == 'quit':
            print("Goodbye!")
            break

        else:
            print("Invalid command!")

if __name__ == "__main__":
    main()
