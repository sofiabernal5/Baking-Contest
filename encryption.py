from cryptography.fernet import Fernet
import os

def generate_key():
    """Generate a new encryption key and save it to a file."""
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from a file."""
    if not os.path.exists('secret.key'):
        generate_key()
    with open('secret.key', 'rb') as key_file:
        return key_file.read()

# Initialize the cipher with the loaded key
key = load_key()
cipher = Fernet(key)

def encrypt(data: str) -> str:
    """Encrypt a string."""
    encrypted = cipher.encrypt(data.encode()).decode()
    print(f"Encrypting Data: {data} -> {encrypted}")
    return encrypted

def decrypt(data: str) -> str:
    """Decrypt a string."""
    return cipher.decrypt(data.encode()).decode()
