from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
import os

def generate_key_pair():
    """Generate an RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair(private_key, public_key, private_key_path, public_key_path):
    """Save the private and public keys to PEM files."""
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_key_pair(private_key_path, public_key_path):
    """Load the private and public keys from PEM files."""
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
        )

    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    return private_key, public_key

def sign_message(private_key, message):
    """Sign a message with the private key."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """Verify a signature with the public key."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    """Main function to generate keys, sign and verify a message."""
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"

    # Generate keys only if they don't exist
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key, public_key = generate_key_pair()
        save_key_pair(private_key, public_key, private_key_path, public_key_path)
        print("New key pair generated and saved.")
    else:
        print("Existing key pair found. Loading keys.")

    # Load the key pair
    private_key, public_key = load_key_pair(private_key_path, public_key_path)

    # Message to be signed
    message = b" darakhsha ."

    # Sign the message
    signature = sign_message(private_key, message)
    print("Signature:", signature.hex())  # Print signature in hex format

    # Verify the signature
    is_valid = verify_signature(public_key, message, signature)
    print("Signature valid:", is_valid)

if __name__ == "__main__":
    main()
