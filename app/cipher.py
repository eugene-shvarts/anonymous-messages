import os

from base64 import b64encode, b64decode
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key_pair():
    """Generate a new X25519 key pair."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize public key to Base64 format."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(raw_bytes).decode()

def deserialize_public_key(base64_string):
    """Deserialize public key from Base64 format."""
    raw_bytes = b64decode(base64_string)
    return X25519PublicKey.from_public_bytes(raw_bytes)

def encrypt_private_key(private_key, password):
    """Encrypt private key with a password using bcrypt and AES-GCM."""
    if isinstance(password, str):
        password = password.encode()

    # Get the raw bytes of the private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate salt and hash password with bcrypt
    salt = bcrypt.gensalt()
    bcrypt_hash = bcrypt.hashpw(password, salt)

    # Use the last 32 bytes of the bcrypt hash as the encryption key
    encryption_key = bcrypt_hash[-32:]

    # Generate a random nonce
    nonce = os.urandom(12)  # 96 bits for GCM

    # Encrypt the private key bytes
    encrypted_key = AESGCM(encryption_key).encrypt(nonce, private_key_bytes, None)

    # Combine salt, nonce, tag, and encrypted key
    return b64encode(salt + nonce + encrypted_key).decode()

def decrypt_private_key(encrypted_key, password):
    """Decrypt private key with a password using bcrypt and AES-GCM."""
    if isinstance(password, str):
        password = password.encode()

    decoded = b64decode(encrypted_key)
    salt, nonce = decoded[:29], decoded[29:41]
    encrypted_key_data = decoded[41:]

    # Use the last 32 bytes of the bcrypt hash as the decryption key
    decryption_key = bcrypt.hashpw(password, salt)[-32:]

    # Decrypt the private key bytes
    decrypted_key_bytes = AESGCM(decryption_key).decrypt(nonce, encrypted_key_data, None)

    # Reconstruct the X25519 private key from the decrypted bytes
    return X25519PrivateKey.from_private_bytes(decrypted_key_bytes)

def hybrid_encrypt(data: str, public_key: X25519PublicKey) -> str:
    """Encrypt data using hybrid encryption (X25519 + AES)."""

    # Perform X25519 key exchange
    ephemeral_private_key = X25519PrivateKey.generate()
    shared_secret = ephemeral_private_key.exchange(public_key)
    
    shared_pubkey = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Derive a key using bcrypt
    bcrypt_salt = bcrypt.gensalt() # 29 bytes
    derived_key = bcrypt.hashpw(shared_secret, bcrypt_salt)[-32:]

    # Generate and encrypt a symmetric key
    key_nonce = os.urandom(12) # 12 bytes
    symmetric_key = os.urandom(32)  # 256-bit key for AES
    encrypted_symmetric_key = AESGCM(derived_key).encrypt(key_nonce, symmetric_key, None)

    # Encrypt the data with AES
    data_nonce = os.urandom(12)  # 12 bytes
    encrypted_data = AESGCM(symmetric_key).encrypt(data_nonce, data.encode(), None)

    # Combine all components
    return b64encode(
        shared_pubkey + bcrypt_salt +
        key_nonce + encrypted_symmetric_key +
        data_nonce + encrypted_data
    ).decode()

def hybrid_decrypt(encrypted_data: str, private_key: X25519PrivateKey) -> str:
    """Decrypt data using hybrid encryption (X25519 + AES)."""
    decoded = b64decode(encrypted_data)
    
    # Split the components
    shared_pubkey_bytes = decoded[:32]
    bcrypt_salt = decoded[32:61]
    key_nonce = decoded[61:73]
    encrypted_symmetric_key = decoded[73:121]
    data_nonce = decoded[121:133]
    encrypted_data = decoded[133:]

    # Perform X25519 key exchange
    shared_pubkey = X25519PublicKey.from_public_bytes(shared_pubkey_bytes)
    shared_secret = private_key.exchange(shared_pubkey)

    # Derive the same key using bcrypt
    derived_key = bcrypt.hashpw(shared_secret, bcrypt_salt)[-32:]

    # Decrypt the symmetric key
    symmetric_key = AESGCM(derived_key).decrypt(key_nonce, encrypted_symmetric_key, None)

    # Decrypt the data with AES
    decrypted_data = AESGCM(symmetric_key).decrypt(data_nonce, encrypted_data, None)

    return decrypted_data.decode()

def user_info_from_secret(secret_key):
    keybytes = b64decode(secret_key)
    pid = int.from_bytes(keybytes[18:], byteorder='big')
    pw = keybytes[:18]
    return pid, pw

def secret_from_user_info(pid, pw):
    def int_to_bytes(x):
        return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    return b64encode(pw + int_to_bytes(pid)).decode()

## Example usage
# priv, pub = generate_key_pair()
# hybrid_decrypt( hybrid_encrypt("check this out", pub), priv )
