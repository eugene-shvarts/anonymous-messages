from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode
import os

# Use base58 for public key encoding
import base58

def generate_key_pair():
    """Generate a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize public key to Base58 format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base58.b58encode(pem).decode()

def deserialize_public_key(base58_string):
    """Deserialize public key from Base58 format."""
    der = base58.b58decode(base58_string)
    public_key = serialization.load_der_public_key(
        der,
        backend=default_backend()
    )
    return public_key

def encrypt_private_key(private_key, password):
    """Encrypt private key with a password."""
    if isinstance(password, str):
        password = password.encode()

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )) + encryptor.finalize()
    return b64encode(salt + iv + encrypted_key).decode()

def decrypt_private_key(encrypted_key, password):
    """Decrypt private key with a password."""
    if isinstance(password, str):
        password = password.encode()

    decoded = b64decode(encrypted_key)
    salt, iv, encrypted_key = decoded[:16], decoded[16:32], decoded[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    return serialization.load_der_private_key(
        decrypted_key,
        password=None,
        backend=default_backend()
    )

def hybrid_encrypt(data: str, public_key) -> str:
    """Encrypt data using hybrid encryption (RSA + AES)."""
    # Generate a random symmetric key
    symmetric_key = os.urandom(32)  # 256-bit key for AES

    # Encrypt the symmetric key with RSA
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt the data with AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    # Combine encrypted symmetric key, IV, and encrypted data
    return b64encode(encrypted_symmetric_key + iv + encrypted_data).decode()

def hybrid_decrypt(encrypted_data: str, private_key) -> str:
    """Decrypt data using hybrid encryption (RSA + AES)."""
    decoded = b64decode(encrypted_data)
    
    # Split the components
    encrypted_symmetric_key = decoded[:256]  # 2048-bit RSA key produces 256-byte ciphertext
    iv = decoded[256:272]  # 16-byte IV
    encrypted_data = decoded[272:]

    # Decrypt the symmetric key with RSA
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

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

### Example usage

# password = "user_secret_password"

# # Generate a key pair for a user
# private_key, public_key = generate_key_pair()

# # Serialize public key to Base58
# public_key_base58 = serialize_public_key(public_key)

# # Encrypt private key with password
# encrypted_private_key = encrypt_private_key(private_key, password)

# print("Public Key (Base58):")
# print(public_key_base58)
# print("\nEncrypted Private Key:")
# print(encrypted_private_key)

# # Simulate storing and retrieving the encrypted private key
# # In a real scenario, you would store this in a database
# stored_encrypted_private_key = encrypted_private_key

# # Later, when the user needs to use their private key:
# decrypted_private_key = decrypt_private_key(stored_encrypted_private_key, password)

# # Encrypt data using hybrid encryption
# original_data = "This is some sensitive user data that needs to be encrypted. It can be quite long now, thanks to hybrid encryption."
# encrypted = hybrid_encrypt(original_data, public_key)

# print(f"\nOriginal: {original_data}")
# print(f"Encrypted: {encrypted}")

# # Decrypt data using hybrid decryption
# decrypted = hybrid_decrypt(encrypted, decrypted_private_key)
# print(f"Decrypted: {decrypted}")

# # Example of using the Base58 public key
# deserialized_public_key = deserialize_public_key(public_key_base58)
# encrypted2 = hybrid_encrypt("Another secret message", deserialized_public_key)
# decrypted2 = hybrid_decrypt(encrypted2, decrypted_private_key)

# print(f"\nDecrypted (using deserialized public key): {decrypted2}")
