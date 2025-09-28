import os
import base64
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# --- Global RSA keypair (for high security encryption) ---
GLOBAL_RSA_KEY = RSA.generate(2048)
GLOBAL_PUBLIC_KEY = GLOBAL_RSA_KEY.publickey()
GLOBAL_PRIVATE_KEY = GLOBAL_RSA_KEY.export_key().decode()

# --- Helper functions ---
def _pack(*parts):
    return b"".join(struct.pack("!I", len(p)) + p for p in parts)

def _unpack(raw, expected_parts):
    parts = []
    current_raw = raw
    for _ in range(expected_parts):
        if len(current_raw) < 4:
            raise ValueError("Corrupted data: Incomplete length header.")
        length = struct.unpack("!I", current_raw[:4])[0]
        current_raw = current_raw[4:]
        if len(current_raw) < length:
            raise ValueError("Corrupted data: Incomplete data part.")
        part, current_raw = current_raw[:length], current_raw[length:]
        parts.append(part)
    return parts

def fix_base64_padding(s: str) -> str:
    return s + '=' * (-len(s) % 4)

# --- Low security (Fernet) ---
def low_encrypt(message: str) -> dict:
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(message.encode())
    bundle = base64.urlsafe_b64encode(_pack(key, token)).decode()
    return {"bundle": bundle, "private_key": key.decode()}  # store key for low messages


def low_decrypt(bundle_str: str, key: str = None) -> str:
    fixed_str = fix_base64_padding(bundle_str)
    raw = base64.urlsafe_b64decode(fixed_str.encode())
    key_from_bundle, token = _unpack(raw, 2)
    fernet_key = key.encode() if key else key_from_bundle
    f = Fernet(fernet_key)
    return f.decrypt(token).decode()


# --- Medium security (AES-GCM) ---
def medium_encrypt(message: str) -> str:
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), None)
    return base64.urlsafe_b64encode(_pack(key, nonce, ct)).decode()

def medium_decrypt(bundle_str: str) -> str:
    fixed_str = fix_base64_padding(bundle_str)
    raw = base64.urlsafe_b64decode(fixed_str.encode())
    key, nonce, ct = _unpack(raw, 3)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

# --- High security (Hybrid AES + RSA) ---
def high_encrypt(message: str) -> dict:
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = aes_cipher.encrypt(pad(message.encode(), AES.block_size))

    rsa_cipher = PKCS1_OAEP.new(GLOBAL_PUBLIC_KEY)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    bundle = _pack(encrypted_key, iv, encrypted_data, GLOBAL_PUBLIC_KEY.export_key())

    return {
        "bundle": base64.urlsafe_b64encode(bundle).decode(),
        "private_key": GLOBAL_PRIVATE_KEY
    }

def high_decrypt(bundle_str: str, private_key_pem: str = None) -> str:
    fixed_str = fix_base64_padding(bundle_str)
    raw = base64.urlsafe_b64decode(fixed_str.encode())
    encrypted_key, iv, encrypted_data, _pub = _unpack(raw, 4)

    rsa_key = RSA.import_key((private_key_pem or GLOBAL_PRIVATE_KEY).encode())
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_key)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(aes_cipher.decrypt(encrypted_data), AES.block_size).decode()

# --- Public API ---
def encrypt_message(message: str, level: str) -> dict:
    level = level.lower()
    if level == "low":
        return {"bundle": low_encrypt(message), "private_key": None}
    elif level == "medium":
        return {"bundle": medium_encrypt(message), "private_key": None}
    elif level == "high":
        return high_encrypt(message)
    else:
        raise ValueError(f"Unknown sensitivity level: {level}")

def decrypt_message(bundle_str: str, level: str, private_key_pem: str = None) -> str:
    level = level.lower()
    if level == "low":
        return low_decrypt(bundle_str, key=private_key_pem)
    elif level == "medium":
        return medium_decrypt(bundle_str)
    elif level == "high":
        return high_decrypt(bundle_str, private_key_pem)
    else:
        raise ValueError(f"Unknown sensitivity level '{level}'")


# --- Message classifier ---
def classify_message(message: str) -> dict:
    """
    Classify a message into low / medium / high confidentiality.
    Returns dict with:
    - label: descriptive label
    - encryption: suggested encryption method
    - mapped_conf: 'low', 'medium', 'high' for DB usage
    """
    text = message.lower()

    if any(word in text for word in ["password", "key", "secret", "confidential", "private"]):
        return {"label": "high_confidential", "encryption": "RSA+AES", "mapped_conf": "high"}
    elif any(word in text for word in ["exam", "marks", "salary", "project", "document"]):
        return {"label": "medium_confidential", "encryption": "AES", "mapped_conf": "medium"}
    else:
        return {"label": "low_confidential", "encryption": "Fernet", "mapped_conf": "low"}
