# app/encryption_utils.py
import os
import base64
import struct
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)

# Helper pack/unpack (length-prefixed) — robust to binary segments
def _pack(*parts: bytes) -> bytes:
    return b"".join(struct.pack("!I", len(p)) + p for p in parts)

def _unpack(raw: bytes, expected_parts: int):
    parts = []
    cur = raw
    for _ in range(expected_parts):
        if len(cur) < 4:
            raise ValueError("Corrupted bundle: missing length header")
        length = struct.unpack("!I", cur[:4])[0]
        cur = cur[4:]
        if len(cur) < length:
            raise ValueError("Corrupted bundle: missing data")
        part, cur = cur[:length], cur[length:]
        parts.append(part)
    return parts

def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()

def _b64decode(s: str) -> bytes:
    # fix padding
    rem = len(s) % 4
    if rem:
        s = s + "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode())

# -----------------------
# Low: Fernet (symmetric)
# Returns: dict with 'bundle' (single base64 string) and 'private_key' = fernet key (base64 urlsafe)
# -----------------------
def low_encrypt(message: str):
    key = Fernet.generate_key()  # bytes
    f = Fernet(key)
    token = f.encrypt(message.encode())
    bundle = _pack(key, token)
    return {"bundle": _b64encode(bundle), "private_key": key.decode(), "algo": "Fernet"}

def low_decrypt(bundle_str: str, private_key: str = None):
    raw = _b64decode(bundle_str)
    key_in_bundle, token = _unpack(raw, 2)
    key_bytes = private_key.encode() if private_key else key_in_bundle
    f = Fernet(key_bytes)
    return f.decrypt(token).decode()

# -----------------------
# Medium: AES-GCM
# Returns: bundle base64, store AES key in private_key (base64)
# -----------------------
def medium_encrypt(message: str):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), None)
    bundle = _pack(key, nonce, ct)
    return {"bundle": _b64encode(bundle), "private_key": base64.urlsafe_b64encode(key).decode(), "algo": "AES-GCM"}

def medium_decrypt(bundle_str: str, private_key: str = None):
    raw = _b64decode(bundle_str)
    key, nonce, ct = _unpack(raw, 3)
    # prefer provided private_key (string base64), else use key from bundle
    if private_key:
        key = base64.urlsafe_b64decode(private_key.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

# -----------------------
# High: AES-CBC + RSA (hybrid)
# We generate a new ephemeral RSA keypair per message here, and return private_key (PEM) and bundle (encrypted_key + iv + ct + pub)
# Note: in production you'd use persistent keys or KMS; for now we store private_key in DB (as you've been doing).
# -----------------------
def high_encrypt(message: str):
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(message.encode(), AES.block_size))

    rsa_key = RSA.generate(2048)
    pub = rsa_key.publickey()
    rsa_cipher = PKCS1_OAEP.new(pub)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # pack: encrypted_aes_key || iv || ciphertext || pub_pem
    bundle = _pack(encrypted_aes_key, iv, ciphertext, pub.export_key())
    private_key_pem = rsa_key.export_key().decode()

    return {"bundle": _b64encode(bundle), "private_key": private_key_pem, "algo": "RSA-AES-HYBRID"}

def high_decrypt(bundle_str: str, private_key_pem: str):
    if not private_key_pem:
        raise ValueError("private_key_pem required for high decryption")
    raw = _b64decode(bundle_str)
    encrypted_aes_key, iv, ciphertext, pub_pem = _unpack(raw, 4)
    rsa_key = RSA.import_key(private_key_pem.encode())
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plain = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return plain.decode()

# -----------------------
# Public dispatcher API (consistent return)
# encrypt_message returns dict:
#   { "bundle": base64str, "private_key": str or None, "algo": "Fernet"/"AES-GCM"/"RSA-AES-HYBRID" }
# decrypt_message(bundle, classification, private_key=None) -> plaintext
# -----------------------
def encrypt_message(message: str, level: str):
    level = (level or "low").lower()
    if level == "low":
        return low_encrypt(message)
    elif level == "medium":
        return medium_encrypt(message)
    elif level == "high":
        return high_encrypt(message)
    else:
        raise ValueError(f"Unknown sensitivity level '{level}'")

def decrypt_message(bundle_str: str, level: str, private_key: str = None):
    level = (level or "low").lower()
    if level == "low":
        return low_decrypt(bundle_str, private_key)
    elif level == "medium":
        return medium_decrypt(bundle_str, private_key)
    elif level == "high":
        return high_decrypt(bundle_str, private_key)
    else:
        raise ValueError(f"Unknown sensitivity level '{level}'")
