import os
import base64
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


# Utility for packing/unpacking with length prefix
def _pack(*parts):
    return b"".join(struct.pack("!I", len(p)) + p for p in parts)


def _unpack(raw, expected_parts):
    parts = []
    for _ in range(expected_parts):
        length = struct.unpack("!I", raw[:4])[0]
        raw = raw[4:]
        part, raw = raw[:length], raw[length:]
        parts.append(part)
    return parts


# ---------------------------
# LOW SECURITY (Fernet)
# ---------------------------
def low_encrypt(message: str) -> str:
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(message.encode())
    return base64.urlsafe_b64encode(_pack(key, token)).decode()


def low_decrypt(bundle_str: str) -> str:
    raw = base64.urlsafe_b64decode(bundle_str.encode())
    key, token = _unpack(raw, 2)
    f = Fernet(key)
    return f.decrypt(token).decode()


# ---------------------------
# MEDIUM SECURITY (AES-GCM)
# ---------------------------
def medium_encrypt(message: str) -> str:
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), None)
    return base64.urlsafe_b64encode(_pack(key, nonce, ct)).decode()


def medium_decrypt(bundle_str: str) -> str:
    raw = base64.urlsafe_b64decode(bundle_str.encode())
    key, nonce, ct = _unpack(raw, 3)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()


# ---------------------------
# HIGH SECURITY (RSA + AES hybrid)
# ---------------------------
def high_encrypt(message: str) -> tuple[str, str]:
    # Generate AES key
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt message with AES-CBC
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = aes_cipher.encrypt(pad(message.encode(), AES.block_size))

    # Generate RSA keypair (ephemeral) – in production, use persistent keys
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()

    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    # Export private key (⚠️ should be stored securely)
    private_key = rsa_key.export_key()

    # Pack encrypted AES key + IV + ciphertext + public key
    bundle = _pack(encrypted_key, iv, encrypted_data, public_key.export_key())
    return base64.urlsafe_b64encode(bundle).decode(), private_key.decode()


def high_decrypt(bundle_str: str, private_key_pem: str) -> str:
    raw = base64.urlsafe_b64decode(bundle_str.encode())
    encrypted_key, iv, encrypted_data, _pub = _unpack(raw, 4)

    rsa_key = RSA.import_key(private_key_pem.encode())
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_key)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(aes_cipher.decrypt(encrypted_data), AES.block_size).decode()


# ---------------------------
# Dispatcher (AI integration)
# ---------------------------
def encrypt_message(message: str, level: str):
    level = level.lower()
    if level == "low":
        return low_encrypt(message)
    elif level == "medium":
        return medium_encrypt(message)
    elif level == "high":
        bundle, private_key = high_encrypt(message)
        # Return both bundle and private key
        return {"bundle": bundle, "private_key": private_key}
    else:
        raise ValueError("Unknown sensitivity level")


def decrypt_message(bundle_str: str, level: str, private_key_pem: str = None) -> str:
    level = level.lower()
    if level == "low":
        return low_decrypt(bundle_str)
    elif level == "medium":
        return medium_decrypt(bundle_str)
    elif level == "high":
        if not private_key_pem:
            raise ValueError("Private key required for high security decryption")
        return high_decrypt(bundle_str, private_key_pem)
    else:
        raise ValueError("Unknown sensitivity level")


# ---------------------------
# Example Usage
# ---------------------------
if __name__ == "__main__":
    msg = "Hello Secure World!"

    # Low Security
    enc = encrypt_message(msg, "low")
    print("Low Enc:", enc)
    print("Low Dec:", decrypt_message(enc, "low"))

    # Medium Security
    enc = encrypt_message(msg, "medium")
    print("Medium Enc:", enc)
    print("Medium Dec:", decrypt_message(enc, "medium"))

    # High Security
    result = encrypt_message(msg, "high")
    enc_bundle = result["bundle"]
    priv_key = result["private_key"]
    print("High Enc:", enc_bundle)
    print("High Dec:", decrypt_message(enc_bundle, "high", priv_key))
