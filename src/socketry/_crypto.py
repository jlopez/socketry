"""Internal cryptographic helpers for Jackery API authentication."""

from __future__ import annotations

import base64
import uuid

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES/ECB/PKCS5Padding encryption (used for HTTP login body)."""
    cipher = AES.new(key, AES.MODE_ECB)
    result: bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return result


def rsa_encrypt(plaintext: bytes, pub_key_b64: str) -> bytes:
    """RSA/ECB/PKCS1Padding encryption (used for encrypting AES key)."""
    der = base64.b64decode(pub_key_b64)
    key = RSA.import_key(der)
    cipher = PKCS1_v1_5.new(key)
    result: bytes = cipher.encrypt(plaintext)
    return result


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES/CBC/PKCS5Padding encryption (used for MQTT password derivation)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result: bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return result


def derive_mqtt_password(username: str, mqtt_password_b64: str) -> str:
    """Derive the MQTT connection password from the stored mqttPassWord.

    The app does: AES/CBC/PKCS5Padding(username, key=b64decode(mqttPassWord), iv=key[:16])
    then base64-encodes the result and sends it as the MQTT password string.
    """
    key = base64.b64decode(mqtt_password_b64)
    iv = key[:16]
    encrypted = aes_cbc_encrypt(username.encode("utf-8"), key, iv)
    return base64.b64encode(encrypted).decode("ascii")


def get_mac_id() -> str:
    """Generate a stable MAC-like identifier for this machine."""
    node = uuid.getnode()
    return ":".join(f"{(node >> (8 * i)) & 0xFF:02x}" for i in range(5, -1, -1))
