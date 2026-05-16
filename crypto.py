"""
crypto.py — Primitives cryptographiques.
AES-256-GCM, scrypt, HMAC-SHA256.
"""

import hmac
import os
from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config import (
    IV_SIZE, TAG_SIZE, SALT_SIZE,
    SCRYPT_N, SCRYPT_R, SCRYPT_P,
)


# ── Dérivation de clé ─────────────────────────────────────────────────────────

def derive_key(data: bytes, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 (32 octets) via scrypt.
    Paramètres configurables dans config.py (SCRYPT_N, SCRYPT_R, SCRYPT_P).
    """
    kdf = Scrypt(
        salt=salt, length=32,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(data)


def derive_master_key(pin: str, uuid_partition: str, device_id: bytes) -> bytes:
    """
    Dérive la clé maître qui protège key.vault.
    Combine PIN (utilisateur) + UUID_partition (USB) + device_id (USB).
    Aucun des trois seuls ne suffit à reconstituer la clé.
    """
    salt     = sha256(uuid_partition.encode("utf-8") + device_id).digest()[:SALT_SIZE]
    material = pin.encode("utf-8") + uuid_partition.encode("utf-8") + device_id
    return derive_key(material, salt)


def derive_file_key(aes_key: bytes, salt: bytes) -> bytes:
    """
    Dérive une sous-clé unique par fichier depuis la clé AES de la USB.
    Garantit que deux fichiers chiffrés avec la même USB ont des clés différentes.
    """
    return derive_key(aes_key + salt, salt)


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Chiffre avec AES-256-GCM.
    Retourne : iv (12) + tag (16) + ciphertext.
    """
    iv     = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    enc    = cipher.encryptor()
    ct     = enc.update(plaintext) + enc.finalize()
    return iv + enc.tag + ct


def aes_gcm_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Déchiffre AES-256-GCM.
    Lève cryptography.exceptions.InvalidTag si la clé ou le tag est incorrect.
    """
    iv  = data[:IV_SIZE]
    tag = data[IV_SIZE:IV_SIZE + TAG_SIZE]
    ct  = data[IV_SIZE + TAG_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    dec    = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────

def sign_data(data: bytes, secret: bytes) -> bytes:
    """Signe des données avec HMAC-SHA256."""
    return hmac.new(secret, data, sha256).digest()


def verify_signature(data: bytes, signature: bytes, secret: bytes) -> bool:
    """Vérifie une signature HMAC-SHA256 de façon résistante aux attaques temporelles."""
    expected = hmac.new(secret, data, sha256).digest()
    return hmac.compare_digest(expected, signature)