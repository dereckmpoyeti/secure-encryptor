"""
config.py — Constantes et paramètres de configuration.
Toutes les valeurs modifiables sont ici.
"""

# ── Cryptographie ─────────────────────────────────────────────────────────────
MAGIC           = b"ENCRYPTED"
FORMAT_VERSION  = b"\x01"
SALT_SIZE       = 16        # octets
IV_SIZE         = 12        # octets (96 bits, standard GCM)
TAG_SIZE        = 16        # octets (128 bits)
CHUNK_SIZE      = 1024 * 1024   # 1 Mo par bloc de lecture/écriture
SCRYPT_N        = 2 ** 17   # Coût CPU/mémoire scrypt (augmenter = plus lent = plus sûr)
SCRYPT_R        = 8
SCRYPT_P        = 1

# ── Clé USB ───────────────────────────────────────────────────────────────────
USB_FOLDER       = "CRYPTEUR"
DEVICE_ID_FILE   = "device.id"
KEY_VAULT_FILE   = "key.vault"
META_FILE        = "meta.json"
ATTEMPTS_FILE    = "attempts.lock"   # Compteur de tentatives PIN signé (HMAC)
PIN_LENGTH       = 8                 # Longueur exacte du PIN (chiffres uniquement)
MAX_PIN_ATTEMPTS = 5                 # Tentatives PIN avant verrouillage définitif


# ── Rapports ──────────────────────────────────────────────────────────────────
LOGS_FOLDER = "logs"   # Sous-dossier de logs dans CRYPTEUR/ sur la clé USB