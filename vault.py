"""
vault.py — Gestion du dossier CRYPTEUR/ sur la clé USB.
Lecture, écriture, attempts.lock signé HMAC, logs USB, dossier caché.
"""

import json
import os
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from config import (
    USB_FOLDER, DEVICE_ID_FILE, KEY_VAULT_FILE,
    META_FILE, ATTEMPTS_FILE, LOGS_FOLDER,
    MAX_PIN_ATTEMPTS,
)
from crypto import sign_data, verify_signature


# ── Chemins ───────────────────────────────────────────────────────────────────

def usb_folder_path(drive_root: str) -> Path:
    return Path(drive_root) / USB_FOLDER


def usb_logs_path(drive_root: str) -> Path:
    return usb_folder_path(drive_root) / LOGS_FOLDER


def is_usb_initialized(drive_root: str) -> bool:
    """Vérifie que les trois fichiers obligatoires sont présents sur la USB."""
    folder   = usb_folder_path(drive_root)
    required = [DEVICE_ID_FILE, KEY_VAULT_FILE, META_FILE]
    return all((folder / f).exists() for f in required)


# ── Lecture ───────────────────────────────────────────────────────────────────

def read_usb_files(drive_root: str) -> dict:
    """
    Lit les fichiers du dossier CRYPTEUR/.
    Retourne un dict avec device_id, key_vault, meta.
    Lève RuntimeError si un fichier est manquant ou illisible.
    """
    folder = usb_folder_path(drive_root)
    try:
        device_id = (folder / DEVICE_ID_FILE).read_bytes()
        key_vault = json.loads((folder / KEY_VAULT_FILE).read_text("utf-8"))
        meta      = json.loads((folder / META_FILE).read_text("utf-8"))
        return {
            "device_id": device_id,
            "key_vault": key_vault,
            "meta":      meta,
        }
    except Exception as e:
        raise RuntimeError(f"Erreur de lecture USB : {e}")


# ── Écriture initiale ─────────────────────────────────────────────────────────

def write_vault_files(
    drive_root: str,
    device_id: bytes,
    key_vault: dict,
):
    """
    Écrit device.id, key.vault, attempts.lock (compteur = 0) et meta.json.
    Crée le sous-dossier logs/.
    Masque le dossier CRYPTEUR/ sur Windows (attributs H+S).
    Appelé uniquement lors de l'initialisation.
    """
    folder = usb_folder_path(drive_root)
    folder.mkdir(parents=True, exist_ok=True)

    (folder / DEVICE_ID_FILE).write_bytes(device_id)
    (folder / KEY_VAULT_FILE).write_text(
        json.dumps(key_vault, indent=2), encoding="utf-8"
    )
    (folder / META_FILE).write_text(
        json.dumps({
            "version":    1,
            "created_at": datetime.now().isoformat(),
            "drive":      drive_root,
        }, indent=2),
        encoding="utf-8",
    )

    # Initialiser le compteur de tentatives à 0
    write_attempts(drive_root, device_id, 0)

    # Créer le dossier de logs sur la USB
    usb_logs_path(drive_root).mkdir(parents=True, exist_ok=True)

    # Masquer le dossier CRYPTEUR/ sur Windows
    _hide_folder(str(folder))


# ── Verrou de tentatives PIN (HMAC-SHA256) ────────────────────────────────────
#
# Format du fichier attempts.lock :
#   [4 octets big-endian] compteur de tentatives échouées
#   [32 octets]           HMAC-SHA256(compteur, device_id)
#
# La signature lie le compteur au device_id de la USB physique.
# Toute modification du fichier (reset manuel, falsification) invalide le HMAC
# → le programme refuse de continuer et traite le cas comme un verrou.

_ATTEMPTS_STRUCT = struct.Struct(">I")   # unsigned int 32 bits big-endian


def _attempts_hmac_key(device_id: bytes) -> bytes:
    """Clé HMAC dérivée du device_id (domaine séparé via préfixe)."""
    return b"attempts:" + device_id


def read_attempts(drive_root: str, device_id: bytes) -> int:
    """
    Lit le compteur de tentatives depuis attempts.lock.
    - Fichier absent → retourne 0 (première utilisation).
    - Signature invalide → retourne MAX_PIN_ATTEMPTS (verrou par sécurité).
    """
    path = usb_folder_path(drive_root) / ATTEMPTS_FILE
    if not path.exists():
        # Si key.vault a été détruit (verrouillage définitif), attempts.lock
        # a aussi été supprimé — on traite l'absence comme un verrou.
        vault_path = usb_folder_path(drive_root) / KEY_VAULT_FILE
        if not vault_path.exists():
            return MAX_PIN_ATTEMPTS
        # USB vierge non encore initialisée → premier usage normal
        return 0

    try:
        data      = path.read_bytes()
        count_raw = data[:4]
        signature = data[4:36]

        if not verify_signature(count_raw, signature, _attempts_hmac_key(device_id)):
            # Fichier falsifié ou corrompu → verrouillage
            return MAX_PIN_ATTEMPTS

        return _ATTEMPTS_STRUCT.unpack(count_raw)[0]

    except Exception:
        return MAX_PIN_ATTEMPTS


def write_attempts(drive_root: str, device_id: bytes, count: int):
    """Écrit le compteur signé dans attempts.lock."""
    path      = usb_folder_path(drive_root) / ATTEMPTS_FILE
    count_raw = _ATTEMPTS_STRUCT.pack(count)
    signature = sign_data(count_raw, _attempts_hmac_key(device_id))
    path.write_bytes(count_raw + signature)


def reset_attempts(drive_root: str, device_id: bytes):
    """Remet le compteur à 0 après une authentification réussie."""
    write_attempts(drive_root, device_id, 0)


def is_locked(drive_root: str, device_id: bytes) -> bool:
    """Retourne True si le nombre de tentatives a atteint la limite."""
    return read_attempts(drive_root, device_id) >= MAX_PIN_ATTEMPTS


def destroy_key_vault(drive_root: str):
    """
    Destruction cryptographique irréversible de key.vault.

    Séquence :
      1. Écraser le fichier avec des octets aléatoires (même taille)
         pour éliminer la clé AES chiffrée des secteurs disque.
      2. Supprimer le fichier.
      3. Supprimer attempts.lock (devenu inutile).

    Après cette opération, les fichiers chiffrés avec cette USB sont
    définitivement inaccessibles, même en connaissant le PIN.
    """
    folder = usb_folder_path(drive_root)

    # ── Écrasement sécurisé de key.vault ─────────────────────────────────────
    vault_path = folder / KEY_VAULT_FILE
    try:
        if vault_path.exists():
            size = vault_path.stat().st_size
            # Trois passes pour réduire les chances de récupération physique
            with open(vault_path, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            vault_path.unlink()
    except Exception:
        # En dernier recours : suppression sans écrasement
        try:
            vault_path.unlink(missing_ok=True)
        except Exception:
            pass

    # ── Suppression de attempts.lock ──────────────────────────────────────────
    attempts_path = folder / ATTEMPTS_FILE
    try:
        attempts_path.unlink(missing_ok=True)
    except Exception:
        pass


# ── Masquage du dossier CRYPTEUR ──────────────────────────────────────────────

def _hide_folder(folder_path: str):
    """
    Masque le dossier CRYPTEUR/ pour éviter une suppression accidentelle.

    - Windows : attributs Caché (H) + Système (S) via attrib.exe.
      Le dossier n'apparaît plus dans l'Explorateur par défaut.

    - Linux/macOS : pas de standard équivalent sans renommer le dossier.
      On affiche un avertissement à la place (renommer en .CRYPTEUR
      casserait la compatibilité avec les clés déjà initialisées).
    """
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["attrib", "+H", "+S", folder_path],
                check=True,
                capture_output=True,
            )
        except Exception:
            pass   # Échec silencieux : le dossier reste visible mais fonctionnel


def ensure_folder_hidden(drive_root: str):
    """
    Re-applique le masquage à chaque connexion de la USB.
    Utile si l'attribut a été retiré manuellement ou après un scandisk.
    """
    folder = usb_folder_path(drive_root)
    if folder.exists():
        _hide_folder(str(folder))


# ── Nettoyage des fichiers temporaires orphelins ──────────────────────────────

def cleanup_orphan_tmp(folder_path: str) -> list[str]:
    """
    Supprime les fichiers *.tmp orphelins laissés par une interruption
    du programme lors d'un chiffrement/déchiffrement précédent.
    Retourne la liste des fichiers supprimés.
    """
    removed = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".tmp"):
                path = os.path.join(root, file)
                try:
                    os.remove(path)
                    removed.append(path)
                except OSError:
                    pass
    return removed