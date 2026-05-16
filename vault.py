"""
vault.py — Gestion du dossier CRYPTEUR/ sur la clé USB.
Lecture, écriture, attempts.lock signé.
"""

import base64
import json
import os
from datetime import datetime
from pathlib import Path

from config import (
    USB_FOLDER, DEVICE_ID_FILE, KEY_VAULT_FILE,
    META_FILE,
)


# ── Chemins ───────────────────────────────────────────────────────────────────

def usb_folder_path(drive_root: str) -> Path:
    return Path(drive_root) / USB_FOLDER


def is_usb_initialized(drive_root: str) -> bool:
    """Vérifie que les trois fichiers obligatoires sont présents sur la USB."""
    folder   = usb_folder_path(drive_root)
    required = [DEVICE_ID_FILE, KEY_VAULT_FILE, META_FILE]
    return all((folder / f).exists() for f in required)


# ── Lecture ───────────────────────────────────────────────────────────────────

def read_usb_files(drive_root: str) -> dict:
    """
    Lit les fichiers du dossier CRYPTEUR/.
    Retourne un dict avec device_id, key_vault, attempts, meta.
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


# ── Écriture ──────────────────────────────────────────────────────────────────

def write_vault_files(
    drive_root: str,
    device_id: bytes,
    key_vault: dict,
):
    """
    Écrit device.id, key.vault, attempts.lock (compteur = 0) et meta.json.
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


# ── Nettoyage des fichiers temporaires orphelins ──────────────────────────────

def cleanup_orphan_tmp(folder_path: str):
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