"""
processor.py — Chiffrement/déchiffrement de fichiers et dossiers.
Rapport détaillé horodaté, indicateur de progression en Mo/s.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path

from colorama import Fore
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tqdm import tqdm

from config import (
    MAGIC, FORMAT_VERSION, SALT_SIZE, IV_SIZE,
    TAG_SIZE, CHUNK_SIZE,
)
from crypto import derive_file_key
from display import format_size, print_error, print_info, print_success, print_warning

logger = logging.getLogger(__name__)


# ── Helpers fichiers ──────────────────────────────────────────────────────────

def is_encrypted_file(file_path: str) -> bool:
    """Vérifie si un fichier commence par le magic header ENCRYPTED."""
    try:
        with open(file_path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def get_output_path(input_file: str, operation: str) -> str:
    if operation == "encrypt":
        return input_file + ".encrypted"
    if input_file.endswith(".encrypted"):
        return input_file[:-len(".encrypted")]
    return input_file


def validate_folder_path(path: str) -> tuple[str | None, str | None]:
    if not path:
        return None, "Chemin vide."
    p = Path(path).resolve()
    if not p.exists():
        return None, f"'{p}' n'existe pas."
    if not p.is_dir():
        return None, f"'{p}' n'est pas un dossier."
    try:
        list(p.iterdir())
    except PermissionError:
        return None, f"Accès refusé à '{p}'."
    return str(p), None


# ── Chiffrement / Déchiffrement unitaire ──────────────────────────────────────

def encrypt_file(input_file: str, aes_key: bytes) -> int:
    """
    Chiffre un fichier avec AES-256-GCM.
    Retourne la taille du fichier source en octets.
    """
    from cryptography.hazmat.backends import default_backend
    salt = os.urandom(SALT_SIZE)
    iv   = os.urandom(IV_SIZE)
    file_key  = derive_file_key(aes_key, salt)
    cipher    = Cipher(algorithms.AES(file_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    output    = get_output_path(input_file, "encrypt")
    temp      = output + ".tmp"
    size      = os.path.getsize(input_file)

    try:
        with open(input_file, "rb") as src, open(temp, "wb") as dst:
            dst.write(MAGIC + FORMAT_VERSION + salt + iv)
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(encryptor.update(chunk))
            encryptor.finalize()
            dst.write(encryptor.tag)

        os.replace(temp, output)

        # Effacement sécurisé du fichier source
        _secure_delete(input_file)

    except Exception:
        if os.path.exists(temp):
            os.remove(temp)
        raise

    return size


def decrypt_file(input_file: str, aes_key: bytes) -> int:
    """
    Déchiffre un fichier chiffré par encrypt_file.
    Retourne la taille du fichier chiffré en octets.
    Ignore les fichiers non chiffrés silencieusement.
    """
    if not is_encrypted_file(input_file):
        return 0

    output = get_output_path(input_file, "decrypt")
    temp   = output + ".tmp"
    size   = os.path.getsize(input_file)

    try:
        with open(input_file, "rb") as src:
            if src.read(len(MAGIC)) != MAGIC:
                return 0

            version = src.read(1)
            if version != FORMAT_VERSION:
                raise ValueError("Format non supporté par cette version.")

            salt = src.read(SALT_SIZE)
            iv   = src.read(IV_SIZE)

            header_size     = len(MAGIC) + 1 + SALT_SIZE + IV_SIZE
            ciphertext_size = size - header_size - TAG_SIZE

            if ciphertext_size < 0:
                raise ValueError("Fichier chiffré invalide ou incomplet.")

            src.seek(size - TAG_SIZE)
            tag = src.read(TAG_SIZE)
            src.seek(header_size)

            file_key  = derive_file_key(aes_key, salt)
            cipher    = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            remaining = ciphertext_size

            with open(temp, "wb") as dst:
                while remaining > 0:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    dst.write(decryptor.update(chunk))
                decryptor.finalize()

        os.replace(temp, output)

        # Effacement sécurisé du fichier chiffré source
        if output != input_file:
            _secure_delete(input_file)

    except InvalidTag:
        if os.path.exists(temp):
            os.remove(temp)
        raise ValueError("Clé incorrecte ou fichier corrompu.")
    except Exception:
        if os.path.exists(temp):
            os.remove(temp)
        raise

    return size


def _secure_delete(path: str):
    """
    Écrase le contenu d'un fichier avec des données aléatoires avant suppression.

    3 passes avec flush() + fsync() à chaque passe pour forcer l'écriture
    physique sur le support — même logique que destroy_key_vault() dans vault.py.

    Limites connues :
      - SSD/flash : le wear leveling du contrôleur peut rediriger les écritures
        vers d'autres cellules physiques. Ces 3 passes réduisent le risque mais
        ne l'éliminent pas complètement sur ces supports.
      - Pour une protection maximale, chiffrez le disque au niveau OS
        (BitLocker, LUKS, FileVault).
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        # En dernier recours, suppression classique
        try:
            os.remove(path)
        except Exception:
            pass


# ── Test de la clé avant traitement massif ────────────────────────────────────

def test_decryption_key(files: list[str], aes_key: bytes) -> bool:
    """
    Teste la clé sur le premier fichier chiffré de la liste.
    Évite de lancer un déchiffrement massif avec une mauvaise clé.
    """
    if not files:
        return True

    test = files[0]
    try:
        with open(test, "rb") as src:
            if src.read(len(MAGIC)) != MAGIC:
                return True

            version = src.read(1)
            if version != FORMAT_VERSION:
                return False

            salt = src.read(SALT_SIZE)
            iv   = src.read(IV_SIZE)
            size = os.path.getsize(test)

            header_size     = len(MAGIC) + 1 + SALT_SIZE + IV_SIZE
            ciphertext_size = size - header_size - TAG_SIZE
            if ciphertext_size < 0:
                return False

            src.seek(size - TAG_SIZE)
            tag = src.read(TAG_SIZE)
            src.seek(header_size)

            file_key  = derive_file_key(aes_key, salt)
            cipher    = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            remaining = ciphertext_size
            while remaining > 0:
                chunk = src.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                decryptor.update(chunk)
            decryptor.finalize()
            return True

    except InvalidTag:
        return False
    except Exception:
        return False


# ── Traitement de dossier ─────────────────────────────────────────────────────

def process_folder(
    folder_path: str,
    aes_key: bytes,
    operation: str = "encrypt",
    logs_dir: str = "logs",
) -> dict:
    """
    Parcourt récursivement un dossier et chiffre ou déchiffre chaque fichier.
    Affiche une barre de progression avec débit en Mo/s.
    Écrit un rapport JSON horodaté dans LOGS_DIR.
    Retourne un dict de statistiques.
    """
    from vault import cleanup_orphan_tmp

    start = time.time()
    label_op = "Chiffrement" if operation == "encrypt" else "Déchiffrement"

    stats = {
        "folder":        folder_path,
        "operation":     label_op,
        "files_count":   0,
        "success_count": 0,
        "error_count":   0,
        "total_size":    0,
        "throughput":    "N/A",
        "duration":      "N/A",
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_path":      "N/A",
        "errors":        [],
    }

    # Nettoyage des .tmp orphelins avant de commencer
    removed_tmp = cleanup_orphan_tmp(folder_path)
    if removed_tmp:
        print_warning(f"{len(removed_tmp)} fichier(s) temporaire(s) orphelin(s) supprimé(s).")

    # Collecte des fichiers à traiter
    files_to_process = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            path = os.path.join(root, file)

            # Exclure les fichiers temporaires et les fichiers du coffre USB
            if file.endswith(".tmp"):
                continue

            try:
                stats["total_size"] += os.path.getsize(path)
            except OSError:
                pass

            if operation == "encrypt":
                if not file.endswith(".encrypted"):
                    files_to_process.append(path)
            else:
                if is_encrypted_file(path):
                    files_to_process.append(path)

    stats["files_count"] = len(files_to_process)

    if not files_to_process:
        print_warning("Aucun fichier à traiter.")
        return stats

    # Validation de la clé avant traitement massif (déchiffrement uniquement)
    if operation == "decrypt":
        print_info("Validation de la clé sur un fichier test...")
        if not test_decryption_key(files_to_process, aes_key):
            print_error("La clé USB ne correspond pas à ces fichiers chiffrés.")
            return stats
        print_success("Clé validée.")

    print(f"""
{Fore.CYAN}Traitement :{Fore.WHITE}
  Dossier    : {folder_path}
  Fichiers   : {stats['files_count']}
  Taille     : {format_size(stats['total_size'])}
""")

    # Barre de progression avec débit
    bytes_done = 0
    bar_format = (
        "{l_bar}{bar}| {n_fmt}/{total_fmt} fichiers "
        "[{elapsed}<{remaining}, {postfix}]"
    )

    with tqdm(
        total=len(files_to_process),
        desc=label_op,
        bar_format=bar_format,
        unit="f",
    ) as pbar:
        for path in files_to_process:
            try:
                if operation == "encrypt":
                    size = encrypt_file(path, aes_key)
                else:
                    size = decrypt_file(path, aes_key)
                bytes_done += size
                stats["success_count"] += 1
            except Exception as e:
                err_msg = f"{path} — {e}"
                logger.error(f"Échec : {err_msg}")
                stats["error_count"] += 1
                stats["errors"].append(err_msg)

            elapsed = time.time() - start
            throughput = bytes_done / elapsed if elapsed > 0 else 0
            pbar.set_postfix_str(f"{format_size(int(throughput))}/s")
            pbar.update(1)

    duration = time.time() - start
    throughput_avg = bytes_done / duration if duration > 0 else 0
    stats["duration"]   = f"{duration:.1f}s"
    stats["throughput"] = f"{format_size(int(throughput_avg))}/s"

    print(f"""
{Fore.GREEN}Traitement terminé !{Fore.WHITE}
  Succès  : {stats['success_count']}
  Échecs  : {stats['error_count']}
  Débit   : {stats['throughput']}
  Durée   : {stats['duration']}
""")

    # Rapport JSON horodaté dans le dossier logs/ de la clé USB
    stats["log_path"] = _write_report(stats, logs_dir)

    return stats



# ── Mode détresse ─────────────────────────────────────────────────────────────

def fake_process_folder(
    folder_path: str,
    drive_root: str,
    logs_dir: str = "logs",
) -> dict:
    """
    Simule un déchiffrement convaincant pour le mode détresse (duress PIN).

    Ce qui se passe réellement :
      - Les fichiers .encrypted sont renommés sans leur extension
        (le contenu reste chiffré — seul le nom change).
      - Une fausse barre de progression s'affiche à vitesse réaliste.
      - key.vault est détruit en 3 passes dans un thread parallèle
        pendant la progression — sans bloquer l'affichage.
      - Un rapport JSON falsifié est écrit dans logs/.
      - Un message d'erreur générique est affiché à la fin pour
        orienter l'attaquant vers une fausse piste.

    L'attaquant voit des fichiers renommés sans extension .encrypted,
    une progression normale, et un message de fin standard.
    """
    from vault import destroy_key_vault

    start    = time.time()
    label_op = "Déchiffrement"

    stats = {
        "folder":        folder_path,
        "operation":     label_op,
        "files_count":   0,
        "success_count": 0,
        "error_count":   0,
        "total_size":    0,
        "throughput":    "N/A",
        "duration":      "N/A",
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_path":      "N/A",
        "errors":        [],
    }

    # Collecter les fichiers .encrypted à "traiter"
    files_to_process = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".tmp"):
                continue
            path = os.path.join(root, file)
            if is_encrypted_file(path):
                try:
                    stats["total_size"] += os.path.getsize(path)
                except OSError:
                    pass
                files_to_process.append(path)

    stats["files_count"] = len(files_to_process)

    if not files_to_process:
        print_warning("Aucun fichier à traiter.")
        return stats

    print(f"""
{Fore.CYAN}Traitement :{Fore.WHITE}
  Dossier    : {folder_path}
  Fichiers   : {stats["files_count"]}
  Taille     : {format_size(stats["total_size"])}
""")

    # ── Lancer la destruction de key.vault en arrière-plan ────────────────────
    destroy_thread = threading.Thread(
        target=destroy_key_vault,
        args=(drive_root,),
        daemon=True,
    )
    destroy_thread.start()

    # ── Fausse progression : renommer les fichiers + simuler le débit ─────────
    bytes_done = 0
    bar_format = (
        "{l_bar}{bar}| {n_fmt}/{total_fmt} fichiers "
        "[{elapsed}<{remaining}, {postfix}]"
    )

    with tqdm(
        total=len(files_to_process),
        desc=label_op,
        bar_format=bar_format,
        unit="f",
    ) as pbar:
        for path in files_to_process:
            try:
                file_size = os.path.getsize(path)

                # Renommer : retirer l'extension .encrypted
                output = get_output_path(path, "decrypt")
                if output != path:
                    os.rename(path, output)

                bytes_done += file_size
                stats["success_count"] += 1

            except Exception as e:
                stats["error_count"] += 1
                stats["errors"].append(f"{path} — {e}")

            elapsed    = time.time() - start
            throughput = bytes_done / elapsed if elapsed > 0 else 0
            pbar.set_postfix_str(f"{format_size(int(throughput))}/s")
            pbar.update(1)

    # S'assurer que la destruction est terminée avant de continuer
    destroy_thread.join(timeout=10)

    duration       = time.time() - start
    throughput_avg = bytes_done / duration if duration > 0 else 0
    stats["duration"]   = f"{duration:.1f}s"
    stats["throughput"] = f"{format_size(int(throughput_avg))}/s"

    # ── Message de fin trompeur ───────────────────────────────────────────────
    print(f"""
{Fore.GREEN}Traitement terminé !{Fore.WHITE}
  Succès  : {stats["success_count"]}
  Échecs  : {stats["error_count"]}
  Débit   : {stats["throughput"]}
  Durée   : {stats["duration"]}
""")
    print_warning(
        "Avertissement : certains fichiers semblent corrompus. "
        "Relancez --verify pour diagnostiquer."
    )

    # Rapport JSON dans logs/ (falsifié mais cohérent)
    stats["log_path"] = _write_report(stats, logs_dir)

    return stats


def _write_report(stats: dict, logs_dir: str) -> str:
    """
    Écrit un rapport JSON dans LOGS_DIR.
    Retourne le chemin du fichier de rapport.
    """
    try:
        os.makedirs(logs_dir, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        op_short = "enc" if stats["operation"] == "Chiffrement" else "dec"
        filename = f"{ts}_{op_short}.json"
        path     = os.path.join(logs_dir, filename)

        # Ne pas sérialiser le champ log_path lui-même dans le rapport
        report = {k: v for k, v in stats.items() if k != "log_path"}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return path
    except Exception:
        return "N/A"