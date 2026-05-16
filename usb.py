"""
usb.py — Détection USB, initialisation, déverrouillage, statut.
"""

import base64
import getpass
import os
import subprocess

from colorama import Fore

from config import (
    PIN_LENGTH,
    KEY_VAULT_FILE, DEVICE_ID_FILE,
)
from crypto import derive_master_key, aes_gcm_encrypt, aes_gcm_decrypt
from cryptography.exceptions import InvalidTag
from display import (
    typewriter, print_separator, print_success, print_error,
    print_warning, print_info,
)
from vault import (
    is_usb_initialized, read_usb_files, write_vault_files,
    usb_folder_path,
)

try:
    import ctypes
    WINDOWS = True
except ImportError:
    WINDOWS = False


# ── Détection USB ─────────────────────────────────────────────────────────────

def get_usb_drives() -> list[dict]:
    """
    Retourne la liste des lecteurs USB amovibles.
    Utilise psutil pour une détection fiable multiplateforme.
    Chaque entrée : {'letter', 'label', 'uuid', 'mountpoint'}
    """
    import psutil
    drives = []

    for partition in psutil.disk_partitions():
        opts       = partition.opts.lower()
        mountpoint = partition.mountpoint

        is_removable = (
            "removable" in opts
            or "/media" in mountpoint
            or "/mnt"   in mountpoint
        )
        if not is_removable:
            continue

        if WINDOWS:
            letter = mountpoint.rstrip("\\").rstrip("/")
            if not letter.endswith(":"):
                letter = partition.device.rstrip("\\")
        else:
            letter = mountpoint

        label = "USB"
        uuid  = ""

        if WINDOWS:
            try:
                result = subprocess.run(
                    ["wmic", "logicaldisk", "where",
                     f"DeviceID='{letter}'",
                     "get", "VolumeName,VolumeSerialNumber", "/format:csv"],
                    capture_output=True, text=True, timeout=5,
                )
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                if len(lines) >= 2:
                    parts = lines[-1].split(",")
                    if len(parts) >= 3:
                        label = parts[1].strip() if parts[1].strip() else "Sans nom"
                        uuid  = parts[2].strip()
            except Exception:
                pass

        drives.append({
            "letter":     letter,
            "label":      label,
            "uuid":       uuid,
            "mountpoint": mountpoint,
        })

    return drives


def get_usb_uuid(drive_letter: str) -> str:
    """
    Récupère le numéro de série du volume d'un lecteur Windows.
    Fallback via GetVolumeInformationW si WMIC échoue.
    """
    letter = drive_letter.rstrip("\\").rstrip("/")

    if WINDOWS:
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "where", f"DeviceID='{letter}'",
                 "get", "VolumeSerialNumber", "/format:csv"],
                capture_output=True, text=True, timeout=10,
            )
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if len(lines) >= 2:
                parts = lines[-1].split(",")
                if len(parts) >= 2 and parts[-1].strip():
                    return parts[-1].strip()
        except Exception:
            pass

        try:
            serial = ctypes.c_ulong(0)
            ret = ctypes.windll.kernel32.GetVolumeInformationW(
                letter + "\\", None, 0, ctypes.byref(serial),
                None, None, None, 0,
            )
            if ret:
                return format(serial.value, "08X")
        except Exception:
            pass

    return ""


def select_usb_drive() -> str | None:
    """
    Détecte les USB disponibles et demande à l'utilisateur de choisir.
    - Si une seule USB : demande confirmation avant de la sélectionner.
    - Si plusieurs USB : affiche la liste et demande un choix.
    - Si aucune USB : retourne None.
    Retourne le chemin racine du lecteur (ex: 'E:\\').
    """
    drives = get_usb_drives()

    if not drives:
        print_error("Aucune clé USB détectée. Branchez la clé et réessayez.")
        return None

    # Cas : une seule USB → demande confirmation
    if len(drives) == 1:
        d = drives[0]
        label = f"{d['letter']} — {d['label']}"
        if d["uuid"]:
            label += f"  (série: {d['uuid']})"
        print_info(f"Clé USB détectée : {label}")
        rep = input(f"{Fore.CYAN}Utiliser cette clé ? (O/n) :{Fore.WHITE} >> ").strip().lower()
        if rep in ("", "o", "oui", "y", "yes"):
            return d["letter"] + "\\"
        print_warning("Opération annulée.")
        return None

    # Cas : plusieurs USB → liste
    print(f"\n{Fore.CYAN}Clés USB disponibles :{Fore.WHITE}")
    for i, d in enumerate(drives, 1):
        uuid_str = f"  (série: {d['uuid']})" if d["uuid"] else ""
        print(f"  {i}. {d['letter']} — {d['label']}{uuid_str}")

    while True:
        rep = input(f"{Fore.CYAN}Votre choix (1-{len(drives)}) :{Fore.WHITE} >> ").strip()
        if rep.isdigit() and 1 <= int(rep) <= len(drives):
            return drives[int(rep) - 1]["letter"] + "\\"
        print_error("Choix invalide.")


# ── Validation du PIN ─────────────────────────────────────────────────────────

def validate_pin(pin: str) -> tuple[bool, str]:
    if len(pin) != PIN_LENGTH:
        return False, f"Le PIN doit faire exactement {PIN_LENGTH} chiffres."
    if not pin.isdigit():
        return False, "Le PIN ne doit contenir que des chiffres."
    return True, ""


def ask_pin(label: str = "PIN") -> str | None:
    """
    Demande le PIN de façon sécurisée.
    Utilise msvcrt sur Windows (compatible PowerShell/CMD)
    et getpass sur Linux/macOS.
    Retourne None si l'utilisateur annule avec Ctrl+C.
    """
    prompt = f"{Fore.CYAN}{label} ({PIN_LENGTH} chiffres) : {Fore.WHITE}"

    if WINDOWS:
        import msvcrt
        print(prompt, end="", flush=True)
        chars = []
        try:
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):   # Entrée
                    print()
                    break
                if ch == "\x03":          # Ctrl+C
                    print()
                    return None
                if ch == "\x08":          # Retour arrière
                    if chars:
                        chars.pop()
                        print("\b \b", end="", flush=True)
                else:
                    chars.append(ch)
                    print("*", end="", flush=True)
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        return "".join(chars).strip()

    else:
        try:
            pin = getpass.getpass(prompt)
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        return pin.strip()


# ── Initialisation ────────────────────────────────────────────────────────────

def initialize_usb(drive_root: str) -> bool:
    """
    Configure automatiquement une clé USB au premier usage :
    - Génère un device_id aléatoire (32 octets)
    - Génère une clé AES-256 totalement aléatoire
    - Demande un PIN à 8 chiffres (confirmé deux fois)
    - Chiffre la clé AES avec scrypt(PIN + UUID + device_id)
    - Écrit CRYPTEUR/ sur la USB
    Retourne True si succès, False si annulé.
    """
    print_separator()
    print_info("PREMIÈRE UTILISATION — Configuration de la clé USB")

    # UUID de la partition
    uuid_partition = get_usb_uuid(drive_root)
    if not uuid_partition:
        print_warning("UUID de partition introuvable. Utilisation d'un identifiant de secours.")
        uuid_partition = base64.b64encode(os.urandom(8)).decode("ascii")

    # device_id aléatoire
    device_id = os.urandom(32)

    # Saisie du PIN
    typewriter(f"\nDéfinissez un PIN à {PIN_LENGTH} chiffres.", color=Fore.YELLOW)

    while True:
        pin1 = ask_pin("Nouveau PIN")
        if pin1 is None:
            print_warning("Annulé.")
            return False

        ok, err = validate_pin(pin1)
        if not ok:
            print_error(err)
            continue

        pin2 = ask_pin("Confirmez le PIN")
        if pin2 is None:
            print_warning("Annulé.")
            return False

        if pin1 != pin2:
            print_error("Les PIN ne correspondent pas.")
            continue
        break

    # Clé AES aléatoire (jamais dérivée d'un mot de passe)
    aes_key    = os.urandom(32)
    master_key = derive_master_key(pin1, uuid_partition, device_id)
    encrypted  = aes_gcm_encrypt(aes_key, master_key)

    key_vault = {
        "version":        1,
        "uuid_partition": uuid_partition,
        "key_encrypted":  base64.b64encode(encrypted).decode("ascii"),
    }

    write_vault_files(drive_root, device_id, key_vault)

    print_success("Clé USB configurée avec succès !")
    typewriter("Conservez cette USB et votre PIN en lieu sûr.", color=Fore.YELLOW)
    typewriter("Perte de l'un ou l'autre = données définitivement inaccessibles.", color=Fore.RED)
    return True


# ── Déverrouillage ────────────────────────────────────────────────────────────

def unlock_usb_key(drive_root: str) -> bytes | None:
    """
    Déverrouille la clé USB :
    1. Demande le PIN
    2. Dérive la clé maître et déchiffre key.vault
    3. Succès → retourne la clé AES
    4. PIN incorrect → redemande indéfiniment (q pour quitter)
    """
    try:
        usb_data = read_usb_files(drive_root)
    except RuntimeError as e:
        print_error(str(e))
        return None

    device_id      = usb_data["device_id"]
    key_vault      = usb_data["key_vault"]
    uuid_partition = key_vault["uuid_partition"]
    print_separator()
    print_info("Déverrouillez la clé USB avec votre PIN.")
    typewriter("(tapez 'q' pour annuler)", color=Fore.YELLOW)

    while True:
        pin = ask_pin("PIN")

        # Annulation explicite (q) ou Ctrl+C
        if pin is None or pin.lower() == "q":
            print_warning("Annulé.")
            return None

        # Erreur de format → on redemande sans consommer de tentative
        ok, err = validate_pin(pin)
        if not ok:
            print_error(err)
            continue

        # Tentative de déchiffrement
        try:
            master_key    = derive_master_key(pin, uuid_partition, device_id)
            encrypted_aes = base64.b64decode(key_vault["key_encrypted"])
            aes_key       = aes_gcm_decrypt(encrypted_aes, master_key)

            print_success("Clé USB déverrouillée.")
            return aes_key

        except InvalidTag:
            print_error("PIN incorrect, réessayez.")

        except Exception as e:
            print_error(f"Erreur inattendue : {e}")
            return None


# ── Statut ────────────────────────────────────────────────────────────────────

def get_usb_status(drive_root: str) -> dict | None:
    """
    Retourne un dict avec les informations de statut de la clé USB,
    prêt à être affiché par display.display_usb_status().
    Retourne None si la USB n'est pas initialisée ou illisible.
    """
    if not is_usb_initialized(drive_root):
        print_warning("Cette USB n'est pas configurée.")
        return None

    try:
        usb_data = read_usb_files(drive_root)
    except RuntimeError as e:
        print_error(str(e))
        return None

    key_vault      = usb_data["key_vault"]
    meta           = usb_data["meta"]
    uuid_partition = key_vault["uuid_partition"]

    return {
        "drive":          drive_root,
        "uuid_partition": uuid_partition,
        "created_at":     meta.get("created_at", "N/A"),
    }