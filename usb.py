"""
usb.py — Détection USB, initialisation, déverrouillage, statut.
"""

import base64
import getpass
import os
import subprocess
import sys

from colorama import Fore

from config import (
    PIN_LENGTH, MAX_PIN_ATTEMPTS,
    KEY_VAULT_FILE, DEVICE_ID_FILE,
    DURESS_TOKEN_FILE, META_FILE, ATTEMPTS_FILE,
)
from crypto import derive_master_key, aes_gcm_encrypt, aes_gcm_decrypt
from cryptography.exceptions import InvalidTag
from display import (
    typewriter, print_separator, print_success, print_error,
    print_warning, print_info,
)
from vault import (
    is_usb_initialized, read_usb_files, write_vault_files,
    usb_folder_path, ensure_folder_hidden,
    read_attempts, write_attempts, reset_attempts, is_locked, destroy_key_vault,
    write_duress_token, is_duress_pin, usb_logs_path,
)

WINDOWS = sys.platform == "win32"


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
            import ctypes
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
            drive = d["letter"] + "\\"
        else:
            print_warning("Opération annulée.")
            return None
    else:
        # Cas : plusieurs USB → liste
        print(f"\n{Fore.CYAN}Clés USB disponibles :{Fore.WHITE}")
        for i, d in enumerate(drives, 1):
            uuid_str = f"  (série: {d['uuid']})" if d["uuid"] else ""
            print(f"  {i}. {d['letter']} — {d['label']}{uuid_str}")

        while True:
            rep = input(f"{Fore.CYAN}Votre choix (1-{len(drives)}) :{Fore.WHITE} >> ").strip()
            if rep.isdigit() and 1 <= int(rep) <= len(drives):
                drive = drives[int(rep) - 1]["letter"] + "\\"
                break
            print_error("Choix invalide.")

    # Re-appliquer le masquage à chaque connexion (attribut peut être perdu
    # après un scandisk ou une manipulation manuelle)
    if is_usb_initialized(drive):
        ensure_folder_hidden(drive)

    return drive


# ── Validation du PIN ─────────────────────────────────────────────────────────

def validate_pin(pin: str) -> tuple[bool, str]:
    if len(pin) != PIN_LENGTH:
        return False, f"Le PIN doit faire exactement {PIN_LENGTH} chiffres."
    if not pin.isdigit():
        return False, "Le PIN ne doit contenir que des chiffres."
    return True, ""


def ask_pin(label: str = "PIN") -> str | None:
    """
    Demande le PIN de façon sécurisée (caractères masqués).
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
                if ch in ("\r", "\n"):
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
    - Écrit CRYPTEUR/ sur la USB (caché sur Windows)
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

    # ── Saisie du PIN de détresse ────────────────────────────────────────────
    print_separator()
    typewriter(f"\nDéfinissez un PIN de détresse à {PIN_LENGTH} chiffres.", color=Fore.YELLOW)
    typewriter("Ce PIN détruira silencieusement la clé si utilisé sous contrainte.", color=Fore.RED)
    typewriter("Il doit être différent de votre PIN principal.", color=Fore.YELLOW)

    while True:
        duress1 = ask_pin("PIN de détresse")
        if duress1 is None:
            print_warning("Annulé.")
            return False

        ok, err = validate_pin(duress1)
        if not ok:
            print_error(err)
            continue

        if duress1 == pin1:
            print_error("Le PIN de détresse doit être différent du PIN principal.")
            continue

        duress2 = ask_pin("Confirmez le PIN de détresse")
        if duress2 is None:
            print_warning("Annulé.")
            return False

        if duress1 != duress2:
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

    # write_vault_files crée attempts.lock, logs/ et masque le dossier
    write_vault_files(drive_root, device_id, key_vault)

    # Écrire le token du PIN de détresse
    write_duress_token(drive_root, duress1, uuid_partition, device_id)

    print_success("Clé USB configurée avec succès !")
    typewriter("Conservez cette USB et votre PIN en lieu sûr.", color=Fore.YELLOW)
    typewriter("Perte de l'un ou l'autre = données définitivement inaccessibles.", color=Fore.RED)
    return True


# ── Déverrouillage ────────────────────────────────────────────────────────────

def unlock_usb_key(drive_root: str) -> tuple[bytes | None, bool]:
    """
    Déverrouille la clé USB.
    Retourne (aes_key, False) en cas de succès normal.
    Retourne (None, True)     si le PIN de détresse est détecté.
    Retourne (None, False)    en cas d'échec ou d'annulation.
    """
    try:
        usb_data = read_usb_files(drive_root)
    except RuntimeError as e:
        print_error(str(e))
        return None, False

    device_id      = usb_data["device_id"]
    key_vault      = usb_data["key_vault"]
    uuid_partition = key_vault["uuid_partition"]

    # ── Vérification du verrou ────────────────────────────────────────────────
    if is_locked(drive_root, device_id):
        _print_locked_message()
        return None, False

    print_separator()
    print_info("Déverrouillez la clé USB avec votre PIN.")

    attempts = read_attempts(drive_root, device_id)
    remaining = MAX_PIN_ATTEMPTS - attempts
    if attempts > 0:
        print_warning(
            f"Attention : {attempts} tentative(s) échouée(s). "
            f"Il vous reste {remaining} essai(s) avant verrouillage définitif."
        )

    typewriter("(tapez 'q' pour annuler)", color=Fore.YELLOW)

    while True:
        # Revérifier le verrou à chaque itération (sécurité défensive)
        current = read_attempts(drive_root, device_id)
        if current >= MAX_PIN_ATTEMPTS:
            _print_locked_message()
            return None, False

        pin = ask_pin("PIN")

        # Annulation explicite (ne consomme pas de tentative)
        if pin is None or pin.lower() == "q":
            print_warning("Annulé.")
            return None, False

        # ── Incrémenter le compteur AVANT toute vérification ─────────────────
        # Toute saisie non annulée (format invalide ou PIN incorrect) consomme
        # une tentative — un attaquant ne peut pas tâtonner sur la longueur
        # sans déclencher le verrou.
        new_count = current + 1
        write_attempts(drive_root, device_id, new_count)

        # Erreur de format : compter la tentative mais informer l'utilisateur
        ok, err = validate_pin(pin)
        if not ok:
            remaining_after = MAX_PIN_ATTEMPTS - new_count
            if remaining_after <= 0:
                destroy_key_vault(drive_root)
                _print_locked_message()
                return None, False
            print_error(f"{err} ({remaining_after} tentative(s) restante(s))")
            continue

        # ── Vérifier le PIN de détresse AVANT le PIN principal ────────────────
        # Les deux dérivations scrypt prennent le même temps → pas de timing leak
        if is_duress_pin(drive_root, pin, uuid_partition, device_id):
            reset_attempts(drive_root, device_id)
            print_success("Clé USB déverrouillée.")   # Message normal, pas de suspicion
            return None, True                          # Signal duress vers l'appelant

        try:
            master_key    = derive_master_key(pin, uuid_partition, device_id)
            encrypted_aes = base64.b64decode(key_vault["key_encrypted"])
            aes_key       = aes_gcm_decrypt(encrypted_aes, master_key)

            # ── Succès : remettre le compteur à 0 ────────────────────────────
            reset_attempts(drive_root, device_id)
            print_success("Clé USB déverrouillée.")
            return aes_key, False

        except InvalidTag:
            remaining_after = MAX_PIN_ATTEMPTS - new_count
            if remaining_after <= 0:
                destroy_key_vault(drive_root)
                _print_locked_message()
                return None, False
            else:
                print_error(
                    f"PIN incorrect. "
                    f"{remaining_after} tentative(s) restante(s) avant verrouillage."
                )

        except Exception as e:
            print_error(f"Erreur inattendue : {e}")
            return None, False


def _print_locked_message():
    """Affiche le message de verrouillage définitif."""
    print_error(
        f"Clé USB verrouillée après {MAX_PIN_ATTEMPTS} tentatives incorrectes."
    )
    typewriter(
        "Cette clé USB est définitivement verrouillée.",
        color=Fore.RED,
    )
    typewriter(
        "Les données chiffrées avec cette clé sont inaccessibles.",
        color=Fore.RED,
    )



# ── Réinitialisation du PIN ──────────────────────────────────────────────────

def reset_pin(drive_root: str) -> bool:
    """
    Réinitialise le PIN principal et le PIN de détresse sans toucher aux fichiers.

    Flux :
      1. Déverrouillage avec le PIN actuel (consomme des tentatives)
      2. Saisie du nouveau PIN principal (confirmé deux fois)
      3. Demande si l'utilisateur veut changer le PIN de détresse
         - OUI : saisir le nouveau duress PIN (confirmé deux fois)
         - NON : ressaisir l'ancien duress PIN (Option A — obligatoire)
      4. Écriture atomique du nouveau key.vault via fichier .tmp
      5. Re-génération de duress.token
      6. Remise à zéro de attempts.lock
    Retourne True si succès, False si annulé ou échoué.
    """
    try:
        usb_data = read_usb_files(drive_root)
    except RuntimeError as e:
        print_error(str(e))
        return False

    device_id      = usb_data["device_id"]
    key_vault      = usb_data["key_vault"]
    uuid_partition = key_vault["uuid_partition"]

    # ── Vérification du verrou ────────────────────────────────────────────────
    if is_locked(drive_root, device_id):
        print_error("Clé USB verrouillée — réinitialisation impossible.")
        return False

    print_separator()
    print_info("RÉINITIALISATION DU PIN")
    typewriter("Saisissez votre PIN actuel pour continuer.", color=Fore.YELLOW)

    # ── Déverrouillage avec le PIN actuel ─────────────────────────────────────
    aes_key, is_duress = unlock_usb_key(drive_root)
    if is_duress:
        print_error("Opération annulée.")
        return False
    if aes_key is None:
        return False

    # ── Nouveau PIN principal ─────────────────────────────────────────────────
    print_separator()
    typewriter("Définissez votre nouveau PIN principal.", color=Fore.YELLOW)

    while True:
        new_pin1 = ask_pin("Nouveau PIN principal")
        if new_pin1 is None:
            print_warning("Annulé.")
            return False

        ok, err = validate_pin(new_pin1)
        if not ok:
            print_error(err)
            continue

        new_pin2 = ask_pin("Confirmez le nouveau PIN principal")
        if new_pin2 is None:
            print_warning("Annulé.")
            return False

        if new_pin1 != new_pin2:
            print_error("Les PIN ne correspondent pas.")
            continue
        break

    # ── PIN de détresse : changer ou conserver ? ──────────────────────────────
    print_separator()
    rep = input(
        f"{Fore.CYAN}Voulez-vous changer votre PIN de détresse ? (O/n) :{Fore.WHITE} >> "
    ).strip().lower()
    change_duress = rep in ("", "o", "oui", "y", "yes")

    if change_duress:
        typewriter("Définissez votre nouveau PIN de détresse.", color=Fore.YELLOW)
        while True:
            new_duress1 = ask_pin("Nouveau PIN de détresse")
            if new_duress1 is None:
                print_warning("Annulé.")
                return False

            ok, err = validate_pin(new_duress1)
            if not ok:
                print_error(err)
                continue

            if new_duress1 == new_pin1:
                print_error("Le PIN de détresse doit être différent du PIN principal.")
                continue

            new_duress2 = ask_pin("Confirmez le nouveau PIN de détresse")
            if new_duress2 is None:
                print_warning("Annulé.")
                return False

            if new_duress1 != new_duress2:
                print_error("Les PIN ne correspondent pas.")
                continue
            break
        duress_pin = new_duress1

    else:
        # Option A : ressaisir l'ancien duress PIN — obligatoire
        typewriter(
            "Saisissez votre PIN de détresse actuel pour confirmer.",
            color=Fore.YELLOW,
        )
        old_duress = ask_pin("PIN de détresse actuel")
        if old_duress is None:
            print_warning("Annulé.")
            return False

        ok, err = validate_pin(old_duress)
        if not ok:
            print_error(f"PIN de détresse invalide : {err}")
            print_error("Opération annulée.")
            return False

        if not is_duress_pin(drive_root, old_duress, uuid_partition, device_id):
            print_error(
                "PIN de détresse incorrect. "
                "Sans ce PIN, la réinitialisation est impossible."
            )
            print_error("Opération annulée. Vos PIN actuels sont inchangés.")
            return False

        duress_pin = old_duress

    # ── Écriture atomique du nouveau key.vault ────────────────────────────────
    import json as _json
    folder     = usb_folder_path(drive_root)
    vault_path = folder / KEY_VAULT_FILE
    temp_path  = vault_path.with_suffix(".tmp")

    try:
        new_master_key = derive_master_key(new_pin1, uuid_partition, device_id)
        new_encrypted  = aes_gcm_encrypt(aes_key, new_master_key)

        new_vault = {
            "version":        key_vault.get("version", 1),
            "uuid_partition": uuid_partition,
            "key_encrypted":  base64.b64encode(new_encrypted).decode("ascii"),
        }

        temp_path.write_text(_json.dumps(new_vault, indent=2), encoding="utf-8")
        # Remplacement atomique — si coupure avant ici, l'ancien vault est intact
        temp_path.replace(vault_path)

    except Exception as e:
        print_error(f"Erreur lors de l'écriture du nouveau vault : {e}")
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False

    # ── Re-génération du duress.token ─────────────────────────────────────────
    try:
        write_duress_token(drive_root, duress_pin, uuid_partition, device_id)
    except Exception as e:
        print_error(f"Erreur lors de la mise à jour du PIN de détresse : {e}")
        return False

    # ── Remise à zéro du compteur de tentatives ───────────────────────────────
    reset_attempts(drive_root, device_id)

    print_success("PIN réinitialisé avec succès !")
    typewriter("Vos nouveaux PIN sont actifs immédiatement.", color=Fore.GREEN)
    return True


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

    device_id      = usb_data["device_id"]
    key_vault      = usb_data["key_vault"]
    meta           = usb_data["meta"]
    uuid_partition = key_vault["uuid_partition"]
    attempts       = read_attempts(drive_root, device_id)
    locked         = attempts >= MAX_PIN_ATTEMPTS

    return {
        "drive":          drive_root,
        "uuid_partition": uuid_partition,
        "created_at":     meta.get("created_at", "N/A"),
        "attempts":       attempts,
        "max_attempts":   MAX_PIN_ATTEMPTS,
        "locked":         locked,
    }


def get_usb_verify_info(drive_root: str) -> dict:
    """
    Collecte toutes les informations de vérification de la clé USB.
    Ne demande pas le PIN — inspecte uniquement les métadonnées.
    Retourne un dict complet utilisé par display_verify_usb().
    """
    from pathlib import Path
    import struct

    folder      = usb_folder_path(drive_root)
    initialized = is_usb_initialized(drive_root)

    # ── Présence des fichiers ─────────────────────────────────────────────────
    files = {
        "device_id":    (folder / DEVICE_ID_FILE).exists(),
        "key_vault":    (folder / KEY_VAULT_FILE).exists(),
        "duress_token": (folder / DURESS_TOKEN_FILE).exists(),
        "attempts_lock":(folder / ATTEMPTS_FILE).exists(),
        "meta":         (folder / META_FILE).exists(),
    }

    # ── Métadonnées ───────────────────────────────────────────────────────────
    uuid_partition = "N/A"
    created_at     = "N/A"
    attempts       = 0
    hmac_ok        = True
    locked         = False
    device_id      = b""

    if initialized:
        try:
            usb_data       = read_usb_files(drive_root)
            device_id      = usb_data["device_id"]
            uuid_partition = usb_data["key_vault"].get("uuid_partition", "N/A")
            created_at     = usb_data["meta"].get("created_at", "N/A")
            attempts       = read_attempts(drive_root, device_id)
            locked         = is_locked(drive_root, device_id)

            # Vérifier l'intégrité du HMAC de attempts.lock
            attempts_path = folder / ATTEMPTS_FILE
            if attempts_path.exists():
                from crypto import verify_signature
                data      = attempts_path.read_bytes()
                count_raw = data[:4]
                signature = data[4:36]
                hmac_key  = b"attempts:" + device_id
                hmac_ok   = verify_signature(count_raw, signature, hmac_key)
        except Exception:
            pass

    # ── Statistiques logs ─────────────────────────────────────────────────────
    logs_count = 0
    logs_size  = 0
    logs_path  = usb_logs_path(drive_root)
    if logs_path.exists():
        for f in logs_path.iterdir():
            if f.is_file() and f.suffix == ".json":
                logs_count += 1
                try:
                    logs_size += f.stat().st_size
                except OSError:
                    pass

    return {
        "drive":          drive_root,
        "initialized":    initialized,
        "uuid_partition": uuid_partition,
        "created_at":     created_at,
        "files":          files,
        "attempts":       attempts,
        "max_attempts":   MAX_PIN_ATTEMPTS,
        "locked":         locked,
        "hmac_ok":        hmac_ok,
        "logs_count":     logs_count,
        "logs_size":      logs_size,
    }