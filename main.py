#!/usr/bin/env python3
"""
main.py — Point d'entrée CLI du Crypteur Sécurisé v3.

Usage :
  python main.py --encrypt <dossier>
  python main.py --decrypt <dossier>
  python main.py --status
  python main.py --reset-pin
  python main.py --help
"""

import argparse
import sys

from colorama import Fore

from display import print_banner, print_error, print_warning, display_stats, display_usb_status, display_help
from processor import process_folder, fake_process_folder, validate_folder_path
from usb import select_usb_drive, is_usb_initialized, initialize_usb, unlock_usb_key, get_usb_status, reset_pin
from vault import cleanup_orphan_tmp, usb_logs_path


# ── Parsing des arguments ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypteur",
        description="Crypteur Sécurisé v3 — AES-256-GCM + clé USB + PIN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python main.py --encrypt /mon/dossier
  python main.py --decrypt /mon/dossier
  python main.py --status
  python main.py --reset-pin
""",
        add_help=False,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--encrypt", metavar="DOSSIER",
        help="Chiffre tous les fichiers du dossier (récursif).",
    )
    group.add_argument(
        "--decrypt", metavar="DOSSIER",
        help="Déchiffre tous les fichiers .encrypted du dossier (récursif).",
    )
    group.add_argument(
        "--status", action="store_true",
        help="Affiche l'état de la clé USB connectée.",
    )
    group.add_argument(
        "--reset-pin", action="store_true",
        help="Réinitialise le PIN principal et le PIN de détresse.",
    )
    group.add_argument(
        "--help", "-h", action="store_true",
        help="Affiche cette aide.",
    )

    return parser


# ── Flux USB commun ───────────────────────────────────────────────────────────

def get_unlocked_key() -> bytes | None:
    """
    Flux commun pour chiffrement et déchiffrement :
    1. Demande de brancher la USB
    2. Sélection (auto si une seule, avec confirmation)
    3. Auto-initialisation si vierge (chiffrement uniquement côté appelant)
    4. Déverrouillage PIN
    Retourne la clé AES ou None si annulé/bloqué.
    """
    print_warning("\nBranchez la clé USB et appuyez sur Entrée.")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()
        return None

    drive = select_usb_drive()
    if not drive:
        return None

    return drive, is_usb_initialized(drive)


# ── Commandes ─────────────────────────────────────────────────────────────────

def cmd_encrypt(folder_path: str):
    folder_path, error = validate_folder_path(folder_path)
    if error:
        print_error(error)
        sys.exit(1)

    result = get_unlocked_key()
    if result is None:
        sys.exit(1)

    drive, initialized = result

    # Auto-initialisation si la USB est vierge
    if not initialized:
        print_warning("Clé USB non configurée — configuration automatique.")
        if not initialize_usb(drive):
            sys.exit(1)

    aes_key, is_duress = unlock_usb_key(drive)
    if is_duress:
        # PIN de détresse pendant un chiffrement : destruction silencieuse
        # On ne chiffre rien — la clé est déjà détruite dans unlock_usb_key
        from vault import destroy_key_vault
        destroy_key_vault(drive)
        print_warning("Aucun fichier à traiter.")
        sys.exit(0)
    if aes_key is None:
        sys.exit(1)

    stats = process_folder(folder_path, aes_key, "encrypt", str(usb_logs_path(drive)))
    display_stats(stats)


def cmd_decrypt(folder_path: str):
    folder_path, error = validate_folder_path(folder_path)
    if error:
        print_error(error)
        sys.exit(1)

    result = get_unlocked_key()
    if result is None:
        sys.exit(1)

    drive, initialized = result

    if not initialized:
        print_error("Cette USB n'est pas configurée pour ce coffre.")
        sys.exit(1)

    aes_key, is_duress = unlock_usb_key(drive)
    if is_duress:
        # PIN de détresse : simulation convaincante + destruction de key.vault
        stats = fake_process_folder(folder_path, drive, str(usb_logs_path(drive)))
        display_stats(stats)
        return
    if aes_key is None:
        sys.exit(1)

    stats = process_folder(folder_path, aes_key, "decrypt", str(usb_logs_path(drive)))
    display_stats(stats)


def cmd_status():
    print_warning("\nBranchez la clé USB et appuyez sur Entrée.")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

    drive = select_usb_drive()
    if not drive:
        sys.exit(1)

    info = get_usb_status(drive)
    if info:
        display_usb_status(info)



def cmd_reset_pin():
    print_warning("\nBranchez la clé USB et appuyez sur Entrée.")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

    drive = select_usb_drive()
    if not drive:
        sys.exit(1)

    if not is_usb_initialized(drive):
        print_error("Cette USB n'est pas configurée.")
        sys.exit(1)

    success = reset_pin(drive)
    if not success:
        sys.exit(1)


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()

    # Aide
    if args.help:
        display_help()
        sys.exit(0)

    # Dispatch
    try:
        if args.encrypt:
            cmd_encrypt(args.encrypt)

        elif args.decrypt:
            cmd_decrypt(args.decrypt)

        elif args.status:
            cmd_status()

        elif args.reset_pin:
            cmd_reset_pin()


    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Arrêt demandé par l'utilisateur.{Fore.WHITE}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Erreur fatale : {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()