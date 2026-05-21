"""
display.py — Affichage, couleurs, progression, formatage.
"""

import sys
import time
import logging

from colorama import Fore, Style, init

init(autoreset=True)


# ── Logger global ─────────────────────────────────────────────────────────────

class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    Fore.CYAN,
        "INFO":     Fore.GREEN,
        "WARNING":  Fore.YELLOW,
        "ERROR":    Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(name: str = __name__) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter("%(levelname)s - %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


logger = setup_logger(__name__)


# ── Primitives d'affichage ────────────────────────────────────────────────────

def typewriter(text: str, delay: float = 0.01, color: str = Fore.WHITE, end: str = "\n"):
    """Affiche du texte caractère par caractère."""
    for char in text:
        sys.stdout.write(color + char + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)


def print_separator():
    print(f"{Fore.BLUE}{'-' * 60}{Style.RESET_ALL}")


def print_banner():
    print(f"""
{Fore.CYAN}+------------------------------------------------------------+
|                    CRYPTEUR SECURISE  v3                   |
|     AES-256-GCM + scrypt  |  Clé USB + PIN obligatoires   |
+------------------------------------------------------------+{Style.RESET_ALL}
""")


def print_success(msg: str):
    typewriter(f"✓ {msg}", color=Fore.GREEN)


def print_error(msg: str):
    typewriter(f"✗ {msg}", color=Fore.RED)


def print_warning(msg: str):
    typewriter(msg, color=Fore.YELLOW)


def print_info(msg: str):
    typewriter(msg, color=Fore.BLUE)




# ── Formatage ─────────────────────────────────────────────────────────────────

def format_size(size_bytes: int) -> str:
    """Convertit un nombre d'octets en chaîne lisible (KB, MB, GB...)."""
    if size_bytes == 0:
        return "0 B"
    names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {names[i]}"


# ── Statistiques ──────────────────────────────────────────────────────────────

def display_stats(stats: dict):
    """Affiche les statistiques du dernier traitement."""
    if not stats:
        print_warning("Aucune statistique disponible.")
        return

    print(f"""
{Fore.GREEN}STATISTIQUES DU DERNIER TRAITEMENT{Style.RESET_ALL}
{Fore.BLUE}{'-' * 50}{Style.RESET_ALL}
Dossier        : {stats.get('folder', 'N/A')}
Opération      : {stats.get('operation', 'N/A')}
Fichiers       : {stats.get('files_count', 0)}
Succès         : {stats.get('success_count', 0)}
Échecs         : {stats.get('error_count', 0)}
Taille totale  : {format_size(stats.get('total_size', 0))}
Débit moyen    : {stats.get('throughput', 'N/A')}
Durée          : {stats.get('duration', 'N/A')}
Date           : {stats.get('timestamp', 'N/A')}
Journal        : {stats.get('log_path', 'N/A')}
""")


def display_usb_status(info: dict):
    """Affiche l'état de la clé USB."""
    locked      = info.get("locked", False)
    attempts    = info.get("attempts", 0)
    max_att     = info.get("max_attempts", 5)
    lock_status = (
        f"{Fore.RED}VERROUILLÉE{Style.RESET_ALL}"
        if locked
        else f"{Fore.GREEN}Déverrouillée{Style.RESET_ALL}"
    )
    print(f"""
{Fore.GREEN}STATUT DE LA CLÉ USB{Style.RESET_ALL}
{Fore.BLUE}{'-' * 50}{Style.RESET_ALL}
Lecteur        : {info.get('drive', 'N/A')}
UUID partition : {info.get('uuid_partition', 'N/A')}
Créée le       : {info.get('created_at', 'N/A')}
Statut         : {lock_status}
Tentatives     : {attempts} / {max_att}
""")



# ── Vérification ──────────────────────────────────────────────────────────────

def display_verify_usb(info: dict):
    """Affiche le rapport de vérification de la clé USB."""
    files = info.get("files", {})

    def file_status(present: bool, label: str) -> str:
        if present:
            return f"{Fore.GREEN}✓ Présent{Style.RESET_ALL}    {label}"
        return f"{Fore.RED}✗ Manquant{Style.RESET_ALL}   {label}"

    locked   = info.get("locked", False)
    attempts = info.get("attempts", 0)
    max_att  = info.get("max_attempts", 5)
    lock_str = (
        f"{Fore.RED}VERROUILLÉE{Style.RESET_ALL}"
        if locked
        else f"{Fore.GREEN}Opérationnelle{Style.RESET_ALL}"
    )
    hmac_ok  = info.get("hmac_ok", True)
    hmac_str = (
        f"{Fore.GREEN}✓ Valide{Style.RESET_ALL}"
        if hmac_ok
        else f"{Fore.RED}✗ Falsifié ou corrompu{Style.RESET_ALL}"
    )
    logs_count = info.get("logs_count", 0)
    logs_size  = info.get("logs_size", 0)

    print(f"""
{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}
{Fore.GREEN}  VÉRIFICATION DE LA CLÉ USB{Style.RESET_ALL}
{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}

{Fore.YELLOW}Identification{Style.RESET_ALL}
  Lecteur        : {info.get("drive", "N/A")}
  UUID partition : {info.get("uuid_partition", "N/A")}
  Créée le       : {info.get("created_at", "N/A")}

{Fore.YELLOW}Fichiers CRYPTEUR/{Style.RESET_ALL}
  {file_status(files.get("device_id"), "device.id  — identifiant USB")}
  {file_status(files.get("key_vault"), "key.vault  — clé AES chiffrée")}
  {file_status(files.get("duress_token"), "duress.token — PIN de détresse")}
  {file_status(files.get("attempts_lock"), "attempts.lock — compteur de tentatives")}
  {file_status(files.get("meta"), "meta.json  — métadonnées")}

{Fore.YELLOW}Sécurité{Style.RESET_ALL}
  Statut         : {lock_str}
  Tentatives PIN : {attempts} / {max_att}
  HMAC verrou    : {hmac_str}

{Fore.YELLOW}Journaux{Style.RESET_ALL}
  Rapports       : {logs_count} fichier(s) — {format_size(logs_size)}
{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}
""")


def display_verify_folder(result: dict):
    """Affiche le rapport de vérification d'intégrité du dossier."""
    ok_count      = result.get("ok_count", 0)
    corrupt_count = result.get("corrupt_count", 0)
    orphan_tmp    = result.get("orphan_tmp", 0)
    details       = result.get("details", [])

    # Résumé global
    if corrupt_count == 0 and ok_count > 0:
        integrity_str = f"{Fore.GREEN}✓ Tous les fichiers sont intègres{Style.RESET_ALL}"
    elif corrupt_count > 0:
        integrity_str = f"{Fore.RED}✗ {corrupt_count} fichier(s) corrompu(s) détecté(s){Style.RESET_ALL}"
    else:
        integrity_str = f"{Fore.YELLOW}Aucun fichier chiffré trouvé{Style.RESET_ALL}"

    print(f"""
{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}
{Fore.GREEN}  VÉRIFICATION DU DOSSIER{Style.RESET_ALL}
{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}

{Fore.YELLOW}Inventaire{Style.RESET_ALL}
  Dossier        : {result.get("folder", "N/A")}
  Total fichiers : {result.get("total_files", 0)}
  Chiffrés       : {result.get("encrypted_files", 0)}  ({format_size(result.get("encrypted_size", 0))})
  En clair       : {result.get("plain_files", 0)}  ({format_size(result.get("plain_size", 0))})
  Taille totale  : {format_size(result.get("total_size", 0))}
  Fichiers .tmp  : {orphan_tmp} orphelin(s){"  ⚠" if orphan_tmp > 0 else ""}

{Fore.YELLOW}Intégrité GCM{Style.RESET_ALL}
  {integrity_str}
  Vérifiés OK    : {ok_count}
  Corrompus      : {corrupt_count}
""")

    # Détail des fichiers corrompus uniquement
    corrupted = [d for d in details if d["status"] == "corrompu"]
    if corrupted:
        print(f"{Fore.RED}  Fichiers corrompus :{Style.RESET_ALL}")
        for d in corrupted:
            print(f"    ✗ {d['path']}")
            print(f"      → {d['reason']}")
        print()

    # Détail complet si tout est OK (liste courte)
    elif ok_count > 0 and ok_count <= 20:
        print(f"{Fore.GREEN}  Détail :{Style.RESET_ALL}")
        for d in details:
            size_str = format_size(d["size"])
            print(f"    ✓ {d['path']}  ({size_str})")
        print()

    elif ok_count > 20:
        print(f"{Fore.GREEN}  (détail omis — {ok_count} fichiers OK){Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")


def display_help():
    """Affiche l'aide CLI."""
    print(f"""
{Fore.GREEN}CRYPTEUR SECURISE v3 — Aide{Style.RESET_ALL}

{Fore.YELLOW}USAGE :{Style.RESET_ALL}
  python main.py --encrypt <dossier>   Chiffre tous les fichiers du dossier
  python main.py --decrypt <dossier>   Déchiffre tous les fichiers du dossier
  python main.py --status              Affiche l'état de la clé USB connectée
  python main.py --verify [dossier]    Vérifie la clé USB et l'intégrité des fichiers
  python main.py --reset-pin           Réinitialise le PIN principal et le PIN de détresse
  python main.py --help                Affiche cette aide

{Fore.YELLOW}AUTHENTIFICATION :{Style.RESET_ALL}
  - Clé USB physique + PIN à 8 chiffres : protège les fichiers.

{Fore.YELLOW}PREMIER USAGE :{Style.RESET_ALL}
  - Branchez la USB, lancez --encrypt.
  - La USB est configurée automatiquement.
  - Définissez un PIN à 8 chiffres (jamais stocké).

{Fore.YELLOW}AVERTISSEMENTS :{Style.RESET_ALL}
  - Perte de la USB ou du PIN = données définitivement perdues.
  - Aucun mécanisme de récupération n'est prévu.
  - Sauvegardez vos données avant tout traitement massif.
""")