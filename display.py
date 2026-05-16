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
    print(f"""
{Fore.GREEN}STATUT DE LA CLÉ USB{Style.RESET_ALL}
{Fore.BLUE}{'-' * 50}{Style.RESET_ALL}
Lecteur        : {info.get('drive', 'N/A')}
UUID partition : {info.get('uuid_partition', 'N/A')}
Créée le       : {info.get('created_at', 'N/A')}
""")


def display_help():
    """Affiche l'aide CLI."""
    print(f"""
{Fore.GREEN}CRYPTEUR SECURISE v3 — Aide{Style.RESET_ALL}

{Fore.YELLOW}USAGE :{Style.RESET_ALL}
  python main.py --encrypt <dossier>   Chiffre tous les fichiers du dossier
  python main.py --decrypt <dossier>   Déchiffre tous les fichiers du dossier
  python main.py --status              Affiche l'état de la clé USB connectée
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