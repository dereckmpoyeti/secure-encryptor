# Crypteur Sécurisé v3

Outil en ligne de commande pour chiffrer et déchiffrer récursivement les fichiers d'un dossier avec AES-256-GCM. L'accès aux données repose sur une clé USB physique et un PIN à 8 chiffres. Après 5 tentatives de PIN incorrectes, la clé AES est détruite de façon irréversible.

![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-red)
![Auth](https://img.shields.io/badge/auth-USB%20%2B%20PIN-orange)

---

## Fonctionnalités

**Chiffrement**
- Chiffrement et déchiffrement récursifs de dossiers avec AES-256-GCM.
- Sel et IV uniques par fichier — deux fichiers identiques produisent des chiffrés différents.
- Sous-clé unique par fichier dérivée depuis la clé AES de la USB.
- Traitement par blocs de 1 Mo pour limiter l'utilisation mémoire sur les gros fichiers.
- Effacement sécurisé du fichier source après chiffrement (écrasement aléatoire avant suppression).
- Fichiers temporaires `*.tmp` avant remplacement atomique — pas de fichier à moitié écrit en cas de coupure.
- Nettoyage automatique des `*.tmp` orphelins avant chaque traitement.

**Authentification**
- Clé USB physique obligatoire + PIN à 8 chiffres.
- Le PIN n'est jamais stocké — il sert uniquement à dériver la clé maître.
- Initialisation automatique d'une clé USB vierge au premier chiffrement.
- Dossier `CRYPTEUR/` caché sur Windows (attributs Système + Caché).
- Verrouillage définitif après 5 tentatives de PIN incorrectes (format invalide inclus).
- À la 5ème tentative échouée : destruction cryptographique irréversible de `key.vault` (3 passes aléatoires + suppression).

**Rapports**
- Rapports JSON horodatés écrits dans `CRYPTEUR/logs/` sur la clé USB.
- Chaque rapport contient : dossier traité, opération, nombre de fichiers, succès, échecs, taille totale, débit moyen, durée, erreurs détaillées.
- Barre de progression avec débit en temps réel (Mo/s).

---

## Prérequis

- Python 3.12 ou supérieur
- Une clé USB disponible
- Espace disque suffisant pour les fichiers temporaires (taille du plus gros fichier à traiter)

Dépendances Python :

```txt
colorama==0.4.6
cryptography==46.0.3
psutil==7.1.3
tqdm==4.67.1
```

---

## Installation

**Windows :**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

**Linux/macOS :**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Utilisation

```powershell
python main.py --help
python main.py --encrypt <dossier>
python main.py --decrypt <dossier>
python main.py --status
```

Si le chemin contient des espaces, entourez-le de guillemets :

```powershell
python main.py --encrypt "C:\Users\Alice\Documents\mon dossier"
```

---

## Premier usage

1. Lancez `--encrypt` sur le dossier à chiffrer.
2. Branchez la clé USB et appuyez sur Entrée.
3. Confirmez la clé détectée (ou choisissez parmi plusieurs).
4. Si la clé n'est pas encore configurée, le programme crée automatiquement le dossier `CRYPTEUR/`.
5. Définissez un PIN à exactement 8 chiffres (saisi deux fois pour confirmation).
6. Le programme génère une clé AES-256 aléatoire, la chiffre et l'écrit dans `key.vault`.
7. Le dossier cible est chiffré récursivement.

> **Attention :** notez votre PIN et conservez la clé USB en lieu sûr. Il n'existe aucun mécanisme de récupération.

---

## Structure sur la clé USB

Après initialisation, la clé USB contient le dossier `CRYPTEUR/` (caché sur Windows) :

```text
CRYPTEUR/
├── device.id       # Identifiant aléatoire de 32 octets lié à cette USB
├── key.vault       # Clé AES-256 chiffrée par la clé maître
├── attempts.lock   # Compteur de tentatives PIN signé HMAC-SHA256
├── meta.json       # Métadonnées de création
└── logs/           # Rapports JSON horodatés
    ├── 20250517_143012_enc.json
    └── 20250517_145501_dec.json
```

Le PIN n'est jamais stocké. Il sert à dériver la clé maître qui déchiffre `key.vault`.

---

## Verrouillage après tentatives échouées

Le programme comptabilise **toute saisie non annulée** comme une tentative, y compris les PIN de longueur incorrecte. Le compteur est signé par HMAC-SHA256 avec le `device_id` de la USB — il ne peut pas être falsifié ou remis à zéro sans connaître ce `device_id`.

À la 5ème tentative échouée :

1. `key.vault` est écrasé avec 3 passes de données aléatoires (avec `fsync` entre chaque passe).
2. `key.vault` est supprimé.
3. `attempts.lock` est supprimé.

**Les fichiers chiffrés avec cette USB sont alors définitivement inaccessibles**, même en connaissant le PIN ou en récupérant physiquement la clé USB.

Le seuil de 5 tentatives est configurable dans `config.py` (`MAX_PIN_ATTEMPTS`).

---

## Format des fichiers chiffrés

```text
[9 octets]   Magic header : "ENCRYPTED"
[1 octet]    Version du format
[16 octets]  Sel scrypt (unique par fichier)
[12 octets]  IV GCM (unique par fichier)
[Variable]   Données chiffrées (AES-256-GCM)
[16 octets]  Tag d'authentification GCM
```

Les fichiers chiffrés prennent l'extension `.encrypted`. Au déchiffrement, cette extension est retirée et le fichier `.encrypted` est effacé de façon sécurisée.

---

## Structure du projet

```text
├── main.py           # Point d'entrée CLI
├── config.py         # Constantes et paramètres configurables
├── crypto.py         # Dérivation de clés (scrypt), AES-256-GCM, HMAC-SHA256
├── usb.py            # Détection, initialisation, déverrouillage et verrouillage USB
├── vault.py          # Gestion de CRYPTEUR/ : lecture, écriture, verrou, destruction
├── processor.py      # Chiffrement/déchiffrement de dossiers, rapports JSON
├── display.py        # Affichage, couleurs, progression, statistiques
├── requirements.txt  # Dépendances Python
├── README.md         # Documentation
└── LICENCE           # Licence MIT
```

---

## Sécurité

**Ce qui est garanti**
- La clé AES est générée avec `os.urandom(32)` — jamais dérivée d'un mot de passe.
- La clé maître est dérivée avec `scrypt(PIN + UUID_partition + device_id)` — aucun des trois éléments seuls ne suffit.
- Chaque fichier utilise un sel unique et une sous-clé dérivée : deux fichiers identiques produisent des chiffrés différents.
- AES-256-GCM garantit confidentialité et intégrité simultanément — toute altération du fichier est détectée.
- Le compteur de tentatives est signé HMAC-SHA256 et lié physiquement au `device_id` de la USB.
- La destruction de `key.vault` est effectuée par 3 passes d'écrasement aléatoire avec `fsync` avant suppression.

**Limites connues**

*Effacement sécurisé et wear leveling :* sur les clés USB avec contrôleur intelligent, le wear leveling peut rediriger les écritures vers d'autres blocs physiques. Les 3 passes d'écrasement sont efficaces sur la grande majorité des clés USB grand public, mais un outil forensique spécialisé pourrait théoriquement récupérer des données sur un support haut de gamme. Cette limite est inhérente au support flash et ne peut pas être contournée en logiciel pur.

*Mémoire Python :* le PIN et la clé AES transitent en clair dans la mémoire du processus Python pendant l'exécution. Ce risque est difficile à éliminer en Python pur.

*Verrouillage Linux/macOS :* le dossier `CRYPTEUR/` n'est pas masqué sur Linux et macOS (pas d'équivalent à `attrib +H +S` sans renommer le dossier, ce qui briserait la compatibilité).

---

## Recommandations pour un usage haute sécurité

Pour neutraliser la limite du wear leveling, la mesure complémentaire la plus efficace est de **chiffrer intégralement la clé USB au niveau du volume** :

- **Windows :** activer BitLocker To Go sur la clé USB (clic droit → Activer BitLocker). Les données physiquement récupérées sur la NAND seront chiffrées au niveau volume, indépendamment du comportement du contrôleur.
- **Linux :** formater la clé avec LUKS (`cryptsetup`).
- **macOS :** utiliser un volume chiffré (`Finder → Chiffrer`).

Avec cette combinaison — `key.vault` chiffré par scrypt + destruction en 3 passes + volume USB chiffré — la sécurité reste effective même face à un attaquant disposant d'outils forensiques et d'un accès physique à la clé USB.

Pour les environnements à très haute exigence, des clés USB avec **chiffrement matériel certifié** (Kingston IronKey, Apricorn Aegis) intègrent un mécanisme de destruction hardware après N tentatives incorrectes, incontournable par logiciel.

---

## Bonnes pratiques

- Sauvegardez vos données avant tout chiffrement massif.
- Testez le déchiffrement sur un petit dossier avant un usage en production.
- Ne lancez pas deux instances du programme simultanément sur le même dossier.
- N'interrompez pas le programme pendant une opération (risque de fichiers `.tmp` orphelins, nettoyés automatiquement au prochain lancement).
- Conservez la clé USB séparément de la machine qui héberge les fichiers chiffrés.
- Le PIN ne doit être connu que de vous — il n'existe aucune procédure de récupération.

---

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENCE`.