# Crypteur Securise v3

Outil en ligne de commande pour chiffrer et dechiffrer recursivement les fichiers d'un dossier avec AES-256-GCM. L'acces aux donnees repose sur une cle USB physique et un PIN a 8 chiffres.

![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-red)
![Auth](https://img.shields.io/badge/auth-USB%20%2B%20PIN-orange)

## Fonctionnalites

- Interface en ligne de commande avec `--encrypt`, `--decrypt`, `--status` et `--help`.
- Detection de cle USB avec `psutil`.
- Initialisation automatique d'une cle USB non configuree lors du premier chiffrement.
- Generation d'une cle AES-256 aleatoire, stockee chiffree dans `CRYPTEUR/key.vault`.
- Protection de `key.vault` par une cle derivee avec `scrypt` depuis le PIN, l'UUID de partition et un `device.id`.
- Chiffrement et dechiffrement recursifs de dossiers.
- AES-GCM avec verification d'integrite.
- Sel et IV uniques par fichier.
- Traitement par blocs pour limiter l'utilisation memoire.
- Fichiers temporaires `*.tmp` avant remplacement final.
- Nettoyage des fichiers `*.tmp` orphelins avant traitement.
- Rapports JSON horodates avec statistiques et erreurs.

## Prerequis

- Python 3.12 ou superieur
- Une cle USB disponible
- Espace disque suffisant pour creer les fichiers temporaires

Dependances Python :

```txt
colorama==0.4.6
cryptography==46.0.3
psutil==7.1.3
tqdm==4.67.1
```

## Installation

Windows :

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

Linux/macOS :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Utilisation

Afficher l'aide :

```powershell
python main.py --help
```

Chiffrer un dossier :

```powershell
python main.py --encrypt C:\chemin\vers\dossier
```

Dechiffrer un dossier :

```powershell
python main.py --decrypt C:\chemin\vers\dossier
```

Afficher le statut de la cle USB :

```powershell
python main.py --status
```

Si le chemin contient des espaces, entourez-le avec des guillemets :

```powershell
python main.py --encrypt "C:\Users\Dereck\Pictures\mon dossier"
```

## Premier Usage

1. Lancez une commande de chiffrement avec `--encrypt`.
2. Branchez la cle USB et appuyez sur Entree.
3. Confirmez la cle detectee.
4. Si la cle n'est pas encore configuree, le programme cree automatiquement le dossier `CRYPTEUR`.
5. Definissez un PIN a exactement 8 chiffres.
6. Le programme genere une cle AES aleatoire et la stocke chiffree dans `key.vault`.
7. Le dossier cible est chiffre recursivement.

## Structure Sur La Cle USB

Apres initialisation, la cle USB contient :

```text
CRYPTEUR/
+-- device.id      # Identifiant aleatoire de 32 octets
+-- key.vault      # Cle AES chiffree
`-- meta.json      # Metadonnees de creation
```

Le PIN n'est pas stocke. Il sert a deriver une cle maitre permettant de dechiffrer `key.vault`.

## Rapports

La V3 actuelle ecrit les rapports JSON dans le dossier local :

```text
logs/
```

Chaque rapport contient notamment :

- le dossier traite
- l'operation
- le nombre de fichiers
- les succes et echecs
- la taille totale
- le debit moyen
- la duree
- les erreurs eventuelles

## Format Des Fichiers Chiffres

```text
[9 octets]  Header : ENCRYPTED
[1 octet]   Version du format
[16 octets] Sel scrypt
[12 octets] IV GCM
[Variable]  Donnees chiffrees
[16 octets] Tag GCM
```

Les fichiers chiffres prennent l'extension `.encrypted`. Au dechiffrement, cette extension est retiree.

## Structure Du Projet

```text
V3/
+-- main.py           # Point d'entree CLI
+-- config.py         # Constantes du projet
+-- crypto.py         # Derivation de cles, AES-GCM, HMAC
+-- usb.py            # Detection, initialisation et deverrouillage USB
+-- vault.py          # Lecture/ecriture du dossier CRYPTEUR
+-- processor.py      # Chiffrement/dechiffrement de dossiers
+-- display.py        # Affichage, couleurs et statistiques
+-- requirements.txt  # Dependances Python
+-- README.md         # Documentation
`-- LICENCE           # Licence MIT
```

## Securite

- La cle AES des fichiers est generee aleatoirement avec `os.urandom(32)`.
- La cle AES est stockee chiffree dans `key.vault`.
- La cle maitre est derivee avec `scrypt(PIN + UUID_partition + device_id)`.
- Chaque fichier utilise un sel unique et une sous-cle derivee.
- AES-GCM fournit confidentialite et verification d'integrite.
- Une mauvaise cle ou un fichier corrompu declenche une erreur de tag GCM.

Important : dans l'etat actuel du code, un PIN incorrect redemande une nouvelle saisie. Le blocage definitif apres 3 tentatives n'est pas implemente dans cette V3.

## Bonnes Pratiques

- Sauvegardez vos donnees avant un chiffrement massif.
- Testez le dechiffrement sur un petit dossier avant un usage reel.
- Gardez la cle USB dans un endroit sur.
- Ne perdez pas le PIN : sans la cle USB et le PIN, les donnees sont inaccessibles.
- N'interrompez pas le programme pendant une operation.

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENCE`.
