# certlive

`certlive` est un petit outil en Python qui se connecte au flux public
[certstream](https://certstream.calidog.io/) (agrégateur des logs
[Certificate Transparency](https://certificate.transparency.dev/)) et
affiche en temps réel la liste des domaines associés à **chaque
certificat TLS nouvellement émis**, quel que soit son type (DV, OV, EV,
wildcard, Let's Encrypt, DigiCert, etc.).

## Installation

```bash
git clone https://github.com/Marlbogaro/certlive.git
cd certlive
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Utilisation

```bash
# Afficher tous les domaines en continu
python certlive.py

# Enregistrer les domaines dans un fichier (append)
python certlive.py -o domains.txt

# Filtrer sur un mot-clé (insensible à la casse)
python certlive.py -k paypal

# Ignorer les domaines wildcard (*.exemple.com)
python certlive.py --no-wildcard

# Mode verbeux : horodatage + émetteur
python certlive.py -v
```

Arrêter avec `Ctrl+C`.

### Options

| Option | Description |
|---|---|
| `-o`, `--output FICHIER` | Ajoute chaque domaine dans un fichier (un par ligne). |
| `-k`, `--keyword MOT` | Ne garde que les domaines contenant ce mot-clé. |
| `--no-wildcard` | Ignore les domaines commençant par `*.`. |
| `-v`, `--verbose` | Affiche aussi l'horodatage et l'émetteur du certificat. |
| `-u`, `--url URL` | URL du serveur certstream (défaut: `wss://certstream.calidog.io/`). |

## Fonctionnement

Chaque nouveau certificat émis publiquement est publié dans les logs
Certificate Transparency. Le service [certstream](https://certstream.calidog.io/)
agrège ces logs et les diffuse via WebSocket. `certlive` :

1. Ouvre une connexion WebSocket vers le serveur certstream.
2. Reçoit les événements `certificate_update`.
3. Extrait la liste des domaines (`CN` + `SAN`) de chaque certificat.
4. Applique les filtres éventuels et affiche / enregistre les domaines.

## Licence

Voir [LICENSE](LICENSE).
