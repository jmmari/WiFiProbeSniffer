# WiFi Probe Sniffer (ESP32/ESP8266 + Python)
An ESP32 WiFi Probe Sniffer with Python script for reading the detections

Un petit outil pour **sniffer les Probe Requests Wi-Fi** avec un ESP32/ESP8266, 
et les afficher joliment sur PC (Windows/Linux/macOS) avec **Python**.  
Affichage en **JSON coloré**, possibilité de **logger**, **prendre un snapshot**, et **effacer le buffer en mémoire**.

## 📦 Fonctionnalités

- Capture des Probe Requests avec l’ESP32 (firmware Arduino fourni).
- Sortie **JSON** envoyée par l’ESP32 → traitée par Python.
- Affichage en tableau coloré (RSSI vert/jaune/rouge).
- Détection des **vendors (constructeurs)** à partir des adresses MAC.
- **Contrôles clavier en direct** :
  - `Ctrl-R` → démarrer/arrêter l’enregistrement (`probes_log_N.jsonl`)
  - `Ctrl-Q` → snapshot instantané (`snapshot_N.jsonl`)
  - `Ctrl-W` → effacer le buffer en mémoire (n’affecte pas les fichiers)
  - `Ctrl-C` → quitter

## ⚡ Prérequis

- Un **ESP32** (ou ESP8266) flashé avec le firmware `Interceptor_8266_V1.ino`.
- Python **3.8+**
- Les dépendances : `pyserial`, `colorama`

## 🛠 Installation

### Windows
```powershell
git clone https://github.com/tonpseudo/WiFiProbeSniffer.git
cd WiFiProbeSniffer\host
setup.bat
Linux / macOS
bash
Copier le code
git clone https://github.com/tonpseudo/WiFiProbeSniffer.git
cd WiFiProbeSniffer/host
chmod +x setup.sh
./setup.sh

Les scripts setup.* :
- créent un environnement virtuel Python (venv/),
- installent automatiquement les dépendances.

▶️ Utilisation
1. Flasher l’ESP32
Ouvrir firmware/Interceptor_8266_V1.ino dans Arduino IDE, sélectionner la carte ESP32, et flasher.

2. Lancer le sniffer
Windows :

powershell
Copier le code
start_sniffer.bat
Linux/macOS :

bash
Copier le code
./start_sniffer.sh
Le script essaie de détecter automatiquement le port série.
Sinon, il affichera la liste des ports disponibles (COM4, /dev/ttyUSB0, etc.) et vous demandera de choisir.

📊 Exemple de sortie
markdown
Copier le code
Probe requests (most recent first) — total stored: 3
----------------------------------------------------------------------------------------------------
TS       MAC                   RSSI  CH    SEQ SSID                   VENDORS
----------------------------------------------------------------------------------------------------
15668    42:8E:CC:82:01:FD      -76   6   2889 TP-Link_F184_5G        TP-Link/Arcadyan, Microsoft
15465    42:8E:CC:82:01:FD      -77   6   2881 TP-Link_F184_5G        TP-Link/Arcadyan, Microsoft
12233    92:C2:85:F3:E1:0F      -42   6    583 <hidden>               Apple, Microsoft
----------------------------------------------------------------------------------------------------
Top MACs:
  42:8E:CC:82:01:FD : 2
  92:C2:85:F3:E1:0F : 1

Press Ctrl-C to quit.
      Ctrl-R : toggle logging (write to probes_log_N.jsonl)
      Ctrl-Q : save snapshot (snapshot_N.jsonl)
      Ctrl-W : clear in-memory buffer (does NOT delete files)
