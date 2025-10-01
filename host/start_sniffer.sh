#!/bin/bash
#
#
# chmod +x start_sniffer.sh
# ./start_sniffer.sh
# 
echo "=== Wi-Fi Sniffer (ESP32/ESP8266) ==="
echo "Recherche du port série..."

# Active le venv si besoin
source venv/bin/activate 2>/dev/null

# installe dépendances
pip install -q pyserial colorama

PORTS=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null)

if [ -z "$PORTS" ]; then
    echo "Aucun port série détecté. Branchez l'ESP32."
    exit 1
fi

COUNT=$(echo "$PORTS" | wc -w)

if [ $COUNT -eq 1 ]; then
    PORT=$PORTS
    echo "Port détecté : $PORT"
    python3 serial_probe_viewer.py $PORT 115200
else
    echo "Plusieurs ports détectés :"
    echo "$PORTS"
    echo "Lancez avec : python3 serial_probe_viewer.py /dev/ttyUSBX"
fi
