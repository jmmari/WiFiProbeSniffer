#!/bin/bash
echo "[*] Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "[*] Setup complete."
echo "Usage:"
echo "  - Live sniffing : ./venv/bin/python serial_probe_viewer.py"
echo "  - Live sniffing : ./venv/bin/python serial_probe_viewer.py COM3 115200"
echo "  - Playback log  : ./venv/bin/python serial_probe_viewer.py probes_log_1.jsonl"
