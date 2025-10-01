@echo off
echo === Wi-Fi Sniffer (ESP32/ESP8266) ===
echo Recherche du port série...

:: active venv si besoin
call venv\Scripts\activate

python -m pip install -q pyserial colorama

python - <<END
import serial.tools.list_ports
ports = list(serial.tools.list_ports.comports())
if not ports:
    print("Aucun port série détecté. Branchez l'ESP32.")
else:
    for p in ports:
        print(" -", p.device, p.description)
    if len(ports) == 1:
        import os
        os.system(f"python serial_probe_viewer.py {ports[0].device} 115200")
    else:
        print("Choisissez le port et lancez manuellement :")
        print("   python serial_probe_viewer.py COMX")
END
pause
