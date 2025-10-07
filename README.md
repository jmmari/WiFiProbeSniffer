🛰️ WiFi Probe Sniffer — ESP32 + Python Viewer
A multi-channel Wi-Fi sniffer using ESP32 and a Python live viewer

Now supports all Wi-Fi channels (1–13) with channel hopping, JSON output, and a colorful real-time console viewer.

🧩 Overview

This project turns your ESP32 (or ESP8266) into a Wi-Fi Probe Sniffer —
it captures all nearby 802.11 frames (beacons, probe requests, data frames...)
and sends them in JSON format to your PC via serial port.

On the computer, a Python script (serial_probe_viewer.py) displays the packets live,
with RSSI color coding, channel grouping, vendor lookup, and live logging controls.

⚙️ Features

📡 Capture Wi-Fi frames (Probe Requests, Beacons, Data, Control)

🔀 Automatic channel hopping (1–13 by default)

💾 JSON output over serial (parsable, colorized)

🧠 Vendor detection from MAC OUI (Apple, Samsung, Xiaomi, etc.)

🧮 Channel filtering & per-channel summaries

⌨️ Interactive console controls:

Shortcut	Action
Ctrl-R	Start/stop live logging (probes_log_N.jsonl)
Ctrl-Q	Save snapshot (snapshot_N.jsonl)
Ctrl-W	Clear in-memory buffer (no files affected)
Ctrl-C	Quit cleanly
🧰 Requirements

ESP32 or ESP8266 (recommended: ESP32 with 4 MB flash)

Python 3.8+

Dependencies:

pip install pyserial colorama

🧠 Firmware Setup

Open the firmware file (e.g. Interceptor_ESP32_V1.ino) in the Arduino IDE.

Select your ESP32 board and correct serial port (e.g. COM4 or /dev/ttyUSB0).

Flash the firmware to your ESP32.

When booted, the ESP32 will print JSON detections at 921600 baud.

Optional serial commands
Command	Description
HOP ON / HOP OFF	Enable/disable channel hopping
SET CH ALL	Hop across all 13 channels
SET CH 1,6,11	Limit hopping to specific channels
SET HOP_MS 300	Change hopping delay (ms)
SHOW	Display current parameters
LOG FILE ON	Record raw packets to flash memory
DUMP FILE JSON	Dump capture file as JSON stream
🧑‍💻 Python Viewer (serial_probe_viewer.py)

The Python script provides both live viewing and offline playback from saved .jsonl files.

▶️ Usage examples
Live mode (direct from ESP32)
python serial_probe_viewer.py COM4 921600

Playback from saved log
python serial_probe_viewer.py captures.jsonl

Filter one channel only
python serial_probe_viewer.py COM4 921600 --channel 6

Show last 15 packets per channel
python serial_probe_viewer.py COM4 921600 --nlast 15

🪄 Installation (Windows / Linux / macOS)
Windows PowerShell
git clone https://github.com/tonpseudo/WiFiProbeSniffer.git
cd WiFiProbeSniffer\host
setup.bat

Linux / macOS
git clone https://github.com/tonpseudo/WiFiProbeSniffer.git
cd WiFiProbeSniffer/host
chmod +x setup.sh
./setup.sh


The setup scripts will:

Create a virtual Python environment (venv/)

Install all dependencies automatically.

📊 Example Output
Wi-Fi detections (grouped by channel)
--------------------------------------------------------------------------------------------------------------
CH  TS       MAC                  RSSI   SEQ   SSID                  VENDORS
--------------------------------------------------------------------------------------------------------------
1   9181702  50:E6:36:4A:7A:8F    -73          <hidden>             Samsung
1   9180945  40:ED:00:BC:F1:83    -41          MyNetwork            Huawei
2   9181330  50:E6:36:4A:7A:8F    -76          <hidden>             Samsung
6   9182099  92:C2:85:F3:E1:0F    -42          Livebox-5G           Apple, Microsoft
--------------------------------------------------------------------------------------------------------------
Top MACs:
  42:ED:00:81:F7:AE : 148
  50:E6:36:4A:7A:8F : 96
--------------------------------------------------------------------------------------------------------------
Ctrl-R: toggle log | Ctrl-Q: snapshot | Ctrl-W: clear | Ctrl-C: quit

🧪 Advanced Notes

Works in real time (≈500–1500 frames/s at 921600 baud)

Each JSON line can be piped to other tools:

python acquireWiFiDetections.py -s | jq .


You can visualize or process captures with tools like:

jq (CLI JSON filter)

Wireshark (after conversion)

pandas / matplotlib (Python analysis)

🧱 Repository Structure
WiFiProbeSniffer/
├── firmware/
│   ├── Interceptor_ESP32_V1.ino     # ESP32 firmware
│   └── ...                          # support files
├── host/
│   ├── serial_probe_viewer.py       # live Python viewer
│   ├── acquireWiFiDetections.py     # JSON acquisition tool
│   ├── displayWiFiCaptures.py       # simple tail-style viewer
│   └── setup.sh / setup.bat         # environment setup
└── docs/
    └── README.md                    # this file

📜 License

This project is released under the MIT License.
© 2025 — Université de la Polynésie française (UPF), JM Mari
