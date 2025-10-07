#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
serial_probe_viewer.py
-----------------------------------------
Author: JM Mari
Affiliation: Université de la Polynésie française (UPF)
Year: 2025
License: MIT

Description:
  Enhanced live & playback viewer for ESP32 Wi-Fi Sniffer (JSON/JSONL output).
  Designed to display Wi-Fi probe requests, management frames, and data frames
  captured by an ESP32 running in promiscuous mode with channel hopping enabled.

  The viewer supports:
    - Live serial streaming from ESP32 via COM port
    - Playback from JSONL capture files
    - Per-channel grouping and filtering
    - Real-time colored console display
    - Interactive keyboard shortcuts (logging, snapshots, clearing)
    - Vendor name inference from OUI (MAC prefix)

------------------------------------------------------------------------------
Usage examples:
------------------------------------------------------------------------------

  🟢 Live mode (direct serial read)
      python serial_probe_viewer.py COM4 921600

  🟠 File playback (read previously logged file)
      python serial_probe_viewer.py captures.jsonl

  🔵 Filter to one Wi-Fi channel only
      python serial_probe_viewer.py COM4 921600 --channel 6

  🟣 Show N last detections per channel (default 20)
      python serial_probe_viewer.py COM4 921600 --nlast 15

------------------------------------------------------------------------------
Command-line options:
------------------------------------------------------------------------------

  target         : Serial port (e.g. COM4, /dev/ttyUSB0) or JSONL filename.
  baud           : Baud rate for serial mode (default: 921600).
  --channel, -ch : Display only packets from the specified Wi-Fi channel (1–13).
  --nlast, -n    : Number of last detections to display per channel (default: 20).

------------------------------------------------------------------------------
Keyboard shortcuts (live mode):
------------------------------------------------------------------------------

  Ctrl-R : Toggle JSON logging (write to probes_log_N.jsonl).
  Ctrl-Q : Save current snapshot of buffer (snapshot_N.jsonl).
  Ctrl-W : Clear in-memory buffer and counters.
  Ctrl-C : Quit program safely (close serial/log files).

------------------------------------------------------------------------------
Displayed fields:
------------------------------------------------------------------------------

  CH       : Wi-Fi channel (1–13).
  TS       : Timestamp in milliseconds since ESP32 boot.
  MAC      : Source MAC address of the device.
  RSSI     : Received Signal Strength Indicator (dBm).
             - Strong signal  → closer device  (e.g., -40 dBm = very near)
             - Weak signal    → farther device (e.g., -85 dBm = far)
  SEQ      : Sequence number of the frame (if provided by sniffer).
  SSID     : Network name being probed (or "<hidden>" if not broadcast).
  VENDORS  : Manufacturer inferred from MAC OUI (first 3 bytes).

------------------------------------------------------------------------------
Dependencies:
------------------------------------------------------------------------------

  pip install pyserial colorama

------------------------------------------------------------------------------
Notes:
------------------------------------------------------------------------------
  - Only works with ESP32 firmwares that print JSON lines to the serial port.
  - Color output is terminal-friendly (Windows PowerShell, Linux, macOS).
  - Playback mode accepts files with one JSON object per line (.jsonl).
  - Vendor lookup is approximate and uses the OUI prefix.
  - RSSI and channel fields are hardware-reported by the ESP32 radio.
  - Works with all ESP32 channel hopping configurations (1–13 or custom).
------------------------------------------------------------------------------
"""

import sys, os, json, time, threading, argparse
from collections import deque, Counter
from colorama import init, Fore, Style
import serial.tools.list_ports

init(autoreset=True)

# ------------------------------------------------------------------------
# CLI arguments
# ------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="ESP32 Wi-Fi sniffer viewer with per-channel display",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("target", nargs="?", help="Serial port (e.g. COM4) or JSONL file for playback.")
parser.add_argument("baud", nargs="?", type=int, default=921600, help="Serial baudrate for live mode.")
parser.add_argument("--channel", "-ch", type=int, help="Display only packets from this Wi-Fi channel (1–13).")
parser.add_argument("--nlast", "-n", type=int, default=5, help="Number of detections shown per channel.")
args = parser.parse_args()

# ------------------------------------------------------------------------
# Vendor lookup table (short version placeholder)
# ------------------------------------------------------------------------
OUI_TABLE = {
    # --- Infrastructure & Networking ---
    "001018": "Cisco Systems",
    "00E04C": "Cisco Systems",
    "00D0B0": "Cisco Systems",
    "000E2B": "Broadcom",
    "001BCA": "Broadcom",
    "00050D": "Ubiquiti Networks",
    "001A11": "AVM (Fritz!Box)",
    "0017F2": "TP-Link / Arcadyan",
    "50:67:F3".replace(":", ""): "TP-Link",
    "54:EE:75".replace(":", ""): "TP-Link",
    "0019D2": "D-Link",
    "001018": "Cisco Systems",
    "00163E": "Apple (old)",
    "0022F7": "Realtek Semiconductor",
    "0C5BC2": "Realtek Semiconductor",
    "F0D1A9": "Intel Corporation",
    "0018E7": "Intel Corporation",
    "A45E60": "Espressif Systems (ESP32)",
    "B827EB": "Raspberry Pi Foundation",
    "3C5A37": "Google (Nest, Pixel)",
    "000FAC": "Qualcomm Atheros",
    "E8E5D6": "Qualcomm Technologies",
    "F09FC2": "Qualcomm Technologies",

    # --- PC & IT manufacturers ---
    "0013EF": "Dell Inc.",
    "000C29": "VMware Inc.",
    "000E08": "Hewlett-Packard",
    "0024D7": "HP Inc.",
    "001018": "Cisco Systems",
    "90:9F:33".replace(":", ""): "Lenovo",
    "A4:C3:F0".replace(":", ""): "Sony Corporation",
    "001018": "Cisco Systems",
    "FC3FDB": "Microsoft Corporation",
    "0050F2": "Microsoft Corporation",
    "F8E079": "ASUSTek Computer",
    "E0CB1D": "ASUSTek Computer",

    # --- Smartphones / Tablets ---
    "506F9A": "Apple Inc.",
    "D4:61:9D".replace(":", ""): "Apple Inc.",
    "F0:B4:29".replace(":", ""): "Apple Inc.",
    "A4:83:E7".replace(":", ""): "Apple Inc.",
    "30:07:4D".replace(":", ""): "Apple Inc.",
    "001B63": "Samsung Electronics",
    "B4:0B:2F".replace(":", ""): "Samsung Electronics",
    "44:4E:1A".replace(":", ""): "Samsung Electronics",
    "88:C6:26".replace(":", ""): "Samsung Electronics",
    "F4:F5:E8".replace(":", ""): "Huawei / Honor",
    "F4:F5:D8".replace(":", ""): "Huawei Technologies",
    "A4:0B:83".replace(":", ""): "Huawei Technologies",
    "D8:30:62".replace(":", ""): "Xiaomi / Redmi",
    "84:38:35".replace(":", ""): "Xiaomi / Redmi",
    "5C:49:79".replace(":", ""): "Xiaomi / Redmi",
    "FC:F5:C4".replace(":", ""): "Xiaomi / Redmi",
    "60:57:18".replace(":", ""): "Xiaomi / Redmi",
    "9C:0E:3F".replace(":", ""): "Xiaomi / Redmi",
    "E4:5F:01".replace(":", ""): "Xiaomi / Redmi",
    "30:83:98".replace(":", ""): "Xiaomi / Redmi",
    "38:2C:4A".replace(":", ""): "LG Electronics",
    "F8:1A:67".replace(":", ""): "OPPO Mobile",
    "00:6F:64".replace(":", ""): "OPPO Mobile",
    "74:23:44".replace(":", ""): "Vivo Mobile",
    "78:05:DC".replace(":", ""): "Vivo Mobile",
    "7C:2E:BD".replace(":", ""): "OnePlus",
    "BC:76:70".replace(":", ""): "OnePlus",
    "E0:37:2C".replace(":", ""): "Amazon Technologies (Echo / Fire)",
    "70:88:6B".replace(":", ""): "Amazon Technologies",
    "A0:02:DC".replace(":", ""): "Google Nest / Chromecast",

    # --- IoT / Wearables ---
    "74:DA:38".replace(":", ""): "MediaTek Inc.",
    "74:26:B9".replace(":", ""): "MediaTek Inc.",
    "28:6A:BA".replace(":", ""): "MediaTek Inc.",
    "4C:65:A8".replace(":", ""): "Hon Hai / Foxconn",
    "00:1E:C0".replace(":", ""): "LG Innotek",
    "88:4A:EA".replace(":", ""): "Fitbit / Google Wear",
    "B8:27:EB".replace(":", ""): "Raspberry Pi Foundation",
    "A4:CF:12".replace(":", ""): "Tuya Smart / IoT Devices",
    "C8:2B:96".replace(":", ""): "Tuya Smart / IoT Devices",
    "44:33:4C".replace(":", ""): "Wyze Labs / Smart Home",
    "A0:20:A6".replace(":", ""): "Ring / Amazon Blink",
    "FC:58:FA".replace(":", ""): "Sonos Inc.",

    # --- Automotive & Misc ---
    "F0:03:8C".replace(":", ""): "Tesla Motors",
    "88:15:44".replace(":", ""): "Tesla Motors",
    "84:FC:FE".replace(":", ""): "Volkswagen AG",
    "78:24:AF".replace(":", ""): "BMW Group",
    "A0:32:99".replace(":", ""): "Mercedes-Benz",
    "58:91:CF".replace(":", ""): "Ford Motor Company",

    # --- Generic fallback examples ---
    "FCF5C4": "Xiaomi / Redmi",
    "E45F01": "Xiaomi / Redmi",
    "0C5BC2": "Realtek Semiconductor",
    "E0D4E8": "Unknown IoT Device",
    "AABBCC": "Generic Vendor Example"
}

# Normalize keys (uppercase, no separators)
OUI_TABLE = {k.upper().replace(":", "").replace("-", ""): v for k, v in OUI_TABLE.items()}

def lookup_vendor(ouis: str) -> str:
    """Return vendor name(s) from OUI hex list."""
    if not ouis:
        return ""
    names = []
    for part in ouis.split(","):
        key = part.strip().upper().replace(":", "")
        if len(key) < 6:
            continue
        names.append(OUI_TABLE.get(key[:6], key))
    return ",".join(names)

# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------
def auto_detect_port():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("❌ Aucun port série détecté.")
        sys.exit(1)
    if len(ports) == 1:
        return ports[0].device
    print("Ports disponibles :")
    for i, p in enumerate(ports):
        print(f"  [{i}] {p.device} - {p.description}")
    sel = input("Choisissez un port (numéro) : ").strip()
    try:
        return ports[int(sel)].device
    except:
        return ports[0].device

def color_rssi(rssi):
    """Color-code RSSI for readability."""
    try:
        rssi = int(rssi)
    except:
        return str(rssi)
    if rssi > -50:
        return Fore.GREEN + str(rssi) + Style.RESET_ALL
    elif rssi > -70:
        return Fore.YELLOW + str(rssi) + Style.RESET_ALL
    else:
        return Fore.RED + str(rssi) + Style.RESET_ALL

def color_channel(ch):
    if ch <= 5:
        return Fore.GREEN + f"{ch}" + Style.RESET_ALL
    elif ch <= 9:
        return Fore.YELLOW + f"{ch}" + Style.RESET_ALL
    else:
        return Fore.RED + f"{ch}" + Style.RESET_ALL

# ------------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------------
MAX_RECENT = 200
recent_by_channel = {ch: deque(maxlen=MAX_RECENT) for ch in range(1, 15)}
mac_counts = Counter()

def pretty_print():
    """Print summary table grouped by channel."""
    print("\033[2J\033[H", end="")  # clear screen
    print("Wi-Fi detections (grouped by channel)")
    print("-" * 110)
    print(f"{'CH':<3}   {'TS':<8} {'MAC':<20} {'RSSI':>5} {'SEQ':>6}     {'SSID':<22} {'VENDORS':<20}")
    print("-" * 110)
    for ch in range(1, 14):
        if args.channel and ch != args.channel:
            continue
        entries = list(recent_by_channel[ch])[-args.nlast:]
        for entry in entries[::-1]:
            ts = entry.get("ts", "")
            mac = entry.get("addr2") or entry.get("mac", "")
            rssi = entry.get("rssi", "")
            seq = entry.get("seq", "")
            ssid = entry.get("ssid", "")
            vendor_hex = entry.get("vendor", "")
            vendor_names = lookup_vendor(vendor_hex)
            print(f"{color_channel(ch):<3}   {str(ts):<8} {mac:<20}     {color_rssi(rssi):>5} {str(seq):>6}     {ssid[:22]:<22} {vendor_names[:20]:<20}")
    print("-" * 110)
    print(Fore.CYAN + "Top MACs:" + Style.RESET_ALL)
    for mac, c in mac_counts.most_common(5):
        print(f"  {mac:<20} {c:>4}")
    print(Fore.CYAN + "\nCtrl-R: toggle log | Ctrl-Q: snapshot | Ctrl-W: clear | Ctrl-C: quit" + Style.RESET_ALL)

# ------------------------------------------------------------------------
# File playback mode
# ------------------------------------------------------------------------
if args.target and os.path.isfile(args.target):
    fname = args.target
    print(f"Reading file {fname}...")
    with open(fname, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "{" not in line:
                continue
            try:
                obj = json.loads(line[line.find("{"):])
            except:
                continue
            ch = obj.get("ch", obj.get("hdr_ch", 0))
            if args.channel and ch != args.channel:
                continue
            recent_by_channel.setdefault(ch, deque(maxlen=MAX_RECENT)).append(obj)
            mac = obj.get("mac") or obj.get("addr2")
            if mac:
                mac_counts[mac] += 1
    pretty_print()
    print(Fore.GREEN + f"\nDisplayed {sum(len(q) for q in recent_by_channel.values())} detections." + Style.RESET_ALL)
    sys.exit(0)

# ------------------------------------------------------------------------
# Live serial mode
# ------------------------------------------------------------------------
import serial, msvcrt

if not args.target:
    PORT = auto_detect_port()
    BAUD = args.baud
else:
    PORT = args.target
    BAUD = args.baud

print(f"Opening {PORT} @ {BAUD} baud...")
ser = serial.Serial(PORT, BAUD, timeout=1)

logging_enabled = False
log_file = None
log_index = 1
snapshot_index = 1

def toggle_logging():
    global logging_enabled, log_file, log_index
    logging_enabled = not logging_enabled
    if logging_enabled:
        fname = f"probes_log_{log_index}.jsonl"
        log_index += 1
        log_file = open(fname, "w", encoding="utf-8")
        print(Fore.GREEN + f"\n>>> Logging to {fname}" + Style.RESET_ALL)
    else:
        if log_file:
            log_file.close()
        log_file = None
        print(Fore.YELLOW + "\n>>> Logging stopped" + Style.RESET_ALL)

def save_snapshot():
    global snapshot_index
    fname = f"snapshot_{snapshot_index}.jsonl"
    snapshot_index += 1
    with open(fname, "w", encoding="utf-8") as f:
        for ch in range(1, 14):
            for entry in recent_by_channel[ch]:
                f.write(json.dumps(entry) + "\n")
    print(Fore.CYAN + f"\n>>> Snapshot saved to {fname}" + Style.RESET_ALL)

def key_listener():
    while True:
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'\x12':   # Ctrl-R
                toggle_logging()
            elif key == b'\x11': # Ctrl-Q
                save_snapshot()
            elif key == b'\x17': # Ctrl-W
                for q in recent_by_channel.values():
                    q.clear()
                mac_counts.clear()
                print(Fore.MAGENTA + "\n>>> Cleared in-memory data" + Style.RESET_ALL)
        time.sleep(0.05)

threading.Thread(target=key_listener, daemon=True).start()

# ------------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------------
last_refresh = time.time()
try:
    while True:
        line = ser.readline()
        if not line:
            if time.time() - last_refresh > 2:
                pretty_print()
                last_refresh = time.time()
            continue
        try:
            s = line.decode(errors="ignore").strip()
        except:
            continue
        if not s or "{" not in s:
            continue
        try:
            obj = json.loads(s[s.find("{"):])
        except Exception:
            continue
        ch = obj.get("ch", obj.get("hdr_ch", 0))
        if args.channel and ch != args.channel:
            continue
        recent_by_channel.setdefault(ch, deque(maxlen=MAX_RECENT)).append(obj)
        mac = obj.get("mac") or obj.get("addr2")
        if mac:
            mac_counts[mac] += 1
        if logging_enabled and log_file:
            log_file.write(json.dumps(obj) + "\n")
            log_file.flush()
        if time.time() - last_refresh > 2:
            pretty_print()
            last_refresh = time.time()

except KeyboardInterrupt:
    print("\nExiting.")
    if log_file:
        log_file.close()
    ser.close()
