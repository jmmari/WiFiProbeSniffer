#!/usr/bin/env python3
# serial_probe_viewer.py
#
# JM MARI, Université de la Polynésie française (UPF), 2025
#
# Usage:
#   Live mode   : python serial_probe_viewer.py COM3 115200
#   Playback    : python serial_probe_viewer.py probes_log_1.jsonl
# ------------------------------------------------------------------------
# Probe Request / Wi-Fi Packet Fields Displayed
#
# TS        : Timestamp in milliseconds since ESP32 boot (relative clock).
# MAC       : Source MAC address of the sender device.
# RSSI      : Received Signal Strength Indicator (dBm). 
#             - Closer devices → higher (less negative), e.g. -40 dBm = very strong.
#             - Further devices → lower (more negative), e.g. -85 dBm = weak signal.
# CH        : Wi-Fi channel (1–14 in 2.4 GHz; ESP32 only supports 2.4 GHz sniffing).
# SEQ       : Sequence number from the 802.11 header.
#             - Increases with each frame sent by a device.
#             - Can be used to detect retransmissions or bursts.
# SSID      : The SSID (network name) being probed.
#             - "<hidden>" means the device is probing without specifying a network.
#             - Otherwise shows the target Wi-Fi name the client is searching for.
# VENDORS   : Vendor names inferred from the OUI (first 3 bytes of MAC address).
#             - Helps identify the manufacturer (Apple, Samsung, Xiaomi, etc).
#             - Multiple OUIs may appear if vendor-specific Information Elements (IEs) are present.
#
# Notes:
# - Only management frames (like Probe Requests) are fully parsed here.
# - Other frame types (data, beacons, control) are still captured but less detailed.
# - RSSI and channel come from the ESP32 hardware radio (hdr_ch).
# - Vendor lookup is approximate (based on known OUI table).
#
# Keyboard shortcuts in live mode:
#   Ctrl-R : Toggle logging to a JSONL file (probes_log_N.jsonl).
#   Ctrl-Q : Save current snapshot of recent probes to a file (snapshot_N.jsonl).
#   Ctrl-W : Wipe in-memory buffer (clear screen + counters, files unaffected).
#
# Usage:
#   Live sniffing : python serial_probe_viewer.py COM3 115200
#   Playback log  : python serial_probe_viewer.py probes_log_1.jsonl
# ------------------------------------------------------------------------

import sys, json, time, os, threading
from collections import deque, Counter
from colorama import init, Fore, Style
import serial.tools.list_ports

def auto_detect_port():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("Aucun port série détecté. Branchez l'ESP32/ESP8266.")
        sys.exit(1)
    if len(ports) == 1:
        return ports[0].device
    print("Ports disponibles :")
    for p in ports:
        print("  ", p.device, "-", p.description)
    # si plusieurs → demande à l’utilisateur
    choice = input("Entrez le port à utiliser (ex: COM3): ").strip()
    return choice

init(autoreset=True)
# --- Extended OUI table (common vendors incl. many Chinese vendors) ---
OUI_TABLE = {
    "0050F2": "Microsoft",
    "506F9A": "Apple",
    "3C5A37": "Google",
    "F0D1A9": "Intel",
    "000C29": "VMware",
    "B827EB": "Raspberry Pi",
    "A45E60": "Espressif",
    "00163E": "Apple (old)",
    "00050D": "Ubiquiti",
    "D83062": "Xiaomi",
    "F4F5D8": "Huawei",
    "0017F2": "TP-Link/Arcadyan",
    "001018": "Cisco",
    "0013EF": "Dell",
    "001B63": "Samsung",
    "000FAC": "Qualcomm Atheros",
    "0022F7": "Realtek",
    "74:DA:38".replace(":",""): "MediaTek",
    "7426B9": "MediaTek",
    "0019D2": "D-Link",
    "F4:F5:E8".replace(":",""): "Honor/Huawei",
    "5C:49:79".replace(":",""): "Xiaomi",
    "A4:C3:F0".replace(":",""): "Sony",
    "90:9F:33".replace(":",""): "Lenovo",
    "50:67:F3".replace(":",""): "TP-Link",
    "E0:37:2C".replace(":",""): "Amazon",
    "B4:0B:2F".replace(":",""): "Samsung",
    "30:83:98".replace(":",""): "Xiaomi",
    "38:2C:4A".replace(":",""): "LG Electronics",
    "F8:1A:67".replace(":",""): "OPPO",
    "84:38:35".replace(":",""): "Xiaomi",
    "00E04C": "Cisco Systems",
    "001A11": "AVM (Fritz!)",
    "000E08": "Hewlett Packard",
    "0024D7": "HP Inc",
    "FCF5C4": "Xiaomi",
    "74DA38": "MediaTek",
    "A40B83": "Huawei",
    "0013EF": "Dell",
    "9C:0E:3F".replace(":",""): "Xiaomi",
    "60:57:18".replace(":",""): "Xiaomi",
    "54:EE:75".replace(":",""): "TP-Link",
    "00D0B0": "Cisco Systems",
    "000E2B": "Broadcom",
    "001BCAF5"[:6]: "Broadcom",
    # fallback examples
    "E4:5F:01".replace(":",""): "Xiaomi",
    "4C:65:A8".replace(":",""): "Hon Hai/Foxconn",
    "FCF5C4": "Xiaomi",
    "0C:5B:C2".replace(":",""): "Realtek",
    # ... you can extend this dict with more OUIs ...
}
# Normalize keys to uppercase without separators
OUI_TABLE = {k.upper().replace(":", "").replace("-", ""): v for k, v in OUI_TABLE.items()}

def lookup_vendor(ouis: str) -> str:
    if not ouis:
        return ""
    names = []
    for part in ouis.split(","):
        key = part.strip().upper().replace(":", "")
        if len(key) < 6:  # invalid OUI
            names.append("Unknown")
            continue
        names.append(OUI_TABLE.get(key, key))
    return ",".join(names)

# ------------------- Shared state -------------------
MAX_RECENT = 200
recent = deque(maxlen=MAX_RECENT)
mac_counts = Counter()

# ------------------- Pretty print -------------------
def pretty_print():
    print("\033[2J\033[H", end="")  # clear screen
    print("Probe requests (most recent first) — total stored:", len(recent))
    print("-" * 100)
    print(f"{'TS':<8} {'MAC':<20} {'RSSI':>5} {'CH':>3} {'SEQ':>6} {'SSID':<22} {'VENDORS':<20}")
    print("-" * 100)
    for entry in list(recent)[-20:][::-1]:
        ts = entry.get("ts", "")
        mac = entry.get("mac", "")
        rssi = entry.get("rssi", "")
        ch = entry.get("hdr_ch", entry.get("channel", ""))
        seq = entry.get("seq", "")
        ssid = entry.get("ssid", "")
        vendor_hex = entry.get("vendor", "")
        vendor_names = lookup_vendor(vendor_hex)
        # color RSSI
        rssi_str = str(rssi)
        if rssi != "":
            try:
                rssi_val = int(rssi)
                if rssi_val > -50:
                    rssi_str = Fore.GREEN + str(rssi) + Style.RESET_ALL
                elif rssi_val > -70:
                    rssi_str = Fore.YELLOW + str(rssi) + Style.RESET_ALL
                else:
                    rssi_str = Fore.RED + str(rssi) + Style.RESET_ALL
            except:
                pass
        print(f"{str(ts):<8} {mac:<20} {rssi_str:>5} {str(ch):>3} {str(seq):>6} {ssid[:22]:<22} {vendor_names[:20]:<20}")
    print("-" * 100)
    print("Top MACs:")
    for mac, c in mac_counts.most_common(10):
        print(f"  {mac} : {c}")
    print(Fore.CYAN + "\nPress Ctrl-C to quit." + Style.RESET_ALL)
    print(Fore.CYAN + "      Ctrl-R : toggle logging (write to probes_log_N.jsonl)" + Style.RESET_ALL)
    print(Fore.CYAN + "      Ctrl-Q : save snapshot (snapshot_N.jsonl)" + Style.RESET_ALL)
    print(Fore.CYAN + "      Ctrl-W : clear in-memory buffer (does NOT delete files)" + Style.RESET_ALL)

#----------------------------------------------------------------------------------------------
# --- Detect mode / arguments ---
if len(sys.argv) > 1:
    target = sys.argv[1]
    is_file_mode = os.path.isfile(target)
else:
    target = None
    is_file_mode = False


if is_file_mode:
    # -------- File playback --------
    fname = target
    print(f"Opening file {fname} for playback...")
    with open(fname, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "{" not in line:
                continue
            try:
                j = line.find("{")
                obj = json.loads(line[j:])
            except Exception:
                continue
            mac = obj.get("mac") or obj.get("addr") or obj.get("source")
            if not mac:
                continue
            recent.append(obj)
            mac_counts[mac] += 1
    pretty_print()
    print(Fore.CYAN + f"\nDisplayed {len(recent)} events from {fname}" + Style.RESET_ALL)
    sys.exit(0)

# -------- Live serial mode --------
import serial, msvcrt

# Decide target and baudrate
if target is None:
    print("\nUsage:\nLive mode   : python serial_probe_viewer.py COM3 115200\nPlayback    : python serial_probe_viewer.py probes_log_1.jsonl\n")
    print("\n=== Wi-Fi Probe Request Sniffer ===")
    print("Usage examples:")
    print("  Auto sniffing : python serial_probe_viewer.py")
    print("  Live sniffing : python serial_probe_viewer.py COM3 115200")
    print("  Playback log  : python serial_probe_viewer.py probes_log_1.jsonl\n")

    print("Keyboard shortcuts (live mode):")
    print("  Ctrl-R : toggle logging (write to probes_log_N.jsonl)")
    print("  Ctrl-Q : save snapshot (snapshot_N.jsonl)")
    print("  Ctrl-W : clear in-memory buffer (does NOT delete files)")
    print("  Ctrl-C : quit\n")

    print("Displayed parameters:")
    print("  TS     : timestamp (ms since boot)")
    print("  MAC    : source MAC address of the client")
    print("  RSSI   : signal strength (dBm)")
    print("  CH     : Wi-Fi channel")
    print("  SEQ    : sequence number (frame counter per device)")
    print("  SSID   : probed network name ('<hidden>' if none)")
    print("  VENDORS: vendor inferred from MAC OUI\n")
    # No args → auto detect port, assume 115200 baud
    target = auto_detect_port()
    PORT = target
    BAUD = 115200
else:
    # Normalize port
    if target.upper().startswith("COM") or target.startswith("/dev/"):
        PORT = target
    else:
        PORT = auto_detect_port()
    BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 115200

# Open serial
ser = serial.Serial(PORT, BAUD, timeout=1)
print(f"Opened {PORT} @ {BAUD}")

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
        print(Fore.GREEN + f"\n>>> Logging enabled, writing to {fname}" + Style.RESET_ALL)
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
        for entry in recent:
            f.write(json.dumps(entry) + "\n")
    print(Fore.CYAN + f"\n>>> Snapshot saved to {fname}" + Style.RESET_ALL)

def key_listener():
    global recent, mac_counts
    while True:
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'\x12':   # Ctrl-R
                toggle_logging()
            elif key == b'\x11': # Ctrl-Q (instead of Ctrl-S)
                save_snapshot()
            elif key == b'\x17': # Ctrl-W
                recent.clear()
                mac_counts.clear()
                print(Fore.MAGENTA + "\n>>> In-memory data cleared" + Style.RESET_ALL)


threading.Thread(target=key_listener, daemon=True).start()

last_print = time.time()
try:
    while True:
        line = ser.readline()
        if not line:
            if time.time() - last_print > 2:
                pretty_print()
                last_print = time.time()
            continue
        try:
            s = line.decode(errors="ignore").strip()
        except:
            continue
        if not s or "{" not in s:
            continue
        try:
            j = s.find("{")
            obj = json.loads(s[j:])
        except Exception:
            continue
        mac = obj.get("mac") or obj.get("addr") or obj.get("source")
        if not mac:
            continue
        recent.append(obj)
        mac_counts[mac] += 1
        if logging_enabled and log_file:
            log_file.write(json.dumps(obj) + "\n")
            log_file.flush()
        vendor_names = lookup_vendor(obj.get("vendor", ""))
        print(f"[{obj.get('ts','')}] {mac} rssi={obj.get('rssi','')} ch={obj.get('hdr_ch', obj.get('channel',''))} ssid=\"{obj.get('ssid','')}\" vendors={vendor_names}")
        if time.time() - last_print > 2:
            pretty_print()
            last_print = time.time()
except KeyboardInterrupt:
    print("\nExiting.")
    if log_file:
        log_file.close()
    ser.close()