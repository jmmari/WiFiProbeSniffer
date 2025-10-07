#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
displayWiFiCaptures.py
-----------------------------------------
Author: JM Mari
Affiliation: Université de la Polynésie française (UPF)
Year: 2025
License: MIT

Description:
  Displays Wi-Fi detections (JSON lines) from a file or stdin
  with a real-time updating table.

Usage examples:
  python displayWiFiCaptures.py --file detections.json
  cat detections.json | python displayWiFiCaptures.py -n 15
  python -u acquireWiFiDetections.py -s | python displayWiFiCaptures.py -n 20

Dependencies:
  pip install colorama
"""

import sys, json, time, argparse, os
from collections import deque
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Real-time display of Wi-Fi detections from JSON stream or file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--file", "-f", type=str, help="JSONL file to read (if omitted, reads from stdin).")
    parser.add_argument("--nrows", "-n", type=int, default=10, help="Number of lines to display.")
    parser.add_argument("--interval", "-i", type=float, default=0.5, help="Refresh interval in seconds.")
    parser.add_argument("--follow", action="store_true", help="Follow file like 'tail -f'.")
    return parser.parse_args()

args = parse_args()

# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------
def clear_screen():
    """Clear terminal screen."""
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def color_rssi(rssi):
    """Color-code RSSI value."""
    if rssi is None:
        return "-"
    if rssi > -50:
        return Fore.GREEN + f"{rssi:>4}" + Style.RESET_ALL
    elif rssi > -70:
        return Fore.YELLOW + f"{rssi:>4}" + Style.RESET_ALL
    else:
        return Fore.RED + f"{rssi:>4}" + Style.RESET_ALL

def color_type(t):
    if t == "Management":
        return Fore.CYAN + t + Style.RESET_ALL
    elif t == "Control":
        return Fore.MAGENTA + t + Style.RESET_ALL
    elif t == "Data":
        return Fore.RED + t + Style.RESET_ALL
    else:
        return t

def parse_json_line(line):
    try:
        return json.loads(line)
    except Exception:
        return None

def print_table(entries, total=0, rate=0.0):
    clear_screen()
    print(Fore.WHITE + Style.BRIGHT + f"Last {len(entries)} Wi-Fi detections:" + Style.RESET_ALL)
    print("-" * 90)
    print(f"{'Type':<12} {'Subtype':<12} {'Ch':<3} {'RSSI':<6} {'MAC':<20} {'SSID'}")
    print("-" * 90)
    for e in entries:
        t = e.get("type", "?")
        st = e.get("subtype", "")
        ch = e.get("ch", "?")
        rssi = e.get("rssi", None)
        mac = e.get("addr2", e.get("mac", ""))
        ssid = e.get("ssid", "")
        print(f"{color_type(t):<12} {st:<12} {ch:<3} {color_rssi(rssi):<6} {mac:<20} {ssid}")
    print("-" * 90)
    print(f"Total frames: {total:,} | Rate: {rate:.1f} pkt/s")
    sys.stdout.flush()

# ------------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------------
def follow_stream(stream):
    """Follow a stream (stdin or file) and update display."""
    recent = deque(maxlen=args.nrows)
    last_update = 0
    total = 0
    t0 = time.time()

    while True:
        line = stream.readline()
        if not line:
            if args.file and args.follow:
                time.sleep(0.1)
                continue
            elif args.file:
                # show final table before quitting
                elapsed = max(time.time() - t0, 0.1)
                rate = total / elapsed
                print_table(list(recent), total, rate)
                break
            else:
                # stdin waiting
                time.sleep(0.05)
                continue

        pkt = parse_json_line(line.strip())
        if not pkt:
            continue
        recent.append(pkt)
        total += 1

        now = time.time()
        if now - last_update > args.interval:
            elapsed = max(now - t0, 0.1)
            rate = total / elapsed
            print_table(list(recent), total, rate)
            last_update = now

# ------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------
if __name__ == "__main__":
    if args.file:
        mode = "r"
        with open(args.file, mode, encoding="utf-8") as f:
            if args.follow:
                f.seek(0, os.SEEK_END)  # start at end if tailing
            follow_stream(f)
    else:
        # read from stdin (e.g. pipeline)
        follow_stream(sys.stdin)
