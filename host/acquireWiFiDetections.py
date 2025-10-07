#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acquireWiFiDetections.py
-----------------------------------------
Author: JM Mari
Affiliation: Université de la Polynésie française (UPF)
Year: 2025
License: MIT

Description:
  Standalone ESP32 Wi-Fi sniffer acquisition client.
  - Configures the ESP32 via serial commands.
  - Starts data acquisition.
  - Outputs parsed Wi-Fi detections (frames) to stdout in JSON format

Usage examples:
  python acquireWiFiDetections.py --port COM4 --baud 921600
  python acquireWiFiDetections.py --commands "HOP ON;SET CH 1,6,11;SET TYPE MGMT;CLEAR TYPE DATA;"
  python acquireWiFiDetections.py --port /dev/ttyUSB0 -s -f detections.json --duration 30
"""

import sys, json, time, argparse, os
import serial, serial.tools.list_ports
from colorama import Fore, Style, init

# ------------------------------------------------------------------------
# CLI arguments
# ------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="ESP32 Wi-Fi Sniffer Acquisition Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--port", "-p", type=str, help="Serial port (e.g. COM4 or /dev/ttyUSB0).")
    parser.add_argument("--baud", "-b", type=int, default=921600, help="Serial baudrate.")
    parser.add_argument("--commands", "-c", type=str,
                        help="Semi-colon separated list of ESP32 commands to send before acquisition (e.g. 'SET CH 1,6,11;SET TYPE MGMT').")
    parser.add_argument("--timeout", type=float, default=0.5, help="Serial read timeout (seconds).")
    parser.add_argument("--file", "-f", type=str, help="Optional log file (JSONL format).")
    parser.add_argument("--silent", "-s", action="store_true", help="Silent mode (no debug output).")
    parser.add_argument("--duration", "-d", type=float,
                        help="Optional acquisition duration in seconds (only applies if --file is used).")

    return parser.parse_args()

args = parse_args()
init(autoreset=True)

# ------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------
def auto_detect_port():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("❌ No serial ports detected.")
        sys.exit(1)
    if len(ports) == 1:
        return ports[0].device
    print("Available ports:")
    for i, p in enumerate(ports):
        print(f"  [{i}] {p.device} - {p.description}")
    sel = input("Select port number: ").strip()
    try:
        return ports[int(sel)].device
    except:
        return ports[0].device

def send_commands(ser, commands: str):
    """Send one or several ';'-separated commands and wait for replies."""
    if not commands:
        return
    cmd_list = [c.strip() for c in commands.split(";") if c.strip()]
    for cmd in cmd_list:
        if not args.silent:
            print(Fore.CYAN + f">>> Sending command: {cmd}" + Style.RESET_ALL)
        ser.reset_input_buffer()
        ser.write((cmd + "\n").encode("utf-8"))
        ser.flush()
        time.sleep(0.1)
        t0 = time.time()
        while time.time() - t0 < 1.5:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if line:
                if not args.silent:
                    print(Fore.YELLOW + "ESP32 says: " + Style.RESET_ALL + line)
                t0 = time.time()
            else:
                break
        time.sleep(0.05)
    if not args.silent:
        print(Fore.GREEN + ">>> All commands sent.\n" + Style.RESET_ALL)

# ------------------------------------------------------------------------
# Acquisition loop
# ------------------------------------------------------------------------
def acquire_loop(ser, log_file=None, duration=None):
    start_time = time.time()
    total = 0
    if not args.silent:
        print(Fore.GREEN + ">>> Starting acquisition... (Ctrl-C to stop)\n" + Style.RESET_ALL)

    try:
        while True:
            if duration and (time.time() - start_time) > duration:
                if not args.silent:
                    print(Fore.YELLOW + f"\n>>> Acquisition duration ({duration}s) reached." + Style.RESET_ALL)
                break

            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line or not line.startswith("{"):
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            total += 1

            # Output JSON
            if not args.silent and not log_file:
                print(json.dumps(pkt))
            elif args.silent and not log_file:
                print(json.dumps(pkt))

            # Save to file if requested
            if log_file:
                log_file.write(json.dumps(pkt) + "\n")

    except KeyboardInterrupt:
        if not args.silent:
            print(Fore.YELLOW + "\n>>> Acquisition stopped by user." + Style.RESET_ALL)

    elapsed = time.time() - start_time
    if not args.silent:
        print(f"Captured {total} packets in {elapsed:.1f}s (~{total/elapsed:.1f} pkt/s).")

# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
if __name__ == "__main__":
    port = args.port or auto_detect_port()
    baud = args.baud
    if not args.silent:
        print(f"Opening {port} @ {baud} baud...")

    try:
        ser = serial.Serial(port, baudrate=baud, timeout=args.timeout)
    except Exception as e:
        print(f"❌ Serial error: {e}")
        sys.exit(1)

    ser.reset_input_buffer()
    ser.write(b"LOG OFF\n")
    time.sleep(0.2)
    ser.reset_input_buffer()

    if args.commands:
        send_commands(ser, args.commands)

    # Enable JSON output
    ser.write(b"LOG ON\n")
    ser.flush()
    time.sleep(0.3)
    ser.reset_input_buffer()

    log_file = open(args.file, "a", encoding="utf-8") if args.file else None
    duration = args.duration if log_file and args.duration else None

    acquire_loop(ser, log_file=log_file, duration=duration)

    if log_file:
        log_file.close()
    ser.close()
