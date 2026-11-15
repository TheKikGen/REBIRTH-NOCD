#!/usr/bin/env python3
"""
ReBirth RB-338 v2.0.1 - Standalone Portable Binary Builder
==========================================================
Generates a 100% standalone, portable, on-disk patched Rebirth.exe from
a pristine Rebirth.sav.exe without requiring any external in-memory launcher.

Bypasses:
  1. CD-ROM Media Checks (No-CD)
  2. WinHelp 3.1 / WinHlp32.exe crashes on Windows 10/11
  3. Portable AppDir path resolution via GetModuleFileNameA (local RB20FUL/UPD.DAT)
  4. Propellerhead On-Disk Self-Checksum Anti-Tamper Protection (sub_40F7BB / sub_40CFDE)

Architecture:
  - 65 pure hex byte patches applied directly to the PE image on disk.
  - ImageBase: 0x00400000 (.text RVA 0x1000, File Offset 0x400)
"""

import os
import sys
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_EXE = os.path.join(SCRIPT_DIR, "Rebirth.sav.exe")
DST_EXE = os.path.join(SCRIPT_DIR, "Rebirth.exe")
CSV_PATCH = os.path.join(SCRIPT_DIR, "standalone.patch.csv")

def main():
    if not os.path.isfile(SRC_EXE):
        print(f"[-] Source pristine binary not found: {SRC_EXE}")
        sys.exit(1)
    if not os.path.isfile(CSV_PATCH):
        print(f"[-] Patch file not found: {CSV_PATCH}")
        sys.exit(1)

    print(f"[*] Reading {SRC_EXE}...")
    with open(SRC_EXE, "rb") as f:
        data = bytearray(f.read())

    text_vma = 0x00401000
    text_off = 0x00000400

    applied = 0
    with open(CSV_PATCH, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            va = int(parts[0], 16)
            old_byte = int(parts[1], 16)
            new_byte = int(parts[2], 16)

            file_off = va - text_vma + text_off
            if data[file_off] != old_byte:
                print(f"[!] Warning: Mismatch at VA 0x{va:08X} (expected 0x{old_byte:02X}, got 0x{data[file_off]:02X})")
            data[file_off] = new_byte
            applied += 1

    with open(DST_EXE, "wb") as f:
        f.write(data)

    print(f"[+] Successfully generated standalone portable {DST_EXE} ({applied} patches applied).")

if __name__ == "__main__":
    main()
