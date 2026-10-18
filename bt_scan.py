#!/usr/bin/env python3
"""
bt_scan.py - Dauerhafter Bluetooth-Scanner (Classic + BLE) fuer Linux/BlueZ.

Sucht ununterbrochen nach allen Bluetooth-Geraeten in der Umgebung und zeigt sie
im Format

    Name - MAC - Signal

an, inkl. aller ermittelbaren Details (Hersteller, Modell, Seriennummer,
Geraetetyp, Dienste, Beacon-Daten, ...).

Benoetigt: bluez (bluetoothd laeuft), Python >= 3.9, Paket "dbus-fast".
"""

import argparse
import asyncio
import csv
import json
import os
import re
import signal
import struct
import sys
import time
import urllib.request
import uuid as uuidlib

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus

BLUEZ = "org.bluez"
IFACE_ADAPTER = "org.bluez.Adapter1"
IFACE_DEVICE = "org.bluez.Device1"
IFACE_GATT_CHAR = "org.bluez.GattCharacteristic1"
IFACE_PROPS = "org.freedesktop.DBus.Properties"
IFACE_OM = "org.freedesktop.DBus.ObjectManager"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

SIG_BASE = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers"
DOWNLOADS = {
    "oui.csv": ["https://standards-oui.ieee.org/oui/oui.csv"],
    "manuf": ["https://www.wireshark.org/download/automated/data/manuf"],
    "company_identifiers.yaml": [SIG_BASE + "/company_identifiers/company_identifiers.yaml"],
    "service_uuids.yaml": [SIG_BASE + "/uuids/service_uuids.yaml"],
    "member_uuids.yaml": [SIG_BASE + "/uuids/member_uuids.yaml"],
}

# --------------------------------------------------------------------------
# Eingebaute Tabellen (Fallback, falls keine Datenbanken heruntergeladen wurden)
# --------------------------------------------------------------------------

COMPANY_IDS = {
    0x0000: "Ericsson", 0x0001: "Nokia", 0x0002: "Intel", 0x0003: "IBM",
    0x0004: "Toshiba", 0x0006: "Microsoft", 0x000A: "Qualcomm Technologies International (CSR)",
    0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x001D: "Qualcomm",
    0x0030: "ST Microelectronics", 0x003F: "Bluetooth SIG", 0x0046: "MediaTek",
    0x0047: "Bluegiga", 0x004C: "Apple", 0x0057: "Harman International",
    0x0059: "Nordic Semiconductor", 0x005D: "Realtek", 0x0067: "GN Netcom",
    0x0075: "Samsung Electronics", 0x0087: "Garmin", 0x009E: "Bose",
    0x00C4: "LG Electronics", 0x00E0: "Google", 0x012D: "Sony", 0x0131: "Cypress Semiconductor",
    0x0157: "Anhui Huami (Amazfit/Zepp)", 0x0171: "Amazon", 0x01DA: "Logitech",
    0x027D: "Huawei", 0x02E5: "Espressif", 0x02FF: "Silicon Labs", 0x038F: "Xiaomi",
    0x0397: "LEGO", 0x0499: "Ruuvi Innovations", 0x05A7: "Sonos", 0x067C: "Tile",
    0x0822: "Adafruit", 0x0969: "Woan Technology (SwitchBot)",
}

SERVICE_UUIDS16 = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert",
    0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time",
    0x1808: "Glucose", 0x1809: "Health Thermometer", 0x180A: "Device Information",
    0x180D: "Heart Rate", 0x180F: "Battery", 0x1810: "Blood Pressure",
    0x1812: "Human Interface Device", 0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence", 0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power", 0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing", 0x181B: "Body Composition", 0x181C: "User Data",
    0x181D: "Weight Scale", 0x181E: "Bond Management", 0x1822: "Pulse Oximeter",
    0x1826: "Fitness Machine", 0x183B: "Binary Sensor", 0x184E: "Audio Stream Control",
    0x1850: "Published Audio Capabilities", 0x1853: "Common Audio", 0x1854: "Hearing Access",
    0x1101: "Serial Port", 0x1103: "Dialup Networking", 0x1104: "IrMC Sync",
    0x1105: "OBEX Object Push", 0x1106: "OBEX File Transfer", 0x1108: "Headset",
    0x110A: "Audio Source", 0x110B: "Audio Sink", 0x110C: "A/V Remote Control Target",
    0x110D: "Advanced Audio Distribution", 0x110E: "A/V Remote Control",
    0x110F: "A/V Remote Control Controller", 0x1112: "Headset Audio Gateway",
    0x1115: "PANU", 0x1116: "NAP", 0x1117: "GN", 0x111E: "Handsfree",
    0x111F: "Handsfree Audio Gateway", 0x1124: "Human Interface Device (Classic)",
    0x112D: "SIM Access", 0x112F: "Phonebook Access Server", 0x1132: "Message Access Server",
    0x1133: "Message Notification Server", 0x1200: "PnP Information",
    0x1203: "Generic Audio", 0x1303: "Video Source", 0x1305: "HDP Source",
    0xFCD2: "BTHome", 0xFD5A: "Samsung", 0xFD6F: "Exposure Notification",
    0xFE07: "Sonos", 0xFE2C: "Google Fast Pair", 0xFE78: "HP", 0xFE95: "Xiaomi MiBeacon",
    0xFE9F: "Google", 0xFEAA: "Google Eddystone", 0xFEBE: "Bose", 0xFEC7: "Apple",
    0xFEC8: "Apple", 0xFEC9: "Apple", 0xFECA: "Apple", 0xFECB: "Apple", 0xFECC: "Apple",
    0xFECD: "Apple", 0xFECE: "Apple", 0xFECF: "Apple", 0xFED0: "Apple", 0xFED1: "Apple",
    0xFED2: "Apple", 0xFED3: "Apple", 0xFED4: "Apple", 0xFEEC: "Tile", 0xFEED: "Tile",
    0xFE0F: "Signify (Philips Hue)", 0xFE59: "Nordic DFU", 0xFDAB: "Xiaomi",
    0xFD44: "Apple Find My (Netzwerk)", 0xFD5F: "Meta (Oculus)", 0xFEF3: "Google",
    0xFE03: "Amazon", 0xFE00: "Amazon", 0xFEB9: "LG Electronics", 0xFE8F: "CSR",
}

APPEARANCE_CATEGORIES = {
    0: "Unbekannt", 1: "Telefon", 2: "Computer", 3: "Uhr / Smartwatch", 4: "Uhr",
    5: "Display", 6: "Fernbedienung", 7: "Brille", 8: "Tag / Tracker", 9: "Schluesselanhaenger",
    10: "Mediaplayer", 11: "Barcode-Scanner", 12: "Thermometer", 13: "Herzfrequenzsensor",
    14: "Blutdruckmessgeraet", 15: "Eingabegeraet (HID)", 16: "Blutzuckermessgeraet",
    17: "Lauf-/Schrittsensor", 18: "Fahrradsensor", 19: "Steuergeraet", 20: "Netzwerkgeraet",
    21: "Sensor", 22: "Leuchte", 23: "Ventilator", 24: "Klimatechnik (HVAC)",
    25: "Klimaanlage", 26: "Luftbefeuchter", 27: "Heizung", 28: "Zutrittskontrolle",
    29: "Motorisiertes Geraet", 30: "Stromversorgung", 31: "Lichtquelle",
    32: "Fensterabdeckung / Rollo", 33: "Audio-Senke (Lautsprecher)", 34: "Audio-Quelle",
    35: "Fahrzeug", 36: "Haushaltsgeraet", 37: "Kopfhoerer / Wearable Audio", 38: "Fluggeraet",
    39: "AV-Geraet", 40: "Anzeigegeraet", 41: "Hoergeraet", 42: "Spielkonsole / Gaming",
    43: "Beschilderung", 49: "Pulsoximeter", 50: "Waage", 51: "Persoenliches Mobilitaetsgeraet",
    52: "CGM (Glukosemonitor)", 53: "Insulinpumpe", 54: "Medikamentenabgabe",
    55: "Spirometer", 81: "Outdoor-Sportgeraet",
}

APPEARANCE_VALUES = {
    0x0040: "Telefon", 0x0080: "Computer", 0x0081: "Desktop", 0x0083: "Laptop",
    0x0084: "Handheld-PC", 0x0086: "Tablet", 0x00C0: "Uhr", 0x00C1: "Sportuhr",
    0x00C2: "Smartwatch", 0x0180: "Fernbedienung", 0x0200: "Tag", 0x03C0: "HID",
    0x03C1: "Tastatur", 0x03C2: "Maus", 0x03C3: "Joystick", 0x03C4: "Gamepad",
    0x03C5: "Digitalisiertablett", 0x03C6: "Kartenleser", 0x03C7: "Digitaler Stift",
    0x03C8: "Barcode-Scanner", 0x03C9: "Touchpad", 0x03CA: "Presenter",
    0x0841: "Lautsprecher", 0x0842: "Soundbar", 0x0941: "Ohrhoerer (In-Ear)",
    0x0942: "Headset", 0x0943: "Kopfhoerer", 0x0944: "Nackenbuegel-Kopfhoerer",
    0x0A40: "Hoergeraet", 0x0C80: "Fernseher",
}

COD_MAJOR = {
    0: "Verschiedenes", 1: "Computer", 2: "Telefon", 3: "Netzwerk (LAN/AP)",
    4: "Audio/Video", 5: "Peripherie (HID)", 6: "Bildgebung", 7: "Wearable",
    8: "Spielzeug", 9: "Gesundheit", 31: "Nicht kategorisiert",
}
COD_MINOR = {
    1: {0: "Unkategorisiert", 1: "Desktop", 2: "Server", 3: "Laptop", 4: "Handheld (PDA)",
        5: "Palm-size", 6: "Wearable-Computer", 7: "Tablet"},
    2: {0: "Unkategorisiert", 1: "Handy", 2: "Schnurlostelefon", 3: "Smartphone",
        4: "Modem/Gateway", 5: "ISDN"},
    4: {0: "Unkategorisiert", 1: "Headset", 2: "Freisprecheinrichtung", 4: "Mikrofon",
        5: "Lautsprecher", 6: "Kopfhoerer", 7: "Tragbares Audio", 8: "Auto-Audio",
        9: "Set-Top-Box", 10: "HiFi-Audio", 11: "Videorekorder", 12: "Videokamera",
        13: "Camcorder", 14: "Videomonitor", 15: "Display + Lautsprecher",
        16: "Videokonferenz", 18: "Spielzeug/Gaming"},
    7: {1: "Armbanduhr", 2: "Pager", 3: "Jacke", 4: "Helm", 5: "Brille"},
    8: {1: "Roboter", 2: "Fahrzeug", 3: "Puppe/Figur", 4: "Controller", 5: "Spiel"},
    9: {1: "Blutdruckmessgeraet", 2: "Thermometer", 3: "Waage", 4: "Blutzuckermessgeraet",
        5: "Pulsoximeter", 6: "Herzfrequenzmesser", 7: "Gesundheitsdaten-Anzeige"},
}
COD_SERVICES = {
    13: "Limited Discoverable", 14: "LE Audio", 16: "Positionierung", 17: "Netzwerk",
    18: "Rendering", 19: "Aufnahme", 20: "Objektuebertragung", 21: "Audio",
    22: "Telefonie", 23: "Information",
}

APPLE_TYPES = {
    0x01: "Overflow", 0x02: "iBeacon", 0x03: "AirPrint", 0x05: "AirDrop", 0x06: "HomeKit",
    0x07: "Proximity Pairing (AirPods/Beats)", 0x08: "Hey Siri", 0x09: "AirPlay-Ziel",
    0x0A: "AirPlay-Quelle", 0x0B: "Magic Switch", 0x0C: "Handoff", 0x0D: "Tethering-Ziel",
    0x0E: "Tethering-Quelle", 0x0F: "Nearby Action", 0x10: "Nearby Info",
    0x12: "Find My", 0x16: "Find My (getrennt)",
}
APPLE_PP_MODELS = {
    0x0220: "AirPods (1. Gen)", 0x0F20: "AirPods (2. Gen)", 0x1320: "AirPods (3. Gen)",
    0x1920: "AirPods (4. Gen)", 0x1B20: "AirPods 4 (ANC)", 0x0E20: "AirPods Pro",
    0x1420: "AirPods Pro (2. Gen)", 0x2420: "AirPods Pro (2. Gen, USB-C)",
    0x2720: "AirPods Pro 3", 0x0A20: "AirPods Max", 0x1F20: "AirPods Max (USB-C)",
    0x0320: "Powerbeats3", 0x0520: "BeatsX", 0x0620: "Beats Solo3", 0x0920: "Beats Studio3",
    0x0B20: "Powerbeats Pro", 0x0C20: "Beats Solo Pro", 0x0D20: "Powerbeats",
    0x1020: "Beats Flex", 0x1120: "Beats Studio Buds", 0x1220: "Beats Fit Pro",
    0x1620: "Beats Studio Buds+", 0x1720: "Beats Studio Pro", 0x1D20: "Powerbeats Pro 2",
}
APPLE_NEARBY_DEVICE = {
    0x01: "iPhone", 0x02: "iPad", 0x03: "Mac", 0x04: "Apple Watch", 0x05: "Apple TV",
    0x06: "HomePod", 0x0A: "AirPods",
}
MS_DEVICE_TYPES = {
    1: "Xbox One", 6: "Apple iPhone", 7: "Apple iPad", 8: "Android-Geraet",
    9: "Windows 10 Desktop", 11: "Windows 10 Phone", 12: "Linux-Geraet",
    13: "Windows IoT", 14: "Surface Hub", 15: "Windows-Laptop", 16: "Windows-Tablet",
}
EDDYSTONE_SCHEMES = ["http://www.", "https://www.", "http://", "https://"]
EDDYSTONE_EXT = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                 ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]

DIS_CHARS = {
    "2a29": "Hersteller",
    "2a24": "Modell",
    "2a25": "Seriennummer",
    "2a27": "Hardware-Revision",
    "2a26": "Firmware-Revision",
    "2a28": "Software-Revision",
    "2a23": "System-ID",
    "2a50": "PnP-ID",
    "2a2a": "IEEE-Zertifizierung",
    "2a00": "Geraetename (GATT)",
    "2a01": "Erscheinungsbild (GATT)",
    "2a19": "Akku",
}

# --------------------------------------------------------------------------
# Datenbanken (OUI, Firmen-IDs, UUIDs)
# --------------------------------------------------------------------------


class Database:
    def __init__(self):
        self.oui = {}
        self.companies = dict(COMPANY_IDS)
        self.uuids16 = dict(SERVICE_UUIDS16)
        self.sources = []
        self._load()

    def _load(self):
        n = self._load_oui()
        if n:
            self.sources.append(f"{n} OUI-Eintraege")
        path = os.path.join(DATA_DIR, "company_identifiers.yaml")
        if os.path.exists(path):
            n = self._load_sig_yaml(path, "value", self.companies)
            self.sources.append(f"{n} Bluetooth-Firmen-IDs")
        for name in ("service_uuids.yaml", "member_uuids.yaml"):
            path = os.path.join(DATA_DIR, name)
            if os.path.exists(path):
                self._load_sig_yaml(path, "uuid", self.uuids16)
        self.uuids16.update(SERVICE_UUIDS16)

    def _load_oui(self):
        candidates = [
            (os.path.join(DATA_DIR, "oui.csv"), "csv"),
            (os.path.join(DATA_DIR, "manuf"), "manuf"),
            ("/usr/share/ieee-data/oui.csv", "csv"),
            ("/usr/share/ieee-data/oui.txt", "txt"),
            ("/var/lib/ieee-data/oui.txt", "txt"),
            ("/usr/share/misc/oui.txt", "txt"),
            ("/usr/share/wireshark/manuf", "manuf"),
        ]
        for path, kind in candidates:
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    if kind == "csv":
                        for row in csv.reader(f):
                            if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                                self.oui[row[1].upper()] = row[2].strip()
                    elif kind == "txt":
                        for line in f:
                            m = re.match(r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)", line)
                            if m:
                                self.oui["".join(m.group(1, 2, 3)).upper()] = m.group(4).strip()
                    else:
                        for line in f:
                            parts = line.rstrip("\n").split("\t")
                            if len(parts) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}", parts[0]):
                                name = parts[2] if len(parts) >= 3 and parts[2] else parts[1]
                                self.oui[parts[0].replace(":", "").upper()] = name.strip()
            except OSError:
                continue
            if self.oui:
                return len(self.oui)
        return 0

    @staticmethod
    def _load_sig_yaml(path, key, target):
        count = 0
        current = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"\s*-\s*" + key + r":\s*0x([0-9A-Fa-f]+)", line)
                if m:
                    current = int(m.group(1), 16)
                    continue
                m = re.match(r"\s*name:\s*(.+)", line)
                if m and current is not None:
                    name = m.group(1).strip()
                    if len(name) >= 2 and name[0] == name[-1] and name[0] in "'\"":
                        name = name[1:-1].replace("''", "'")
                    target[current] = name
                    count += 1
                    current = None
        return count

    def oui_vendor(self, mac):
        return self.oui.get(mac.replace(":", "").upper()[:6])

    def company(self, cid):
        return self.companies.get(cid)

    def uuid_name(self, u):
        u = u.lower()
        if u.endswith("-0000-1000-8000-00805f9b34fb") and u.startswith("0000"):
            short = int(u[4:8], 16)
            name = self.uuids16.get(short)
            return f"{name} (0x{short:04X})" if name else f"0x{short:04X}"
        return u


def update_databases():
    os.makedirs(DATA_DIR, exist_ok=True)
    ok = True
    for name, urls in DOWNLOADS.items():
        target = os.path.join(DATA_DIR, name)
        for url in urls:
            try:
                print(f"Lade {url} ...", end=" ", flush=True)
                req = urllib.request.Request(url, headers={"User-Agent": "bt_scan/1.0"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                with open(target + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(target + ".tmp", target)
                print(f"ok ({len(data) // 1024} KiB)")
                break
            except Exception as e:  # noqa: BLE001
                print(f"fehlgeschlagen: {e}")
        else:
            ok = False
    if not os.path.exists(os.path.join(DATA_DIR, "oui.csv")) and not os.path.exists(os.path.join(DATA_DIR, "manuf")):
        print("Hinweis: Keine OUI-Datenbank geladen - MAC-Hersteller werden nicht angezeigt.")
    return ok


# --------------------------------------------------------------------------
# Decoder fuer Advertising-Daten
# --------------------------------------------------------------------------


def hexs(data):
    return bytes(data).hex(" ").upper()


def address_type_info(address, addr_type):
    if addr_type != "random":
        return "public"
    msb = int(address.split(":")[0], 16)
    top = msb >> 6
    if top == 0b11:
        return "random (statisch)"
    if top == 0b01:
        return "random (privat, aufloesbar - wechselt regelmaessig)"
    if top == 0b00:
        return "random (privat, nicht aufloesbar)"
    return "random"


def decode_cod(cod):
    major = (cod >> 8) & 0x1F
    minor = (cod >> 2) & 0x3F
    major_name = COD_MAJOR.get(major, f"Klasse {major}")
    if major in (1, 2, 4, 7, 8, 9):
        minor_name = COD_MINOR[major].get(minor)
    elif major == 5:
        kinds = {0: "", 1: "Tastatur", 2: "Zeigegeraet (Maus)", 3: "Tastatur + Maus"}
        sub = {1: "Joystick", 2: "Gamepad", 3: "Fernbedienung", 4: "Sensor",
               5: "Digitalisiertablett", 6: "Kartenleser", 7: "Digitaler Stift"}
        parts = [kinds.get(minor >> 4, ""), sub.get(minor & 0x0F, "")]
        minor_name = " / ".join(p for p in parts if p) or None
    elif major == 6:
        bits = {4: "Display", 8: "Kamera", 16: "Scanner", 32: "Drucker"}
        minor_name = ", ".join(n for b, n in bits.items() if minor & b) or None
    elif major == 3:
        minor_name = f"Auslastung {(minor >> 3) * 100 // 7}%"
    else:
        minor_name = None
    services = [n for bit, n in COD_SERVICES.items() if cod & (1 << bit)]
    text = major_name + (f" / {minor_name}" if minor_name else "")
    if services:
        text += f"  [Dienste: {', '.join(services)}]"
    return text


def decode_appearance(value):
    cat = value >> 6
    name = APPEARANCE_VALUES.get(value) or APPEARANCE_CATEGORIES.get(cat, f"Kategorie {cat}")
    return f"{name} (0x{value:04X})"


def decode_modalias(modalias, db):
    m = re.match(r"(usb|bluetooth):v([0-9A-Fa-f]{4})p([0-9A-Fa-f]{4})d([0-9A-Fa-f]{4})", modalias)
    if not m:
        return modalias
    src, vid, pid, ver = m.group(1), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
    vendor = db.company(vid) if src == "bluetooth" else None
    vtxt = f"{vendor} (0x{vid:04X})" if vendor else f"0x{vid:04X} ({'USB-ID' if src == 'usb' else 'BT-ID'})"
    return f"Hersteller {vtxt}, Produkt-ID 0x{pid:04X}, Version 0x{ver:04X}"


def decode_pnp_id(data, db):
    if len(data) < 7:
        return hexs(data)
    src, vid, pid, ver = struct.unpack("<BHHH", bytes(data[:7]))
    vendor = db.company(vid) if src == 1 else None
    vtxt = f"{vendor} (0x{vid:04X})" if vendor else f"0x{vid:04X} ({'USB-ID' if src == 2 else 'BT-ID'})"
    return f"Hersteller {vtxt}, Produkt-ID 0x{pid:04X}, Version 0x{ver:04X}"


def decode_apple(data):
    out = []
    i = 0
    data = bytes(data)
    while i + 1 < len(data):
        typ, length = data[i], data[i + 1]
        payload = data[i + 2:i + 2 + length]
        i += 2 + length
        tname = APPLE_TYPES.get(typ, f"Typ 0x{typ:02X}")
        if typ == 0x02 and len(payload) >= 21:
            u = uuidlib.UUID(bytes=payload[0:16])
            major, minor = struct.unpack(">HH", payload[16:20])
            tx = struct.unpack("b", payload[20:21])[0]
            out.append(f"iBeacon: UUID {u}, Major {major}, Minor {minor}, Messleistung {tx} dBm")
        elif typ == 0x07 and len(payload) >= 7:
            model = (payload[1] << 8) | payload[2]
            mname = APPLE_PP_MODELS.get(model, f"unbekanntes Modell 0x{model:04X}")
            status = payload[3]
            batt = payload[4]
            case = payload[5]

            def pct(n):
                return "?" if n == 0x0F else f"{min(n, 10) * 10}%"
            right, left = batt >> 4, batt & 0x0F
            if status & 0x20:
                right, left = left, right
            txt = f"Apple {mname}: Akku links {pct(left)}, rechts {pct(right)}"
            if model not in (0x0A20, 0x1F20):
                txt += f", Case {pct(case & 0x0F)}"
            charging = case >> 4
            flags = [n for b, n in ((1, "rechts"), (2, "links"), (4, "Case")) if charging & b]
            if flags:
                txt += f" (laedt: {', '.join(flags)})"
            out.append(txt)
        elif typ == 0x10 and len(payload) >= 1:
            out.append(f"Apple {tname} (Status 0x{payload[0]:02X})")
        elif typ == 0x0F and len(payload) >= 2:
            out.append(f"Apple {tname} (Aktion 0x{payload[1]:02X})")
        elif typ == 0x09 and len(payload) >= 1:
            out.append(f"Apple {tname}")
        elif typ in (0x12, 0x16):
            out.append(f"Apple {tname} - Geraet ist im Find-My-Netzwerk (AirTag/iPhone/...)")
        else:
            out.append(f"Apple {tname}")
    return out


def decode_microsoft(data):
    data = bytes(data)
    if len(data) >= 2 and data[0] == 0x01:
        dtype = data[1] & 0x1F
        return [f"Microsoft CDP-Beacon: {MS_DEVICE_TYPES.get(dtype, f'Geraetetyp {dtype}')}"]
    if len(data) >= 1 and data[0] == 0x03:
        name = ""
        if len(data) > 2:
            name = data[2:].split(b"\x00")[0].decode("utf-8", "replace").strip()
        return ["Microsoft Swift Pair" + (f": {name}" if name else "")]
    return []


def decode_ruuvi(data):
    data = bytes(data)
    if len(data) >= 14 and data[0] == 0x05:
        t, h, p = struct.unpack(">hHH", data[1:7])
        volt = (struct.unpack(">H", data[13:15])[0] >> 5) + 1600 if len(data) >= 15 else None
        txt = f"RuuviTag: {t * 0.005:.2f} C, {h * 0.0025:.1f}% rF, {(p + 50000) / 100:.1f} hPa"
        if volt:
            txt += f", Batterie {volt / 1000:.2f} V"
        return [txt]
    return []


def decode_manufacturer(cid, data, db):
    if cid == 0x004C:
        return decode_apple(data)
    if cid == 0x0006:
        return decode_microsoft(data)
    if cid == 0x0499:
        return decode_ruuvi(data)
    return []


def decode_eddystone(data):
    data = bytes(data)
    if not data:
        return []
    frame = data[0]
    if frame == 0x00 and len(data) >= 18:
        return [f"Eddystone-UID: Namespace {data[2:12].hex()}, Instanz {data[12:18].hex()}, "
                f"Sendeleistung@0m {struct.unpack('b', data[1:2])[0]} dBm"]
    if frame == 0x10 and len(data) >= 3:
        url = EDDYSTONE_SCHEMES[data[2]] if data[2] < len(EDDYSTONE_SCHEMES) else ""
        for b in data[3:]:
            url += EDDYSTONE_EXT[b] if b < len(EDDYSTONE_EXT) else chr(b)
        return [f"Eddystone-URL: {url}"]
    if frame == 0x20 and len(data) >= 14:
        volt, temp, adv, sec = struct.unpack(">HhII", data[2:14])
        return [f"Eddystone-TLM: Batterie {volt / 1000:.2f} V, Temperatur {temp / 256:.1f} C, "
                f"{adv} Pakete, Laufzeit {sec // 10 // 3600} h"]
    if frame == 0x30:
        return ["Eddystone-EID (verschluesselt)"]
    return []


def decode_service_data(u, data, db):
    u = u.lower()
    short = int(u[4:8], 16) if u.endswith("-0000-1000-8000-00805f9b34fb") else None
    data = bytes(data)
    if short == 0xFEAA:
        return decode_eddystone(data)
    if short == 0xFE2C and len(data) == 3:
        return [f"Google Fast Pair: Modell-ID 0x{data.hex().upper()} "
                "(nachschlagbar z.B. in der Fast-Pair-Modelldatenbank)"]
    if short == 0xFE2C:
        return ["Google Fast Pair (Kontodaten, nicht oeffentlich)"]
    if short == 0xFE95 and len(data) >= 4:
        pid = struct.unpack("<H", data[2:4])[0]
        return [f"Xiaomi MiBeacon: Produkt-ID 0x{pid:04X}"]
    if short == 0xFCD2:
        return ["BTHome-Sensor" + (" (verschluesselt)" if data and data[0] & 0x01 else "")]
    if short == 0xFD6F:
        return ["Corona-Warn-/Exposure-Notification-Beacon"]
    if short == 0x180F and data:
        return [f"Akku: {data[0]}%"]
    return []


def estimate_distance(rssi, tx_power, at_one_meter=False, n=2.0):
    if rssi is None or tx_power is None:
        return None
    ref = tx_power if at_one_meter else tx_power - 41
    return 10 ** ((ref - rssi) / (10 * n))


# --------------------------------------------------------------------------
# Geraetezustand
# --------------------------------------------------------------------------


def unwrap(v):
    if isinstance(v, Variant):
        return unwrap(v.value)
    if isinstance(v, dict):
        return {k: unwrap(x) for k, x in v.items()}
    if isinstance(v, list):
        return [unwrap(x) for x in v]
    return v


class Device:
    def __init__(self, path):
        self.path = path
        self.props = {}
        self.first_seen = time.time()
        self.last_seen = 0.0
        self.updates = 0
        self.rssi_min = None
        self.rssi_max = None
        self.rssi_sum = 0
        self.rssi_count = 0
        self.gatt = {}
        self.gatt_state = None  # None, "laeuft", "ok", "fehlgeschlagen: ..."
        self.gatt_tries = 0
        self.gatt_last_try = 0.0
        self.last_logged = 0.0

    def update(self, props, seen=True):
        self.props.update(props)
        rssi = props.get("RSSI")
        if rssi is not None:
            self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
            self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)
            self.rssi_sum += rssi
            self.rssi_count += 1
        if seen:
            self.last_seen = time.time()
            self.updates += 1

    @property
    def address(self):
        return self.props.get("Address", self.path.rsplit("dev_", 1)[-1].replace("_", ":"))

    @property
    def name(self):
        name = self.props.get("Name") or self.gatt.get("Geraetename (GATT)")
        if not name:
            alias = self.props.get("Alias")
            if alias and alias.replace("-", ":").upper() != self.address.upper():
                name = alias
        return name

    @property
    def rssi(self):
        return self.props.get("RSSI")

    @property
    def is_le(self):
        p = self.props
        return bool(p.get("AddressType") == "random" or p.get("AdvertisingFlags")
                    or p.get("ManufacturerData") or p.get("ServiceData")
                    or "Appearance" in p or "TxPower" in p)

    @property
    def is_classic(self):
        return "Class" in self.props

    @property
    def transport(self):
        if self.is_classic and self.is_le:
            return "Dual-Mode (Classic + BLE)"
        if self.is_classic:
            return "Classic (BR/EDR)"
        if self.is_le:
            return "BLE"
        return "unbekannt"


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------


class DBusError(Exception):
    pass


def rfkill_blocked():
    """Liefert die per rfkill gesperrten Bluetooth-Geraete, z.B. ['hci0 (soft)']."""
    out = []
    base = "/sys/class/rfkill"
    try:
        entries = os.listdir(base)
    except OSError:
        return out
    for entry in entries:
        try:
            with open(os.path.join(base, entry, "type")) as f:
                if f.read().strip() != "bluetooth":
                    continue
            with open(os.path.join(base, entry, "name")) as f:
                name = f.read().strip()
            kinds = []
            for kind in ("soft", "hard"):
                with open(os.path.join(base, entry, kind)) as f:
                    if f.read().strip() == "1":
                        kinds.append(kind)
            if kinds:
                out.append(f"{name} ({'/'.join(kinds)})")
        except OSError:
            continue
    return out


class Scanner:
    def __init__(self, args, db):
        self.args = args
        self.db = db
        self.bus = None
        self.adapter_path = None
        self.adapter_props = {}
        self.devices = {}
        self.started = time.time()
        self.discovery_restarts = 0
        self.stop_event = asyncio.Event()

    async def call(self, path, interface, member, signature="", body=None, destination=BLUEZ):
        reply = await self.bus.call(Message(destination=destination, path=path, interface=interface,
                                            member=member, signature=signature, body=body or []))
        if reply.message_type == MessageType.ERROR:
            raise DBusError(f"{reply.error_name}: {reply.body[0] if reply.body else ''}")
        return reply.body

    async def get_prop(self, path, interface, name):
        body = await self.call(path, IFACE_PROPS, "Get", "ss", [interface, name])
        return unwrap(body[0])

    async def set_prop(self, path, interface, name, sig, value):
        await self.call(path, IFACE_PROPS, "Set", "ssv", [interface, name, Variant(sig, value)])

    async def managed_objects(self):
        body = await self.call("/", IFACE_OM, "GetManagedObjects")
        return unwrap(body[0])

    async def add_match(self, rule):
        await self.call("/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch", "s", [rule],
                        destination="org.freedesktop.DBus")

    async def setup(self):
        try:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"Keine Verbindung zum System-D-Bus: {e}\n"
                             "Laeuft dbus im Container? (apt install dbus bluez; systemctl start dbus bluetooth)")
        try:
            objs = await self.managed_objects()
        except DBusError as e:
            raise SystemExit(f"BlueZ nicht erreichbar ({e}).\nLaeuft bluetoothd? -> systemctl start bluetooth")

        adapters = {p: i[IFACE_ADAPTER] for p, i in objs.items() if IFACE_ADAPTER in i}
        if not adapters:
            raise SystemExit("Kein Bluetooth-Adapter gefunden. Ist der USB-Dongle im Container sichtbar?\n"
                             "Pruefen mit: bluetoothctl list  /  btmgmt info  /  lsusb")
        if self.args.adapter:
            matches = [p for p, a in adapters.items()
                       if p.endswith("/" + self.args.adapter) or a.get("Address", "").upper() == self.args.adapter.upper()]
            if not matches:
                raise SystemExit(f"Adapter {self.args.adapter} nicht gefunden. Vorhanden: "
                                 + ", ".join(p.rsplit("/", 1)[-1] for p in adapters))
            self.adapter_path = matches[0]
        else:
            self.adapter_path = sorted(adapters)[0]
        self.adapter_props = adapters[self.adapter_path]
        if self.args.mode == "log":
            print(f"Suche laeuft auf {self.adapter_path.rsplit('/', 1)[-1]} ... (Strg+C zum Beenden)", flush=True)

        self.bus.add_message_handler(self.on_message)
        await self.add_match(f"type='signal',sender='{BLUEZ}',interface='{IFACE_OM}'")
        await self.add_match(f"type='signal',sender='{BLUEZ}',interface='{IFACE_PROPS}',member='PropertiesChanged'")

        if not self.adapter_props.get("Powered"):
            await self.power_on()

        # Bereits bekannte Geraete uebernehmen (nur mit aktuellem RSSI als "gesehen")
        for path, ifaces in objs.items():
            if IFACE_DEVICE in ifaces and path.startswith(self.adapter_path + "/"):
                dev = self.devices.setdefault(path, Device(path))
                dev.update(ifaces[IFACE_DEVICE], seen="RSSI" in ifaces[IFACE_DEVICE])

        filt = {"Transport": Variant("s", self.args.transport), "DuplicateData": Variant("b", True)}
        try:
            await self.call(self.adapter_path, IFACE_ADAPTER, "SetDiscoveryFilter", "a{sv}", [filt])
        except DBusError as e:
            print(f"Warnung: SetDiscoveryFilter fehlgeschlagen ({e})", file=sys.stderr)
        await self.start_discovery()

    async def power_on(self):
        """Adapter einschalten; bei Fehlern mehrfach versuchen und dann eine Diagnose ausgeben."""
        error = None
        for attempt in range(5):
            try:
                await self.set_prop(self.adapter_path, IFACE_ADAPTER, "Powered", "b", True)
            except DBusError as e:
                error = e
            await asyncio.sleep(1 + attempt)
            try:
                if await self.get_prop(self.adapter_path, IFACE_ADAPTER, "Powered"):
                    return
            except DBusError:
                pass
        hci = self.adapter_path.rsplit("/", 1)[-1]
        blocked = rfkill_blocked()
        lines = [f"Adapter {hci} laesst sich nicht einschalten: {error}", ""]
        if blocked:
            lines += [f"Ursache: Funk ist per rfkill gesperrt ({', '.join(blocked)}).",
                      "  -> rfkill unblock bluetooth   (ggf. auf dem Proxmox-Host ausfuehren)", ""]
        if error and "Authentication Failed" in str(error):
            lines += ["'Authentication Failed' ist hier irrefuehrend: Der Kernel meldet damit einen TIMEOUT -",
                      "der USB-Dongle hat beim Einschalten nicht geantwortet.", ""]
        lines += [
            "Typische Ursachen und Abhilfe:",
            "  1. Firmware fehlt (v.a. Realtek/Intel/Broadcom-Dongles). Wird vom HOST-Kernel geladen:",
            "     auf dem Proxmox-Host:  dmesg | grep -iE 'bluetooth|btusb|rtl|firmware'",
            "     fehlt Firmware -> auf dem Host: apt install pve-firmware (Proxmox) bzw. linux-firmware,",
            "     dann Dongle ab- und wieder anstecken.",
            "  2. Ein zweiter bluetoothd (auf dem Host oder in einem anderen Container) belegt den Adapter:",
            "     auf dem Host:  systemctl disable --now bluetooth",
            "  3. Dongle haengt: abstecken/anstecken oder im Container:",
            f"     btmgmt --index {hci.replace('hci', '')} power off; btmgmt --index {hci.replace('hci', '')} power on",
            "  4. Pruefen:  btmgmt info   /   bluetoothctl show   /   rfkill list",
        ]
        raise SystemExit("\n".join(lines))

    async def start_discovery(self):
        try:
            await self.call(self.adapter_path, IFACE_ADAPTER, "StartDiscovery")
            self.discovery_restarts += 1
        except DBusError as e:
            if "InProgress" not in str(e):
                print(f"Warnung: StartDiscovery fehlgeschlagen ({e})", file=sys.stderr)

    async def stop_discovery(self):
        try:
            await self.call(self.adapter_path, IFACE_ADAPTER, "StopDiscovery")
        except Exception:  # noqa: BLE001
            pass

    def on_message(self, msg):
        if msg.message_type != MessageType.SIGNAL:
            return None
        try:
            if msg.member == "InterfacesAdded":
                path, ifaces = msg.body[0], unwrap(msg.body[1])
                if IFACE_DEVICE in ifaces and path.startswith(self.adapter_path + "/"):
                    props = ifaces[IFACE_DEVICE]
                    dev = self.devices.setdefault(path, Device(path))
                    dev.update(props, seen="RSSI" in props or "ManufacturerData" in props)
                    self.log_device(dev, new=dev.updates <= 1)
            elif msg.member == "PropertiesChanged":
                iface, changed = msg.body[0], unwrap(msg.body[1])
                path = msg.path
                if iface == IFACE_DEVICE and path.startswith(self.adapter_path + "/"):
                    dev = self.devices.get(path)
                    is_new = dev is None
                    if is_new:
                        dev = self.devices[path] = Device(path)
                    seen = any(k in changed for k in ("RSSI", "ManufacturerData", "ServiceData", "TxPower", "Name"))
                    dev.update(changed, seen=seen)
                    if seen:
                        self.log_device(dev, new=is_new)
                elif iface == IFACE_ADAPTER and path == self.adapter_path:
                    self.adapter_props.update(changed)
        except Exception as e:  # noqa: BLE001
            if self.args.debug:
                print(f"Fehler bei Signal {msg.member}: {e}", file=sys.stderr)
        return None

    def log_device(self, dev, new):
        if self.args.mode != "log":
            return
        if self.args.min_rssi is not None and (dev.rssi is None or dev.rssi < self.args.min_rssi):
            return
        now = time.time()
        if not new and now - dev.last_logged < self.args.interval:
            return
        dev.last_logged = now
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {'NEU ' if new else ''}{format_main_line(dev, color=False)}", flush=True)
        if new and not self.args.compact:
            for line in device_details(dev, self.db):
                print(f"           {line}", flush=True)

    async def watchdog(self):
        """Haelt die Suche dauerhaft am Laufen (andere Programme koennen sie stoppen)."""
        while not self.stop_event.is_set():
            await asyncio.sleep(5)
            try:
                if not await self.get_prop(self.adapter_path, IFACE_ADAPTER, "Discovering"):
                    await self.start_discovery()
            except DBusError:
                pass

    # ---------------- GATT-Abfrage (Device Information Service) -------------

    async def gatt_worker(self):
        while not self.stop_event.is_set():
            await asyncio.sleep(1)
            now = time.time()
            candidates = [d for d in self.devices.values()
                          if d.is_le and not d.is_classic
                          and d.gatt_state not in ("ok", "keine Geraeteinfos lesbar")
                          and d.gatt_tries < 3 and now - d.gatt_last_try > 300
                          and now - d.last_seen < 10
                          and d.rssi is not None and d.rssi >= self.args.deep_min_rssi]
            if not candidates:
                continue
            dev = max(candidates, key=lambda d: d.rssi)
            dev.gatt_tries += 1
            dev.gatt_last_try = now
            dev.gatt_state = "laeuft"
            was_connected = bool(dev.props.get("Connected"))
            try:
                await asyncio.wait_for(self.read_gatt(dev), timeout=self.args.deep_timeout)
                dev.gatt_state = "ok" if dev.gatt else "keine Geraeteinfos lesbar"
            except asyncio.TimeoutError:
                dev.gatt_state = "fehlgeschlagen: Timeout"
            except Exception as e:  # noqa: BLE001
                dev.gatt_state = f"fehlgeschlagen: {str(e).replace('org.bluez.Error.', '')}"
            finally:
                if not was_connected:
                    try:
                        await self.call(dev.path, IFACE_DEVICE, "Disconnect")
                    except Exception:  # noqa: BLE001
                        pass

    async def read_gatt(self, dev):
        if not dev.props.get("Connected"):
            await self.call(dev.path, IFACE_DEVICE, "Connect")
        for _ in range(40):
            if await self.get_prop(dev.path, IFACE_DEVICE, "ServicesResolved"):
                break
            await asyncio.sleep(0.25)
        objs = await self.managed_objects()
        for path, ifaces in objs.items():
            ch = ifaces.get(IFACE_GATT_CHAR)
            if not ch or not path.startswith(dev.path + "/"):
                continue
            u = ch.get("UUID", "").lower()
            short = u[4:8] if u.endswith("-0000-1000-8000-00805f9b34fb") else None
            if short not in DIS_CHARS or "read" not in ch.get("Flags", []):
                continue
            try:
                body = await self.call(path, IFACE_GATT_CHAR, "ReadValue", "a{sv}", [{}])
            except DBusError:
                continue
            value = bytes(body[0])
            label = DIS_CHARS[short]
            if short == "2a50":
                dev.gatt[label] = decode_pnp_id(value, self.db)
            elif short in ("2a23", "2a2a"):
                dev.gatt[label] = hexs(value)
            elif short == "2a19":
                dev.gatt[label] = f"{value[0]}%" if value else "?"
            elif short == "2a01":
                dev.gatt[label] = decode_appearance(struct.unpack("<H", value[:2])[0]) if len(value) >= 2 else hexs(value)
            else:
                text = value.split(b"\x00")[0].decode("utf-8", "replace").strip()
                if text:
                    dev.gatt[label] = text

    # ---------------- Ausgabe ----------------------------------------------

    def visible_devices(self):
        now = time.time()
        devs = [d for d in self.devices.values()
                if d.last_seen and now - d.last_seen <= self.args.timeout]
        if self.args.min_rssi is not None:
            devs = [d for d in devs if d.rssi is not None and d.rssi >= self.args.min_rssi]
        if self.args.sort == "name":
            devs.sort(key=lambda d: ((d.name or "~").lower(), d.address))
        elif self.args.sort == "mac":
            devs.sort(key=lambda d: d.address)
        elif self.args.sort == "seen":
            devs.sort(key=lambda d: -d.last_seen)
        else:
            devs.sort(key=lambda d: -(d.rssi if d.rssi is not None else -999))
        return devs

    def render(self, color=True):
        devs = self.visible_devices()
        a = self.adapter_props
        lines = []
        hdr = (f"Bluetooth-Scan  |  Adapter {self.adapter_path.rsplit('/', 1)[-1]} ({a.get('Address', '?')})"
               f"  |  {len(devs)} Geraete (letzte {self.args.timeout}s)  |  "
               f"Laufzeit {fmt_duration(time.time() - self.started)}  |  {time.strftime('%H:%M:%S')}")
        lines.append(c(hdr, "1", color))
        lines.append(c("Name - MAC - Signal", "2", color))
        lines.append("")
        for d in devs:
            lines.append(format_main_line(d, color))
            if not self.args.compact:
                for det in device_details(d, self.db):
                    lines.append("    " + c(det, "2", color) if det.startswith("Rohdaten") else "    " + det)
                lines.append("")
        return "\n".join(lines)

    def snapshot(self):
        out = []
        for d in self.visible_devices():
            out.append({
                "name": d.name, "mac": d.address, "rssi": d.rssi,
                "rssi_min": d.rssi_min, "rssi_max": d.rssi_max,
                "transport": d.transport,
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(d.last_seen)),
                "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(d.first_seen)),
                "details": device_details(d, self.db),
                "gatt": d.gatt,
            })
        return out

    async def display_loop(self):
        interactive = sys.stdout.isatty()
        while not self.stop_event.is_set():
            await asyncio.sleep(self.args.interval)
            if self.args.json:
                write_json(self.args.json, self.snapshot())
            if self.args.mode == "live" and not self.args.once:
                text = self.render(color=interactive and not self.args.no_color)
                if interactive:
                    sys.stdout.write("\033[H\033[2J" + text + "\n")
                else:
                    sys.stdout.write(text + "\n" + "-" * 60 + "\n")
                sys.stdout.flush()

    async def run(self):
        await self.setup()
        tasks = [asyncio.create_task(self.watchdog()), asyncio.create_task(self.display_loop())]
        if self.args.deep:
            tasks.append(asyncio.create_task(self.gatt_worker()))
        try:
            if self.args.once:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.args.once)
            else:
                await self.stop_event.wait()
        except asyncio.TimeoutError:
            pass
        finally:
            for t in tasks:
                t.cancel()
            await self.stop_discovery()
        if self.args.once:
            if self.args.json:
                write_json(self.args.json, self.snapshot())
            print(self.render(color=sys.stdout.isatty() and not self.args.no_color))


# --------------------------------------------------------------------------
# Formatierung
# --------------------------------------------------------------------------


def c(text, code, enabled):
    return f"\033[{code}m{text}\033[0m" if enabled else text


def fmt_duration(s):
    s = int(s)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def signal_bar(rssi):
    if rssi is None:
        return "     ", "?"
    level = max(0, min(5, (rssi + 100) // 10))
    quality = ["sehr schwach", "sehr schwach", "schwach", "mittel", "gut", "sehr gut"][level]
    return "█" * level + "░" * (5 - level), quality


def format_main_line(d, color):
    name = d.name or "(unbekannt)"
    rssi = d.rssi
    bar, quality = signal_bar(rssi)
    sig = f"{rssi} dBm {bar} {quality}" if rssi is not None else "kein aktuelles Signal"
    if color and rssi is not None:
        code = "32" if rssi >= -60 else "33" if rssi >= -80 else "31"
        sig = c(sig, code, True)
    age = time.time() - d.last_seen
    agetxt = f"  (vor {int(age)}s)" if age >= 5 else ""
    return f"{c(name, '1', color)} - {d.address} - {sig}{agetxt}"


def device_details(d, db):
    p = d.props
    det = []
    det.append(f"Typ: {d.transport}  |  Adresse: {address_type_info(d.address, p.get('AddressType', 'public'))}")

    if p.get("AddressType", "public") == "public":
        vendor = db.oui_vendor(d.address)
        if vendor:
            det.append(f"Hersteller (MAC): {vendor}")

    mdata = p.get("ManufacturerData") or {}
    decoded = []
    for cid, data in mdata.items():
        cname = db.company(cid)
        det.append(f"Hersteller (Funkdaten): {cname or 'unbekannt'} (ID 0x{cid:04X})")
        decoded += decode_manufacturer(cid, data, db)

    sdata = p.get("ServiceData") or {}
    for u, data in sdata.items():
        decoded += decode_service_data(u, data, db)

    if "Appearance" in p:
        det.append(f"Geraeteart: {decode_appearance(p['Appearance'])}")
    if "Class" in p:
        det.append(f"Geraeteklasse: {decode_cod(p['Class'])} (0x{p['Class']:06X})")
    if p.get("Icon"):
        det.append(f"Symbol (BlueZ): {p['Icon']}")

    for line in decoded:
        det.append(f"Info: {line}")

    if d.gatt:
        order = ["Hersteller", "Modell", "Seriennummer", "Hardware-Revision", "Firmware-Revision",
                 "Software-Revision", "PnP-ID", "System-ID", "IEEE-Zertifizierung",
                 "Geraetename (GATT)", "Erscheinungsbild (GATT)", "Akku"]
        for k in order:
            if k in d.gatt:
                det.append(f"{k}: {d.gatt[k]}")
    if d.gatt_state and d.gatt_state not in ("ok",):
        det.append(f"Geraeteinfo-Abfrage (GATT): {d.gatt_state}")

    if p.get("Modalias"):
        det.append(f"Modalias: {decode_modalias(p['Modalias'], db)}")

    uuids = p.get("UUIDs") or []
    if uuids:
        det.append("Dienste: " + ", ".join(db.uuid_name(u) for u in uuids))

    tx = p.get("TxPower")
    rssi = d.rssi
    ibeacon_tx = None
    for line in decoded:
        m = re.search(r"Messleistung (-?\d+) dBm", line)
        if m:
            ibeacon_tx = int(m.group(1))
    sig = []
    if d.rssi_count:
        sig.append(f"min {d.rssi_min} / max {d.rssi_max} / Mittel {d.rssi_sum // d.rssi_count} dBm")
    if tx is not None:
        sig.append(f"Sendeleistung {tx} dBm")
    dist = estimate_distance(rssi, ibeacon_tx, at_one_meter=True) if ibeacon_tx is not None else estimate_distance(rssi, tx)
    if dist is not None:
        sig.append(f"Entfernung ca. {dist:.1f} m")
    if sig:
        det.append("Signal: " + "  |  ".join(sig))

    status = [n for k, n in (("Paired", "gekoppelt"), ("Bonded", "gebunden"), ("Trusted", "vertraut"),
                             ("Connected", "verbunden"), ("Blocked", "blockiert"),
                             ("LegacyPairing", "Legacy-Pairing")) if p.get(k)]
    if status:
        det.append("Status: " + ", ".join(status))

    det.append(f"Gesehen: zuerst {time.strftime('%H:%M:%S', time.localtime(d.first_seen))}, "
               f"zuletzt {time.strftime('%H:%M:%S', time.localtime(d.last_seen))}, {d.updates} Updates")

    raw = []
    for cid, data in mdata.items():
        raw.append(f"Hersteller 0x{cid:04X}: {hexs(data)}")
    for u, data in sdata.items():
        raw.append(f"Dienst {db.uuid_name(u)}: {hexs(data)}")
    if p.get("AdvertisingFlags"):
        raw.append(f"Flags: {hexs(p['AdvertisingFlags'])}")
    for r in raw:
        det.append(f"Rohdaten {r}")
    return det


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "devices": data}, f,
                  ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# --------------------------------------------------------------------------


def parse_args():
    ap = argparse.ArgumentParser(description="Dauerhafter Bluetooth-Scanner (Classic + BLE) fuer BlueZ.")
    ap.add_argument("-a", "--adapter", help="Adapter (z.B. hci0 oder MAC), Standard: erster gefundener")
    ap.add_argument("-m", "--mode", choices=["live", "log"], default="live",
                    help="live = Bildschirm wird laufend aktualisiert (Standard), log = fortlaufende Zeilen")
    ap.add_argument("-t", "--transport", choices=["auto", "le", "bredr"], default="auto",
                    help="auto = Classic + BLE (Standard), le = nur BLE (schnellste Updates), bredr = nur Classic")
    ap.add_argument("-i", "--interval", type=float, default=1.0, help="Aktualisierungsintervall in s (Standard 1)")
    ap.add_argument("--timeout", type=int, default=120,
                    help="Geraete ausblenden, die so viele Sekunden nicht gesehen wurden (Standard 120)")
    ap.add_argument("--min-rssi", type=int, help="Nur Geraete mit Signal >= X dBm anzeigen (z.B. -80)")
    ap.add_argument("-s", "--sort", choices=["rssi", "name", "mac", "seen"], default="rssi", help="Sortierung")
    ap.add_argument("-c", "--compact", action="store_true", help="Nur 'Name - MAC - Signal', ohne Details")
    ap.add_argument("-d", "--deep", action="store_true",
                    help="BLE-Geraete kurz verbinden und Hersteller/Modell/Seriennr./Firmware/Akku "
                         "aus dem GATT 'Device Information Service' lesen")
    ap.add_argument("--deep-min-rssi", type=int, default=-85, help="Mindestsignal fuer --deep (Standard -85)")
    ap.add_argument("--deep-timeout", type=float, default=15, help="Timeout je GATT-Abfrage in s (Standard 15)")
    ap.add_argument("-j", "--json", help="Aktuelle Geraeteliste laufend als JSON in diese Datei schreiben")
    ap.add_argument("--once", type=float, metavar="SEK", help="X Sekunden scannen, Ergebnis ausgeben, beenden")
    ap.add_argument("--update-db", action="store_true",
                    help="Hersteller-Datenbanken (IEEE OUI, Bluetooth SIG) herunterladen und beenden")
    ap.add_argument("--no-color", action="store_true", help="Keine Farben")
    ap.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    return ap.parse_args()


async def amain(args):
    db = Database()
    scanner = Scanner(args, db)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, scanner.stop_event.set)
        except NotImplementedError:
            pass
    if not db.sources and args.mode == "live":
        print("Hinweis: Keine Hersteller-Datenbank gefunden -> 'python3 bt_scan.py --update-db' ausfuehren.",
              file=sys.stderr)
        await asyncio.sleep(2)
    await scanner.run()


def main():
    args = parse_args()
    if args.update_db:
        sys.exit(0 if update_databases() else 1)
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
