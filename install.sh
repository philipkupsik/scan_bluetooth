#!/usr/bin/env bash
# Installiert alles Noetige fuer bt_scan.py (Debian/Ubuntu, als root im LXC-Container ausfuehren)
set -euo pipefail
cd "$(dirname "$0")"

apt-get update
apt-get install -y bluez dbus python3 python3-venv usbutils

systemctl enable --now dbus bluetooth || true

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

.venv/bin/python bt_scan.py --update-db || echo "Datenbank-Download teilweise fehlgeschlagen (Scanner laeuft trotzdem)."

echo
echo "Fertig. Starten mit:"
echo "  $(pwd)/.venv/bin/python $(pwd)/bt_scan.py"
