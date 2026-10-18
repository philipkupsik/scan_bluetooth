# scan_bluetooth

Dauerhafter Bluetooth-Scanner für Linux (BlueZ). Er sucht ohne Pause nach **Classic- und BLE-Geräten**
und zeigt sie so an:

```
Name - MAC - Signal
```

Unter jeder Zeile stehen alle Details, die sich ermitteln lassen:

| Detail | Quelle |
|---|---|
| Hersteller laut MAC-Adresse | IEEE-OUI-Datenbank (nur bei öffentlichen Adressen) |
| Hersteller aus den Funkdaten | Bluetooth-SIG-Firmen-ID in den Manufacturer Data |
| Modell, Seriennummer, Hardware/Firmware/Software-Version, PnP-ID, Akku | GATT *Device Information Service* (nur mit `--deep`) |
| Geräteart (Smartphone, Kopfhörer, Uhr, Maus, …) | Class of Device (Classic) / Appearance (BLE) |
| Hersteller- und Produkt-ID | Modalias (Device ID) |
| AirPods/Beats: Modell + Akkustand, iBeacon, Eddystone, Find My, Microsoft Swift Pair/CDP, Google Fast Pair (Modell-ID), Xiaomi MiBeacon, RuuviTag-Messwerte, BTHome | Auswertung der Advertising-Daten |
| Dienste (UUIDs mit Namen) | Bluetooth-SIG-UUID-Liste |
| Adresstyp (öffentlich / zufällig statisch / privat wechselnd) | Adresse |
| Signal min/max/Mittel, Sendeleistung, geschätzte Entfernung | RSSI + TxPower |
| gekoppelt / verbunden / vertraut | BlueZ |
| Rohdaten (Hex) | Advertising-Daten |

Beispiel:

```
AirPods Pro - 4C:32:75:00:11:22 - -58 dBm ████░ gut
    Typ: BLE  |  Adresse: random (privat, aufloesbar - wechselt regelmaessig)
    Hersteller (Funkdaten): Apple, Inc. (ID 0x004C)
    Geraeteart: Ohrhoerer (In-Ear) (0x0941)
    Info: Apple AirPods Pro (2. Gen): Akku links 80%, rechts 90%, Case 100%
    Signal: min -63 / max -52 / Mittel -58 dBm  |  Sendeleistung 4 dBm  |  Entfernung ca. 2.1 m
    ...

Pixel 8 - 00:1A:7D:DA:71:13 - -77 dBm ██░░░ schwach
    Typ: Classic (BR/EDR)  |  Adresse: public
    Hersteller (MAC): Google, Inc.
    Geraeteklasse: Telefon / Smartphone  [Dienste: Netzwerk, Aufnahme, Objektuebertragung, Telefonie]
```

## Installation (im LXC-Container, als root)

```bash
git clone <dieses-repo> /opt/scan_bluetooth
cd /opt/scan_bluetooth
./install.sh
```

`install.sh` installiert `bluez`, `dbus` und Python, legt eine venv mit `dbus-fast` an und lädt die
Hersteller-Datenbanken nach `data/` (IEEE OUI, Bluetooth-SIG-Firmen-IDs und UUIDs). Die Datenbanken
lassen sich jederzeit mit `--update-db` aktualisieren. Ohne sie läuft der Scanner auch, kennt dann
aber nur eine kleine eingebaute Herstellerliste.

## Benutzung

```bash
.venv/bin/python bt_scan.py                 # Live-Ansicht, wird jede Sekunde aktualisiert
.venv/bin/python bt_scan.py --deep          # zusätzlich Hersteller/Modell/Seriennr. per GATT auslesen
.venv/bin/python bt_scan.py -c              # kompakt: nur "Name - MAC - Signal"
.venv/bin/python bt_scan.py -m log          # fortlaufendes Log statt Live-Ansicht
.venv/bin/python bt_scan.py -t le -i 0.5    # nur BLE, schnellste Aktualisierung
.venv/bin/python bt_scan.py --once 30 -j scan.json   # 30 s scannen, ausgeben, als JSON speichern
```

| Option | Bedeutung |
|---|---|
| `-a hci0` | Adapter wählen (Name oder MAC) |
| `-m live\|log` | Live-Bildschirm (Standard) oder fortlaufende Zeilen |
| `-t auto\|le\|bredr` | Classic + BLE (Standard), nur BLE oder nur Classic |
| `-i 1` | Aktualisierungsintervall in Sekunden |
| `--timeout 120` | Geräte ausblenden, die so viele Sekunden nicht gesehen wurden |
| `--min-rssi -80` | nur Geräte mit Signal ab -80 dBm |
| `-s rssi\|name\|mac\|seen` | Sortierung |
| `-c` | kompakte Ausgabe ohne Details |
| `-d`, `--deep` | BLE-Geräte kurz verbinden und den Device Information Service lesen |
| `-j datei.json` | aktuelle Liste laufend als JSON schreiben (z. B. für Home Assistant/Node-RED) |
| `--once 30` | 30 s scannen, Ergebnis ausgeben und beenden |
| `--update-db` | Hersteller-Datenbanken herunterladen |

### So oft wie möglich scannen

- Der Scanner setzt einen Discovery-Filter mit `DuplicateData=true`. Damit meldet BlueZ jedes
  Advertising-Paket weiter und nicht nur das erste.
- Ein Watchdog startet die Suche sofort neu, falls sie gestoppt wird, z. B. durch ein anderes Programm.
- `-t auto` wechselt zwischen BLE-Scan und Classic-Inquiry. Classic-Geräte werden dadurch nur etwa alle
  10 s aktualisiert. Wenn BLE möglichst schnell aktualisiert werden soll, nimm `-t le`.
- Classic-Geräte tauchen nur auf, wenn sie **sichtbar** sind. Gekoppelte Handys oder Kopfhörer, die
  nicht im Kopplungsmodus sind, antworten auf keine Suche. Das ist eine Grenze von Bluetooth selbst.

### Zu `--deep` (Modell, Seriennummer, Firmware)

Hersteller, Modell und Seriennummer stehen nicht in den Funkpaketen. Man bekommt sie nur, indem man
sich mit dem Gerät verbindet und den *Device Information Service* liest. `--deep` macht das
automatisch: Es verbindet sich nacheinander mit jedem BLE-Gerät, das stark genug empfangen wird
(`--deep-min-rssi`, Standard -85 dBm), liest die Werte und trennt sofort wieder. Ein Gerät, das
schon gelesen wurde, wird nicht noch einmal abgefragt; bei einem Fehler gibt es höchstens 3 Versuche
im Abstand von 5 Minuten.
Viele Geräte erlauben keine Verbindung (Beacons, Handys mit privater Adresse) oder bieten den Dienst
nicht an. Dann steht ein entsprechender Hinweis in der Ausgabe. Verbinde dich nur mit Geräten, bei
denen du das darfst.

## LXC / Proxmox: USB-Dongle im Container

Wenn `bluetoothctl list` im Container den Adapter anzeigt, ist alles bereit. Sonst prüfe Folgendes:

1. **USB-Gerät durchreichen** (`/etc/pve/lxc/<ID>.conf` auf dem Host):
   ```
   lxc.cgroup2.devices.allow: c 189:* rwm
   lxc.mount.entry: /dev/bus/usb dev/bus/usb none bind,optional,create=dir
   ```
   Das Kernelmodul `btusb` läuft auf dem Host. Die Container teilen sich dessen Kernel.

2. **Netzwerk-Namespace:** Der Linux-Kernel erlaubt Bluetooth-Sockets nur im Netzwerk-Namespace
   des Hosts. Ein Container mit eigenem Netzwerk bekommt beim Start von `bluetoothd` die Meldung
   `Address family not supported by protocol` bzw. sieht keinen Adapter. Lösung: Der Container
   nutzt das Host-Netzwerk. Entferne dazu die `net0:`-Zeile und füge hinzu:
   ```
   lxc.net.0.type: none
   ```
   Je nach Kernel muss der Container dafür privilegiert sein.

3. **bluetoothd nur an einer Stelle:** Auf dem Host darf kein eigener `bluetoothd` den Adapter
   belegen (`systemctl disable --now bluetooth` auf dem Host). Im Container müssen `dbus` und
   `bluetooth` laufen.

4. Prüfen im Container: `lsusb`, `btmgmt info`, `bluetoothctl list`.

### Fehler `org.bluez.Error.Failed: Authentication Failed` beim Einschalten

Die Meldung ist irreführend. Der Kernel meldet damit einen **Timeout**: Der Dongle hat auf den
Einschaltbefehl nicht geantwortet. Meist fehlt die Firmware. Sie wird vom **Host**-Kernel geladen,
nicht im Container. So gehst du vor:

```bash
# auf dem Proxmox-Host
dmesg | grep -iE 'bluetooth|btusb|rtl|firmware'   # z.B. "rtl_bt/rtl8761bu_fw.bin failed with error -2"
apt install pve-firmware                          # bzw. linux-firmware / firmware-realtek
systemctl disable --now bluetooth                 # kein zweiter bluetoothd auf dem Host
rfkill unblock bluetooth
# Dongle ab- und wieder anstecken, dann im Container:
btmgmt power on && bluetoothctl show
```

## Als Dienst laufen lassen (optional)

`/etc/systemd/system/bt-scan.service`:

```ini
[Unit]
Description=Bluetooth-Scanner
After=bluetooth.service
Requires=bluetooth.service

[Service]
ExecStart=/opt/scan_bluetooth/.venv/bin/python /opt/scan_bluetooth/bt_scan.py -m log -j /run/bt_scan.json
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now bt-scan
journalctl -fu bt-scan        # Log ansehen
```
