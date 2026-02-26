# Hash Generator Tool

Ein Windows-Tool mit grafischer Oberflaeche zum Generieren von NTLM- und SHA1-Hashes aus Excel- und CSV-Dateien.

## Download

Die portable Version (HashTool.exe) kann direkt aus den [Releases](../../releases) heruntergeladen werden - keine Installation erforderlich.

## Features

- **Excel (.xlsx) und CSV Support**
- **NTLM-Hash** (MD4-basiert, Windows-Passwort-Format)
- **SHA1-Hash**
- **Beide Hash-Typen gleichzeitig** moeglich
- **Automatische Maskierung** der Originaldaten (erste 3 Zeichen + ***)
- **Excel-Tabellen (Filter)** werden automatisch erweitert
- **Automatische CSV-Delimiter-Erkennung** (Semikolon, Komma, Tab, Pipe)
- **Konfigurierbare CSV-Optionen** (Trennzeichen, Encoding)
- **Header-Erkennung** - erste Zeile kann als Titel behandelt werden
- **Automatische Passwort-Spalten-Erkennung** (password, passwort, pwd, kennwort, pass)
- **Multi-CSV-Zusammenfuehrung** - mehrere CSVs mit identischer Struktur auf einmal verarbeiten
- **Automatischer Excel-Export** bei CSV-Verarbeitung (mit Autofilter, Spaltenbreite, leere Spalten ausgeblendet)

## Installation (aus Quellcode)

```bash
# Repository klonen
git clone https://github.com/CrisioDev/PW-HashTool.git
cd PW-HashTool

# Dependencies installieren
pip install -r requirements.txt

# Starten
python hash_tool.py
```

## Portable Version erstellen

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "HashTool" hash_tool.py
```

Die .exe liegt dann im `dist/` Ordner.

## Verwendung

1. **Datei auswaehlen** - Klicke auf "Durchsuchen..."
2. **Header-Option** - Waehle ob erste Zeile ein Titel ist
3. **Sheet waehlen** (nur Excel) - Waehle das Tabellenblatt
4. **Spalte waehlen** - Waehle die Spalte zum Hashen
5. **Hash-Typ waehlen** - NTLM und/oder SHA1
6. **Verarbeiten & Speichern** - Neue Datei wird erstellt

### CSV-Optionen

| Option | Werte | Standard |
|--------|-------|----------|
| Trennzeichen | ; , Tab \| | Automatisch erkannt |
| Encoding | utf-8, latin-1, cp1252, iso-8859-1 | utf-8 |

## Beispiel

**Vorher:**

| Name | Passwort |
|------|----------|
| Max | geheim123 |
| Anna | test456 |

**Nachher:**

| Name | Passwort | Passwort_NTLM_Hash | Passwort_SHA1_Hash |
|------|----------|-------------------|-------------------|
| Max | geh*** | 7A21990FCD... | 5BAA61E4C9... |
| Anna | tes*** | 5BCF78F67C... | 7C4A8D09CA... |

## Systemanforderungen

- Windows 10/11, macOS oder Linux
- Oder: Python 3.7+ mit tkinter und openpyxl

## Lizenz

MIT License
