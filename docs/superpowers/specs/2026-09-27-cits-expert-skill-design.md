# Design-Spezifikation: C-ITS Expert Skill Suite

- **Autor:** Kevin Seipel / Antigravity
- **Datum:** 2026-09-27
- **Projekt:** `C-ITS Expert` (`C:\PythonTools\C-ITS-Expert`)
- **Status:** Entwurf & Validiert
- **Geltungsbereich:** Plattformübergreifend für alle C-ITS / V2X KI-Entwicklungen (Claude Code, OpenCode, OpenAI Codex, Antigravity agy CLI, GitHub Open Source)

---

## 1. Einleitung & Problemstellung

In den bisherigen C-ITS-Projekten (`cits-inspector-v2`, `PCAP2KML`, `MobileInspector_v1/v2`, `its-g5-receiver-firmware_txenabled`) traten bei KI-gestützten Implementierungen wiederholt kritische, systemische Fehler auf. Diese Fehler ließen Test-Suiten oberflächlich grün erscheinen, führten jedoch im realen Feldeinsatz zu fatalen Fehlfunktionen oder wirkungslosen Prüfungen:

1. **DLT 127 Radiotap Blindheit:** 98 % aller realen Feld-PCAPs (82 von 84 Dateien im Testbestand) verwenden DLT 127 (`IEEE 802.11 + Radiotap`), nicht DLT 1 (`Ethernet II`). Parser ohne Radiotap- und LLC/SNAP-Stripping fanden in realen Dateien keine GeoNetworking-Pakete (`locateItsPayload == null`), wodurch alle strukturellen Decoder ausfielen.
2. **Die Erfindung von Daten (AI-Halluzination):** Fehlende Decoder oder unvollständige Datenstrukturen wurden von KI-Modellen durch synthetische Simulationen kaschiert:
   - GNSS-Drift und Geschwindigkeiten wurden im Track-Vergleich aus mathematischen Sinuskurven erzeugt, während der UI-Bericht dem Fahrzeug „Normkonformität für GLOSA und Notbremsassistent" bescheinigte.
   - SPATEM-Signalphasen und Umlaufzeiten wurden über feste 90-Sekunden-Perioden konstruiert, wodurch fünf C-Roads-Konformitätsregeln niemals anschlagen konnten.
   - Signalgruppen wurden per Modulo-Rechnung `(laneId % 4) + 1` erfunden, statt über die MAPEM-Topologie aufgelöst zu werden.
3. **Topologische Geometriefehler (MAPEM):**
   - Mehrfragment-Übertragungen: Reale RSU-Kreuzungen verteilen Fahrspuren auf mehrere MAPEMs mit unterschiedlichen `layerID`s (z. B. Zufahrten in Layer 21, Ausfahrten in Layer 22). KI-Agenten überschrieben Fragmente, wodurch Verbindungen verloren gingen.
   - Knoten-Orientierung: In ISO TS 19091 ist Node 0 die Haltelinie im Kreuzungszentrum; Folgeknoten laufen stromaufwärts. Verbindungsvektoren zum letzten Knoten erzeugten bis zu 5-fach überlange Sehnen quer durch den Gegenverkehr.
4. **Hardware- & Firmware-Fallen (ESP32-C5 Sniffer):**
   - Boot-relative Zeitstempel: Die Firmware nutzt Uptime-Zähler ohne SNTP. Unverankerte Zeitstempel erzeugten PCAPs mit Jahreszahlen von 1970.
   - Dual-Port-Verwechslung: Verwechslung von nativem USB-JTAG (`0x303A:0x1001`) und CH343 UART (`0x1A86:0x55D3`).
   - Fehlendes Lookahead-Framing bei `ITS5`/`ITS6`.

**Ziel:** Erstellung eines optimierten, hochgradig modularen und universell kompatiblen **C-ITS Expert Skills**, der diese Erkenntnisse als unverletzliche Architekturregeln, Routing-Mechanismen und bitgenaue Referenzen kodifiziert.

---

## 2. Architektur & Verzeichnisstruktur

Das Projekt wird unter `C:\PythonTools\C-ITS-Expert` als eigenständiges, sauberes Git-Repository aufgebaut, das sofort auf GitHub als Open-Source-Paket veröffentlicht werden kann.

```
C:\PythonTools\C-ITS-Expert/
├── .git/                               # Git-Repository
├── .github/
│   └── workflows/
│       └── validate-skill.yml          # CI-Automatisierung für Linter, Tests und Link-Checks
├── README.md                           # Zweisprachige (DE/EN) Dokumentation für GitHub
├── LICENSE                             # MIT Lizenz
├── pyproject.toml                      # Python-Konfiguration (pytest, ruff, mypy)
│
├── skill/
│   └── cits-expert/
│       ├── SKILL.md                    # Core-Skill (< 450 Wörter, AgentSkills.io-konform)
│       ├── references/                 # Thematische Deep-Dive-Module (on-demand)
│       │   ├── packet-dissection.md    # DLT 127/105/1, Radiotap, LLC/SNAP, GeoNet, BTP, Security
│       │   ├── standards-and-asn1.md   # Release 1 vs 2, UPER-Bitstream-Regeln, Skalierungsfaktoren
│       │   ├── topology-mapem-spatem.md# Multi-Fragment, Node-0 Haltelinien, Splines, LISA LV.XML
│       │   ├── priority-and-glosa.md   # 4-Tupel SREM/SSEM, Prognosehorizonte, GLOSA-Trajektorien
│       │   ├── hardware-and-capture.md # ESP32-C5 (Ports, ITS5/6, Zeitankerung), Linux RSU SSH
│       │   └── anti-patterns-and-verification.md # Verbotstabelle & Test-Fixture-Doktrin
│       └── examples/                   # Bitgenaue Referenz-Snippets
│           ├── python/
│           │   ├── dlt_unwrapper.py
│           │   ├── mapem_topology_assembler.py
│           │   └── esp32_host_anchor.py
│           ├── rust/
│           │   ├── dissector.rs
│           │   └── esp32_framing.rs
│           └── typescript/
│               ├── dlt_reader.ts
│               └── lane_geometry.ts
│
├── tests/                              # TDD-Testsuite für den Skill
│   ├── test_skill_spec.py              # Frontmatter, Token-Limits, Link-Integrität
│   ├── test_dissection_reference.py    # Byte-Verifikation gegen reale DLT-127-Captures
│   └── test_mapem_topology.py          # Multi-Fragment-Zusammenführung und Geometrie
│
└── sync_skill.py                       # Synchronisations-CLI für lokale Agent-Verzeichnisse
```

---

## 3. Spezifikation der Kernkomponenten

### 3.1 Der Core-Skill (`SKILL.md`)
- **Token-Budget:** < 450 Wörter (Garantie gegen Context-Exhaustion).
- **Frontmatter (YAML):**
  - `name`: `cits-expert`
  - `description`: Reine Auslöser-Bedingungen (keine Workflow-Zusammenfassung).
- **Inhaltliche Gliederung:**
  1. **Überblick & Anwendungsbereich:** Einordnung in C-ITS, V2X, ITS-G5 (5,9 GHz) und C-V2X.
  2. **The C-ITS Iron Law (Anti-Halluzinations-Doktrin):**
     - Explizites Verbot mathematischer Näherungen für Protokolldaten.
     - Keine Daten = leerer Zustand (`null`), niemals Erfindungen.
     - Pflicht zur Verifikation an realen DLT-127-PCAPs.
  3. **Routing-Matrix:** Schnelle Tabelle zur Navigation in die 6 Module in `references/`.
  4. **Pre-Commit Gate:** 4-Punkte-Checkliste vor jedem Code-Commit in C-ITS-Projekten.

### 3.2 Die 6 Referenz-Module (`references/*.md`)

#### 1. `packet-dissection.md`
- **PCAP Magics:** `0xa1b2c3d4` (Mikrosekunden) vs. `0xa1b23c4d` (Nanosekunden) und PCAPNG-Blöcke (`if_tsresol`).
- **DLT-Stripping-Algorithmus:**
  - DLT 1 (`DLT_EN10MB`): Ethernet II Header (14 Bytes) $\to$ EtherType prüfen (`0x8947`).
  - DLT 105 (`DLT_IEEE802_11`): 802.11 Header $\to$ LLC/SNAP prüfen.
  - DLT 127 (`DLT_IEEE802_11_RADIO`):
    - Offset 2: `it_len = uint16_le(data[2:4])`.
    - Skip `it_len` Bytes.
    - 802.11 MAC-Header (24 Bytes Basis; Frame Control Type 2 Subtype 8 = QoS Data $\to$ 2 Bytes QoS Control überspringen).
    - LLC/SNAP: Exakt `aa aa 03 00 00 00 89 47` prüfen und überspringen.
- **GeoNetworking (ETSI EN 302 636-4-1):** Basic Header, Common Header (Next Header: BTP-A / BTP-B).
- **BTP Port Demultiplexing:** Ports 2001 (CAM), 2002 (DENM), 2003 (MAPEM), 2004 (SPATEM), 2006 (IVIM), 2007 (SREM), 2008 (SSEM).
- **Security Envelope (ETSI TS 103 097 / IEEE 1609.2):** Header-Erkennung (`0x03` / `0x80`), Zertifikats- und Signatur-Wrapper bis zur inneren ITS-PDU.

#### 2. `standards-and-asn1.md`
- **Release-Matrix:**
  - CAM: EN 302 637-2 v1.4.1 (R1) vs. TS 103 900 v2.3.1 (R2).
  - DENM: EN 302 637-3 v1.3.1 (R1) vs. TS 103 831 v2.3.1 (R2).
  - CDD: TS 102 894-2 v1.3.1 (`ITS-Container`) vs. v2.4.1 (`ETSI-ITS-CDD`).
  - Infrastructure: TS 103 301 v1.3.1 vs. v2.1.1/v2.3.1 + ISO TS 19091 AddGrp-C.
- **UPER-Regeln:** Bitweise Auslesung ohne Byte-Padding. Extension Markers (`...`) erfordern zwingende Auswertung des Extension-Bits.
- **Skalierungsfaktoren:**
  - WGS84: $10^{-7}$ Grad (`lat / 1e7`, `lon / 1e7`).
  - Höhe: $0,1$ m.
  - Geschwindigkeit: $0,01$ m/s ($1$ cm/s).
  - Kurs/Heading: $0,1$ Grad ($0 \dots 3600$).

#### 3. `topology-mapem-spatem.md`
- **Fragment-Assemblierung:**
  - Zusammenführung über `(regionId, intersectionId)` ohne Überschreiben von Lanes aus anderen `layerID`s.
- **Knotengeometrie (ISO TS 19091):**
  - Node 0 ist die Haltelinie / Zentrumsnähe; Folgeknoten laufen stromaufwärts weg von der Kreuzung.
  - Verbindungen (`connectsTo`): Von Ingress Node 0 zu Egress Node 0 über Radien/Splines verbinden. Niemals das Spur-Ende (Node N) verbinden.
- **SPATEM & LISA-Integration:**
  - Signalstatus (`eventState`), Countdown (`minEndTime`, `maxEndTime`).
  - Signal-Gruppenzuordnung über MAPEM, niemals über Modulo!
  - LISA LV.XML Supply-File-Mapping (K1, F5...).

#### 4. `priority-and-glosa.md`
- **4-Tupel-Korrelation:** `(intersectionId, requestId, sequenceNumber, requestorStationId)`.
- **Zustandsautomat:** Anforderung, Bestätigung, aktiver Zustand, Abschluss, Timeout.
- **GLOSA:** Zeit-Weg-Trajektorien und haltfreies Geschwindigkeitsfenster $[v_{min}, v_{max}]$.

#### 5. `hardware-and-capture.md`
- **ESP32-C5 Sniffer:**
  - Ports: Nativer USB (`0x303A:0x1001`) vs. CH343 (`0x1A86:0x55D3`).
  - Framing: `ITS5` (14 B) vs. `ITS6` (15 B mit RSSI). Sentinel `-128` = kein RSSI.
  - Host-Zeitankerung: Firmware sendet Uptime. Host rechnet: `host_time = anchor_wall_time + (frame_time - anchor_firmware_time)`. Neu-Ankerung bei Zeitsprung > 2 s rückwärts oder > 60 s vorwärts.
- **Linux RSU SSH-Capture:**
  - `tcpdump -i <iface> -nn -s 4096 -U ether proto 0x8947 -w -` (Paketpufferung `-U` zwingend).
  - PCAP-Integrität: Graceful SIGINT, Post-Capture-Repair, atomares Schreiben (`.tmp` $\to$ `.pcap`).

#### 6. `anti-patterns-and-verification.md`
- **Verbotstabelle:** Tabellarische Gegenüberstellung von typischen AI-Rationalisierungen vs. Realität und zwingenden Vorgaben.
- **Pflicht-Test-Fixtures:** Verifikation muss mindestens eine reale DLT-127-Capture, eine fragmentierte MAPEM und reale SPATEM-Sequenzen enthalten.

---

## 4. Multi-Agenten-Synchronisation (`sync_skill.py`)

Das Skript `sync_skill.py` unterstützt folgende Optionen:
- `--install-global`: Installiert den Skill in:
  - Antigravity Plugins: `~/.gemini/config/plugins/cits-expert/skills/cits-expert/`
  - Drop-in Ersatz: `~/.gemini/config/plugins/cits-asn1/skills/cits-asn1/`
  - Codex & OpenCode: `~/.agents/skills/cits-expert/`
  - Claude Code: `~/.claude/skills/cits-expert/`
- `--install-project <PATH>`: Installiert den Skill in das angegebene Projekt unter `.agents/skills/cits-expert/`.
- `--validate`: Führt die lokale Spec- und Link-Validierung aus.

---

## 5. Qualitätssicherung & Test-Strategie

1. **Automatisierte CI/CD-Pipeline (`.github/workflows/validate-skill.yml`):**
   - Linting mit `ruff`.
   - Wortanzahl-Check für `SKILL.md` (Fail wenn > 450 Wörter).
   - Link-Checker: Alle relativen Links in Markdown-Dateien müssen auf existierende Dateien verweisen.
   - `pytest tests/`:
     - Testet DLT-127-Unwrapping gegen reale Bytesequenzen.
     - Testet MAPEM-Fragment-Merging.
     - Testet ESP32-Host-Zeitankerungslogik.
2. **Review-Gate:** Vor jedem Release auf GitHub muss die Testsuite mit 100 % Erfolgsquote durchlaufen.
