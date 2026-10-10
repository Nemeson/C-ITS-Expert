# Codebase-Review C-ITS-Expert (Branch feat/mcp-embedded-m1)

Datum: 2026-10-10. Methode: drei parallele Reviewer (Security/MCP, Decoding-Kern, Tests/CI), nur Code-Lesen, Tests einmal ausgeführt.
Stand Tests: 266 grün, 9,3 s, Coverage 86,32 % (Gate 85 %). Flakiness nicht geprüft.

Urteil: **BLOCK** (2 CRITICAL, 12 HIGH). Befunde sind aus dem Code abgeleitet, nicht alle per Test reproduziert.

## CRITICAL

| # | Ort | Problem | Fix |
|---|-----|---------|-----|
| C1 | `geo/mapem_pdu.py:26,99-102` | Node-XY: Einheit 0,1 m statt 1 cm (Faktor 10), x/y vertauscht (x=lat). Norm (`asn1/standards/r2/DSRC.asn:1171, 2892, 2903`): 1 cm, X=Ost, Y=Nord. Alle MAPEM-Lanes in GeoJSON/KML/MCP sind falsch. `scale`-Feld ignoriert. | `_XY_UNIT_METERS = 0.01`, `lat += y*unit`, `lon += x*unit/cos(lat)`. Tests in `tests/asn1/test_asn1_wiring.py` anpassen. |
| C2 | `core/stream.py:130` | PCAPNG Big-Endian: SHB-Länge immer `<I` gelesen, vor BOM-Prüfung. | BOM zuerst lesen, dann Länge entpacken. |

## HIGH

| # | Ort | Problem | Fix |
|---|-----|---------|-----|
| H1 | `core/stream.py:203` | `stream.read(caplen)` ohne Obergrenze (bis 4 GiB) → OOM auf Edge-Gerät. | `caplen <= min(snaplen, 262144)`, sonst abbrechen. |
| H2 | `core/stream.py:134, 233-242` | PCAPNG-Blocklängen (SHB, alle Blöcke) ohne Obergrenze; Trailer-Länge nie gegen `block_len` geprüft. | Max-Blockgröße, große/unbekannte Blöcke per `seek` überspringen, Trailer prüfen. |
| H3 | `mcp/server.py:335-337` | Pfad-Sandbox `ensure_path_allowed` nur im Profil `device`; `ci`/`host` lesen beliebige Dateien. Check hängt am Argumentnamen `file_path`. | Check in `cits_validate_pcap` selbst, für alle Profile. |
| H4 | `mcp/tools.py:112-118` | TOCTOU: aufgelöster Pfad wird verworfen, Original geöffnet (Symlink-Tausch). | Rückgabewert von `ensure_path_allowed` öffnen. |
| H5 | `mcp/server.py:348-350, 408-419`; `tools.py`, `main.py:94-125` | Kein Limit für Request-Zeile, Argumentgrößen, Dateigröße, Paketzahl; Verstöße werden erst nach dem Sammeln gekappt. | `readline(MAX)`, `max_file_bytes`, `max_packets`, Zählung beim Sammeln. |
| H6 | `lisa/parser.py:62-68` (via `tools.py:160,207`) | `xml.etree` mit unvertrauten Daten: Entity-Expansion. | `defusedxml` oder DOCTYPE/ENTITY ablehnen. |
| H7 | `mcp/server.py:327` | `tools/call` prüft Profil nicht; `device` (read-only) kann `cits_export_kml`, `cits_audit_code` aufrufen. | Profil-Allowlist auch in `tools/call`, `-32601`. |
| H8 | `core/stream.py:168-179` | Iterator nicht wiederverwendbar bei Pfad-Eingabe; Header wird als Record geparst. | Zustand zurücksetzen, Header immer neu lesen. |
| H9 | `rules/r01_link_layer.py:87-207` | Dupliziert `geonet.py`; Fehlalarme bei Management-/Control-Frames, VLAN, Addr4, HT-Control. | `link_layer_offset()` nutzen, Non-Data überspringen. |
| H10 | `asn1/decoder.py:152-186`, `rules/r06_asn1_conformance.py:155-174` | Infrastrukturfehler (Modul fehlt, Compile) = `PduDecodeError`, als Konformitätsfehler gemeldet; Kompilierung pro Paket wiederholt. | Getrennte Exceptions, einmal pro Scan WARNING. |
| H11 | `geo/glosa.py:126-157` | YELLOW wie RED behandelt → falsche Geschwindigkeitsempfehlung (sicherheitsrelevant); `green_end<=0` fällt auf Komfortgeschwindigkeit; keine Eingabevalidierung; ~130 Zeilen. | Gelb separat, "keine Lösung" zulassen, aufteilen, validieren. |
| H12 | `rules/r05_hardware.py:29-68` | Teil-Frames über Chunk-Grenze gehen verloren, Sync-Verlust still, toter Lookahead-Block. | `consumed`/Puffer in `state`, WARNING bei Resync. |
| H13 | `mcp/server.py:293,324-325,420-426` | Jede Exception → `-32700` mit `id: None`; `params`/`arguments`/`file_path` ohne Typprüfung (`TypeError` außerhalb `try`). `inputSchema` wird nie ausgewertet. | Typen prüfen, `-32602` mit echter `id`, Schema validieren. |
| H14 | Tests | Kein Fuzz-/Malformed-Input-Test (`asn1/decoder`, `geonet`, `stream`, `lisa`); `run_stdio`-Schleife ungetestet; keine Tests mit falsch typisierten MCP-Argumenten. | `hypothesis`, stdin-Roundtrip-Tests, parametrisierte Negativtests. |

## MEDIUM

- `mcp/security.py:34-67`: `cap_output` kann `max_bytes` überschreiten (Rest-Payload, JSON-Escapes, Zusatzfelder); `server.py:358` serialisiert mit `indent=2`, gemessen ohne. Nicht kürzbare Strukturen (`cits_parse_lisa`) bleiben unbegrenzt. Nach dem Kürzen erneut prüfen, gleiche `dumps`-Optionen verwenden.
- `mcp/server.py:363-371`: `str(e)` leakt Pfade/interne Meldungen; fehlendes Pflichtargument erscheint als `'code'`.
- `asn1/decoder.py:229`, `r06`: Trailing Bytes nach UPER werden nicht erkannt.
- `core/geonet.py:233-259`: Payload nicht durch GN-PL begrenzt, `geonet_version != 1` nicht abgelehnt.
- `r06:138-145`: Message-ID nicht gegen Port geprüft (`peek_message_id` ungenutzt, `peek_type` toter Code); Sampling (200/Typ) nicht im Report sichtbar.
- `asn1/decoder.py:189-197, 270`: Manifest pro Decode neu von Platte gelesen, sinnloser JSON-Roundtrip.
- `core/stream.py`: `wirelen=len(data)` statt Original-Länge (280); Base-2 `if_tsresol` falsch (317); neuer SHB ändert Byte-Order nicht (244-247); `header_info.dlt` unzuverlässig (256-261, 288-289); unbekannte `interface_id` stiller Fallback (268-272).
- `r04_priority.py:25,26,57-59`: `type=None`/Timestamp crasht; SSEM ohne SREM und doppelte SREM still.
- `r03_topology.py:88-138`: erwartet `laneId`, `mapem_pdu_to_lanes` liefert `lane_id` → alle Lanes still übersprungen.
- `r01:27-35`: `KNOWN_BTP_PORTS` unbenutzt, weicht von `geonet.BTP_PORTS` ab.
- Gesicherte (1609.2) Frames werden nie dekodiert (`secured_undecodable`), Hauptfunktion für Realdaten eingeschränkt.
- `lisa/parser.py`: Namespace-XML ergibt stillen leeren Katalog (80-82); erfundene Default-Aspekte `Rot/Gelb/Gruen` (126, verletzt Zero-Fake-Data); doppelte/ungültige ObjNr still (94, 137).
- `packaging/cits-edge.service`: läuft als root; fehlend: `User/DynamicUser`, `ProtectKernel*`, `RestrictAddressFamilies`, `SystemCallFilter`, `CapabilityBoundingSet=`, `MemoryDenyWriteExecute`, `MemoryMax`, `Environment=CITS_MCP_ROOTS`. `CITS_MCP_ROOTS` mit `;` getrennt statt `os.pathsep`, Default `cwd` (= `/` unter systemd). Mit `systemd-analyze security` prüfen.
- `mcp/security.py:7,23`: `require_token_if_remote` ohne Wirkung (nur stdio) – toter Sicherheitscode.
- `scripts/build_edge_zipapp.py`: Build nicht reproduzierbar (Zeitstempel, `rglob` unsortiert), kein SHA-256/Provenance, keine Modul-Allowlist.
- `scripts/vendor_asn1.py:21`: Hartcodierter Windows-Quellpfad, keine Prüfsummen, Pfad im Manifest.
- `.github/workflows/validate-skill.yml`: Actions nur per Tag, kein `permissions:`, Dependencies ungepinnt, kein `pip-audit`, nur `ubuntu-latest`, Coverage nur Konsole, Skips (`asn1`) nicht überwacht, Zipapp-Job ohne `tools/list`-Roundtrip.
- Coverage-Lücken: `__main__.py` 0 %, `geojson_builder` 76 %, `cli/export` 77 %, `lisa/parser` 78 %, `mcp/server` 79 %; kein Per-Paket-Gate für `mcp/`; Symlink-/Prefix-Tests für `ensure_path_allowed` fehlen.

## LOW

- `core/stream.py`: toter `_interface_count`, `assert` für Narrowing, Dataclasses nicht `frozen` (mutiert `dlt`), fehlende Return-Annotation `iter_records_batched`, unerreichbarer Fall in `_parse_record_block`.
- `r01.audit_packet` ~180 Zeilen, wiederholte Violation-Konstruktion, LLC/SNAP-Literal doppelt.
- `lisa/parser.py:26-41`: redundante `startswith`-Bedingungen, unerreichbarer `BIKE`-Zweig, Substring-Treffer (`"rot" in "protected"`).
- `asn1/decoder.py`: `release_for_message_id` liefert Nachrichtentyp (Umbenennen); Magic Numbers in `r05`, `glosa`.
- `config.py:37`: `int(env)` ohne Validierung.
- `cli/export.py:141-144`: `--output` beliebiger Pfad (CLI ok; nie ins MCP-Tool übernehmen).
- pyproject: mypy nicht strict, ruff nur `E,F,W,I,B` (ergänzen: `S`, `PT`, `UP`), keine pytest-Marker/`--strict-markers`.
- Mögliche Duplikatdatei `validate-skill.yml` im Repo-Root prüfen.
- Zuordnung BTP-Ports 2010/2013/2019 in `core/geonet.py:69-73` gegen TS 103 248 abgleichen (nicht verifiziert).

## Positiv

- Keine Path-Traversal-Lücke in `cits://` (nur exakte URI-Vergleiche), keine hartcodierten Secrets.
- GeoNetworking-Header-Längen, Nibble-Aufteilung, VLAN-Offset, PCAP-Magic korrekt.
- `cap_output` O(n log n); Coverage-Gate in CI und pyproject konsistent; Suite schnell.

## Nicht geprüft

`core/models.py`, `rules/export.py`, `geo/kml_builder.py`, Rest von `cli/main.py` ab Zeile 125, `skill/`, Doku. Kein ruff/mypy/pip-audit-Lauf.

## Umsetzungsstand (TDD, 2026-10-10)

**CRITICAL / HIGH:** vollständig behoben (C1, C2, H1-H14), jeweils mit zuerst fehlschlagendem Test.
Zusätzlicher Fund durch Fuzzing: `cits_parse_lisa`/`lisa_xml` lasen Strings ohne `<` als Dateipfad (Sandbox-Umgehung) → `parse_lisa_xml` (nur Text).

**MEDIUM / LOW – behoben:**
- MCP: `cap_output` hält `max_bytes` auf der echten Wire-Serialisierung (sonst expliziter Fehler), Config-Validierung (`os.pathsep`, Limits, kein Filesystem-Root), keine internen Fehlertexte an Clients.
- Packaging: reproduzierbares Zipapp + `.sha256`, Zipapp liest `CITS_MCP_*`, gehärtete systemd-Unit, SHA-256 der vendorten ASN.1-Module im Manifest (Prüfung vor dem Kompilieren), `vendor_asn1.py` ohne festen Windows-Pfad, `standards_for` gecacht.
- Core: PCAPNG exakte Zeitauflösung (Base 2/10), Original-Länge, EPB-Truncation, Byte-Order pro Section, deterministische DLT + `dlts`, unbekannte Interfaces gezählt; BTP-Payload durch GN-PL begrenzt, GN-Version ≠ 1 abgelehnt; keine `assert` mehr im Reader.
- Regeln: R06 (Trailing Bytes, messageID↔Port, sichtbares Sampling, toter `peek_type` entfernt), R01 (unbekannte BTP-Ports, tote Tabelle entfernt, `audit_packet` in Schritte zerlegt), R03 (Key-Varianten, Float-Toleranz, `None`-Lanes), R04 (Robustheit, verwaiste SSEM, doppelte SREM).
- LISA: Namespaces, keine erfundenen Aspekte, Duplikate/ungültige ObjNr als `warnings`, Wort- statt Substring-Match.
- Geo: GeoJSON/KML erfinden keine Positionen (0,0), Rollen (`ingress`) oder ungültige LineStrings mehr; gemeinsamer Parser `geo/nodes.py`; GLOSA zerlegt, NaN/inf abgelehnt.
- CI/Config: Actions per Commit-SHA, `permissions: contents: read`, Windows-Job, `pip-audit`, Coverage-Artefakt, mcp-Floor 90 %, Skip-Wächter, Zipapp-Roundtrip + Checksum, ruff `S/PT/UP`, `--strict-markers`, mypy `disallow_untyped_defs` für `mcp`.
- Tests: `__main__`, Versions-Fallback, Pfad-Präfix/Symlink, Export-CLI-Fehlerpfade.

**Bewusst offen:**
- IEEE-1609.2-gesicherte Frames werden weiterhin nicht dekodiert (eigenes Feature: COER-Envelope entpacken).
- `cits_validate_pcap` begrenzt Dateigröße, aber nicht die Paketzahl.
- `PcapHeaderInfo`/`PacketRecord` sind nicht `frozen` (Header-Zustand wird beim Iterieren befüllt).
- BTP-Ports 2010/2013/2019 (`core/geonet.py`) gegen ETSI TS 103 248 abgleichen (nicht verifizierbar ohne Norm).
- `release_for_message_id` bleibt als Alias von `message_type_for_id`.

**Stand:** 409 Tests grün, Coverage 91,6 % (`mcp/` 96 %), ruff und mypy sauber.
