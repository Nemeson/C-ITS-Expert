# C-ITS Standards Matrix & ASN.1 / UPER Encoding Reference

## 1. Release 1 vs. Release 2 Standards Evolution

Deployments across Europe and test corridors operate with a dual baseline: Release 1 (currently in production) and Release 2 (current ETSI/C-Roads releases):

| Protocol | Release 1 (Deployed Baseline) | Release 2 (Modern Evolution) | Key Structural Changes |
| :--- | :--- | :--- | :--- |
| **CAM** | **ETSI EN 302 637-2 v1.4.1** | **ETSI TS 103 900 v2.3.1** | *Notice:* There is no EN 302 637-2 V2.x. Release 2 transitioned to TS 103 900 and imports from `ETSI-ITS-CDD`. |
| **DENM** | **ETSI EN 302 637-3 v1.3.1** | **ETSI TS 103 831 v2.3.1** | Event handling, mitigation zones, trace point extensions. |
| **CDD** | **ETSI TS 102 894-2 v1.3.1** (`ITS-Container`) | **ETSI TS 102 894-2 v2.4.1** (`ETSI-ITS-CDD`) | Module renamed from `ITS-Container` to `ETSI-ITS-CDD`. All R2 messages import from this module. |
| **Infra (SPAT/MAP)** | **ETSI TS 103 301 v1.3.1** | **ETSI TS 103 301 v2.3.1** | Annex A specifications, ISO TS 19091 AddGrp-C integration, DSRC schema updates. |
| **VRU / VAM** | *(Stubs / None)* | **ETSI TS 103 300-3** | Vulnerable Road User awareness, pedestrian and motorcycle clusters. |
| **CPM** | *(None)* | **ETSI TS 103 324** | Collective Perception: sensor object sharing, perceived objects list. |

---

## 2. ASN.1 UPER (Unaligned Packed Encoding Rules) Traps

ASN.1 UPER packs information to the exact bit, without padding to byte boundaries until the final bit of the entire PDU:

### 2.1 Extension Markers (`...`)
- In ASN.1 sequences, `...` denotes an **extension root**.
- When an extension marker is present, UPER encodes an **extension bit** before optional additions:
  - `0`: Only fields within the extension root are present.
  - `1`: Extension additions follow (preceded by a length determinant and bitmask).
- **Critical Pitfall**: If a decoder omits checking the extension bit, every subsequent field will be bit-shifted by 1 bit, corrupting the remainder of the message.

### 2.2 Enumerations and Bit Strings
- Enums are encoded using the minimum number of bits needed to represent the value range (e.g., 4 choices = 2 bits, 5 choices = 3 bits).
- Unaligned bit packing means an enum value of 3 bits is immediately concatenated with the next boolean or integer. Never use byte-slicing on raw payloads; always use a dedicated bitstream reader.

### 2.3 A correct implementation does not hand-roll this
The `cits_validator` ASN.1 core (`pip install -e ".[asn1]"`) compiles the real
ETSI/ISO modules with `asn1tools` and decodes through them, so the extension bit
is evaluated by the generated codec rather than by hand-written bit arithmetic.
It runs as rule `R06`:

```bash
cits-lint --pdu <hex> --msg-type MAPEM --release r1
cits-lint capture.pcap --asn1 --release r2
```

Two limits are stated instead of worked around:

- **Release 1 vs Release 2 have separate decoders.** The CDD module differs
  (`ITS-Container` vs `ETSI-ITS-CDD`), so `--release` selects the baseline. They
  also differ in field names: Release 1 uses `messageID`/`stationID`, Release 2
  renamed them to `messageId`/`stationId`. Reading one spelling blindly reads
  nothing in the other release.
- **IEEE 1609.2 secured frames are not decoded.** Their Common Header and BTP sit
  inside the security envelope, so a plaintext decode would be a fabrication.
  `R01` reports such frames as `secured` and `R06` counts them as
  `secured_undecodable`.

A PDU that fails to decode is reported as an error. A PDU that decodes but
carries no usable geometry yields an empty result with an explicit
`NO DATA IN CAPTURE` status — never a synthesised shape.

---

## 3. Standard Field Scaling Factors

Coordinates and physical quantities in C-ITS messages use fixed-point integer encodings:

| Parameter | Unit in ASN.1 Definition | Multiplier to SI Unit | Unavailable Sentinel |
| :--- | :--- | :--- | :--- |
| **Latitude** | Tenths of microdegrees ($10^{-7}$ deg) | `val / 10_000_000.0` $\to$ Decimal deg | `900000001` ($90.0000001$) |
| **Longitude** | Tenths of microdegrees ($10^{-7}$ deg) | `val / 10_000_000.0` $\to$ Decimal deg | `1800000001` ($180.0000001$) |
| **Altitude** | Decimeters ($0.1$ m) | `val / 10.0` $\to$ Meters | `800001` |
| **Speed** | Centimeters per second ($0.01$ m/s) | `val * 0.036` $\to$ km/h | `16383` |
| **Heading** | $0.1$ degrees ($0 \dots 3600$) | `val / 10.0` $\to$ Degrees from True North | `3601` |
| **Acceleration**| $0.1\ \text{m/s}^2$ | `val / 10.0` $\to\ \text{m/s}^2$ | `161` |
