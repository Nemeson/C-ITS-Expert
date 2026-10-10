# Draft requests: redistribution of ISO-authored ASN.1 text

Status: **drafts, not sent.** Send from your own mailbox (the project contact is
`vertrieb@seipel.uk`). Adjust the sender name and attach nothing. Keep the replies; if ISO or ETSI
confirms, record the answer in `NOTICE` and `docs/legal/`.

## What is being asked and why
The open-source project https://github.com/Nemeson/C-ITS-Expert (MIT licence) ships ASN.1 modules
so its validator can decode C-ITS messages offline. Three files contain ISO-authored text that
ETSI republishes in its Forge repository `ITS/asn1/is_ts103301`:

| File in our repository | ETSI path | ISO standard |
| :--- | :--- | :--- |
| `r1/ISO-TS-19091-DSRC.raw.asn` | `reference/ISO-TS-19091-DSRC.raw.asn` (v2.2.1) | ISO/TS 19091 |
| `r1/ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn` | `iso-patched/…` (v2.1.1) | ISO 24534-3 |
| `r2/DSRC.asn` | `DSRC.asn` (v2.2.1) | ISO/TS 19091 (via ETSI TS 103 301) |

ISO's "Licence Agreement for electronic inserts" allows use in the original format without
modification. It does not mention redistribution, and the second file is a modified copy.

## Draft 1 - ISO (copyright@iso.org)

**Subject:** Redistribution of ASN.1 electronic inserts (ISO/TS 19091, ISO 24534-3) in an open-source tool

Dear ISO Copyright team,

I maintain an open-source (MIT) validator for cooperative ITS captures,
https://github.com/Nemeson/C-ITS-Expert. To decode DSRC/SPATEM/MAPEM and ITS-container messages it
needs the ASN.1 modules of ISO/TS 19091 and ISO 24534-3.

The "Licence Agreement for electronic inserts" on standards.iso.org permits use of the inserts in
their original format without modification. We would like to confirm:

1. May we include the unmodified ASN.1 files in our public repository and in released packages
   (source and wheel), with the ISO copyright notice and a pointer to standards.iso.org?
2. ETSI publishes a modified ("patched") copy of the ISO 24534-3 module that fixes compiler
   issues. May that patched copy be redistributed, or must users obtain the original from ISO?
3. If redistribution is not permitted, is a script that downloads the files from standards.iso.org
   on the user's machine (the user accepting your licence at download time) acceptable?

The project is non-commercial and the files are used only to compile and decode PDUs as intended by
the standards. Thank you for your help.

Kind regards,
Kevin Seipel

## Draft 2 - ETSI (via the Forge maintainers / ITS WG1 contact)

**Subject:** Rights in ISO-derived ASN.1 files in ETSI Forge `ITS/asn1/is_ts103301`

Dear ETSI ITS team,

Our open-source validator (https://github.com/Nemeson/C-ITS-Expert, MIT) redistributes ASN.1
modules from your Forge repositories under the BSD-3-Clause licence, with the copyright notices
reproduced as required. Thank you for publishing them.

Three files in `is_ts103301` contain ISO-authored text (`reference/ISO-TS-19091-DSRC.raw.asn`,
`iso-patched/ISO24534-3_…-patched.asn`, and `DSRC.asn`). Could you confirm:

1. Does the BSD-3-Clause licence of the repository also cover these ISO-authored files, i.e. has ISO
   agreed that ETSI may publish and license them this way?
2. Is redistribution of these files by third parties permitted on the same terms?

If not, we will fetch them from the original ISO location at install time instead. We would be
grateful for a short reply that we can quote in our NOTICE file.

Kind regards,
Kevin Seipel

## Fallback if either answer is "no" or there is none after a reasonable time
Remove the three files from the repository and the wheel, add a `cits-lint --fetch-standards` step
that downloads them from standards.iso.org (verifying the SHA-256 in `manifest.json` and applying
the ETSI patch locally), and keep Release 2 decoding working from the ETSI-only modules. Ask the
assistant to implement this; the manifest already records the hashes.
