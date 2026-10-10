# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

## Reporting a Vulnerability

We take the security of C-ITS systems, packet parsers, and AI tool integrations seriously.

If you discover a security vulnerability (such as a buffer overrun in C++ dissectors, parsing denial-of-service in the streaming iterator, or unsafe deserialization), please report it responsibly:

1. **Do not open a public issue.**
2. Email your report with steps to reproduce and an optional sample PCAP to:  
   **vertrieb@seipel.uk**
3. We will acknowledge receipt within 48 hours and coordinate a coordinated fix and advisory.

## Hardening notes (1.5.0)

- The MCP server reads files only below `CITS_MCP_ROOTS` in every profile, and bounds file
  size, packet count, request size and output size.
- Untrusted XML (LISA) is rejected if it declares a DTD or entities.
- IEEE 1609.2 envelopes are **read, not verified**: signatures and certificates are not
  checked, so a "signed" frame must not be treated as authentic.
- Vendored ASN.1 modules are verified against SHA-256 values in the manifest before use.
