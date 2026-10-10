# Publishing checklist and drafts

The repository is public (MIT). This page lists what remains to make it easy to find and to trust.
Items marked **[you]** need an account or a decision that only the maintainer can make.

## 1. Before promoting widely
- [ ] **[you] Licence status of the vendored ASN.1 modules** - see `NOTICE`. The files carry no
      licence header and their redistribution terms are not documented. Decide: confirm the terms of
      the ETSI Forge / ISO sources, or switch to fetching the modules at install time.
- [ ] **[you] Verify the IEEE 1609.2 reader with a real EU secured capture** (known limitation).
- [ ] **[you]** Check BTP ports 2010, 2013, 2019 against ETSI TS 103 248.

## 2. Distribution
- [ ] **[you] PyPI Trusted Publishing:** create the `cits-expert` project on pypi.org, add this
      repository, workflow `release.yml` and environment `pypi` as a trusted publisher, create the
      `pypi` environment in GitHub, then set the repository variable `PUBLISH_PYPI=true`.
      The next release then publishes automatically (`.github/workflows/release.yml`), with signed
      provenance for the wheel, sdist and zipapp.
- [ ] After the first PyPI release, add a PyPI badge to the README and change the install section
      to `pip install "cits-expert[asn1]"`.

## 3. GitHub settings **[you]**
- Enable *Discussions* and *Private vulnerability reporting* (Settings -> Code security).
- Protect `master`: require the `validate` and `standards` checks, no force-push.
- Dependabot is configured (`.github/dependabot.yml`); enable *Dependabot security updates*.
- Repository social preview: use `docs/assets/banner.jpg`.

## 4. Directories
- [ ] **[you]** MCP registry entry and `awesome-mcp-servers` pull request (needs your account). The
      server is started with `python -m cits_validator.mcp.server` or `cits-mcp`; profiles
      `device`/`host`/`ci`.
- [ ] **[you]** Submit to AgentSkills.io-compatible catalogues (the skill lives in `skill/cits-expert`).

## 5. Good first issues (ready to file)
1. *Verify BTP ports 2010/2013/2019 against ETSI TS 103 248* - compare `core/geonet.py:BTP_PORTS`.
2. *Add a real secured EU capture to the tests* - the 1609.2 reader only has hand-built vectors.
3. *Add a `--max-packets` flag to `cits-lint`* - `scan_file(max_packets=)` already exists.
4. *Freeze `PcapHeaderInfo`/`PacketRecord`* - the reader currently fills the header while iterating.
5. *1609.2 signature verification (ECDSA P-256/P-384)* - milestone for 1.6.0.
6. *Document the LISA `LV.XML` schema variants the parser accepts.*

## 6. Announcement drafts
**Short (issue/Discussions/README):**
> C-ITS Expert 1.5.0 - an open toolkit to validate V2X captures (CAM, DENM, MAPEM, SPATEM, SREM, SSEM,
> CPM, VAM): PCAP/PCAPNG link-layer checks, ASN.1 UPER decoding against the vendored ETSI/ISO modules,
> IEEE 1609.2 envelope reading, MAPEM to GeoJSON/KML, GLOSA, and an MCP server for coding agents. It
> runs as a zero-dependency edge zipapp on an RSU.

**Technical hook (blog/forum):** *"Why your MAPEM lanes are 10x too long"* - `node-XY` offsets are
1 cm units with X = East and Y = North; reading them as decimetres with swapped axes is an easy
mistake that no schema check catches. Show the before/after map and the byte-exact test vector.

**Where to post (all need your accounts):** C-Roads and Car 2 Car Communication Consortium channels,
the Wireshark developers list (ITS dissector comparison), r/embedded and the MCP community.
