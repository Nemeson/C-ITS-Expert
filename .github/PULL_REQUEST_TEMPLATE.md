## 📋 Pull Request Description

### Summary of Changes
<!-- Describe the changes proposed in this PR -->

### Relevant C-ITS Standards & Invariants
- [ ] ETSI EN 302 637-2 / TS 103 900 (CAM)
- [ ] ETSI EN 302 637-3 / TS 103 831 (DENM)
- [ ] ISO TS 19091 / ETSI TS 103 301 (MAPEM / SPATEM / SREM / SSEM)
- [ ] IEEE 802.11p / DLT 127 Radiotap
- [ ] Other:

### Checklist
- [ ] **Iron Law Verified:** No synthetic/fake data generation introduced.
- [ ] **Tests Passing:** `pytest -v` runs clean across all test suites.
- [ ] **Lint Clean:** `ruff check .` passes without errors.
- [ ] **Word Count Bound:** If modifying `SKILL.md`, total word count remains $< 450$ words.
- [ ] **Real Fixtures:** Any new protocol decoder tested against real field captures.
