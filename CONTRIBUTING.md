# Contributing to C-ITS Expert

Thank you for your interest in contributing to **C-ITS Expert**! We welcome contributions that expand V2X standards coverage, improve packet dissection accuracy, or enhance AI coding agent tooling.

---

## The Non-Negotiable Rule: Zero Data Hallucination

All contributions MUST strictly uphold the **C-ITS Iron Law**:
```
NEVER SYNTHESIZE OR INVENT PROTOCOL DATA
```
- **No Synthetic Trajectories:** Never generate fake GNSS sine curves or speed profiles. If field data is missing, return `None` or `null`.
- **No Modulo Phases:** Signal groups must always be resolved through MAPEM `connectsTo[].signalGroup`.
- **No Static Cycles:** Never inject hardcoded 90-second cycle loops.
- **Mandatory Real-PCAP Verification:** Every PR modifying link-layer or dissection logic must include or pass verification against real field captures (DLT 127 Radiotap, nanosecond PCAPs).

---

## Development Workflow

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/Nemeson/C-ITS-Expert.git
   cd C-ITS-Expert
   ```
2. **Environment Setup:**
   Ensure Python 3.11+ is installed.
   ```bash
   pip install -e ".[dev]"
   ```
3. **Run Linting & Tests:**
   ```bash
   ruff check .
   pytest -v
   ```
4. **Token Efficiency:**
   If modifying `skill/cits-expert/SKILL.md`, the total word count MUST remain under **450 words** to guarantee rapid loading by LLM agents.

---

## Pull Request Guidelines

- Ensure all 49+ tests pass before submitting.
- Provide a clear explanation of which C-ITS standard or physical hardware phenomenon the change addresses.
- Reference relevant ETSI (e.g. EN 302 637-2/3, TS 103 900/831) or ISO (e.g. TS 19091) specifications.
