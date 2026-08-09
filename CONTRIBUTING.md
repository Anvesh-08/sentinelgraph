# Contributing to SentinelGraph (`CONTRIBUTING.md`)

---

## 1. Engineering Philosophy
SentinelGraph follows strict domain-driven engineering practices designed for mission-critical compliance software:
- **Explainability First:** Every AML typology detector and risk score calculation must produce human-readable evidence metrics that an L1/L2 investigator or regulatory examiner can verify.
- **Deterministic Behavior:** All rules, graph traversals, and simulations must behave deterministically given the same input dataset and random seed.
- **Zero External Secret Dependencies:** Never commit API keys, tokens, `.env` files, or real customer PII.

---

## 2. Branching & Pull Request Workflow
1. Create a descriptive feature or fix branch from `main`:
   - `feat/typology-engine-family-a`
   - `feat/graph-tarjan-scc-cycles`
   - `feat/ruleforge-shadow-simulation`
   - `fix/case-four-eyes-validation`
2. Write comprehensive unit and integration tests covering happy paths, boundary thresholds (e.g., $9,999.99 vs. $10,000.00), and unauthorized access attempts.
3. Run the full verification suite in PowerShell or Bash:
   ```powershell
   python -m unittest discover -s tests -p "test_*.py" -v
   ```
4. Ensure all audit chain checks and schema migrations pass cleanly before merging into `main`.

---

## 3. Coding Standards
- **Python 3.11+** with full type annotations (`typing`, `dataclasses`, `pydantic`).
- Clear docstrings on every domain class, typology detector, graph algorithm, and API endpoint explaining the financial crime rationale and algorithmic complexity.
