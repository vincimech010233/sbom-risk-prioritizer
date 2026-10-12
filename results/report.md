# SBOM remediation review queue

INFERRED heuristic priority; all data synthetic. No safe or suppression decision.

sort descending by upper score bound, then id; severity 0..10 + exploitability 0..3 + exposure 0..2. Heuristic score, not probability. Unknown creates a range; no finding is suppressed.

1. **SYN-UNKNOWN** `unknown-lib` — score range &#91;0.0, 15.0&#93;; resolve missing evidence with owner.
   Context: missing context; provenance: fixture:SYN-UNKNOWN
2. **SYN-CRITICAL** `critical-lib` — score range &#91;14.8, 14.8&#93;; review supplied patch version and test upgrade.
   Context: input assertions only; no runtime verification; provenance: fixture:SYN-CRITICAL
3. **SYN-LOW** `low-lib` — score range &#91;2.0, 2.0&#93;; ask owner for remediation options.
   Context: input assertions only; no runtime verification; provenance: fixture:SYN-LOW

Unassessed components (unknown, not safe): unassessed-lib
