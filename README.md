# SBOM Risk Prioritizer

Security triage teams need a review queue that preserves missing context. This offline Rust tool reads a restricted flat CycloneDX JSON inventory and synthetic vulnerability assertions, joins by exact bom-ref, and ranks a transparent severity/exploitability/exposure score interval. Python renders an escaped Markdown queue. All components without records remain NOT_ASSESSED; no zero score or absent finding means safe.

## Requirements, profile and usage

Rust/Cargo and Python 3.12; Python standard library only. Flat CycloneDX 1.5 JSON v1 components with type library/application, bom-ref, name, version and optional purl. No nested inventory, dependencies, XML, metadata, vulnerability matching or full standard validation. Findings v1 must be synthetic and include classified provenance. CLI requires an explicit fixture gate.

```sh
cargo test --locked
cargo run --locked -- --synthetic examples/sbom.json examples/findings.json results/report.json
python3 src/report.py results/report.json results/report.md
python3 -m unittest discover -s tests -v
```

Expected queue: SYN-UNKNOWN range [0,15], SYN-CRITICAL [14.8,14.8], SYN-LOW [2,2]; unassessed-lib remains unknown. Upper-bound ranking deliberately escalates uncertainty for analyst review. The score is a configurable-in-code heuristic, not risk probability, CVSS replacement or calibrated decision model.

## Business value, limitations and boundaries

Exact inventory joins, original evidence references, deterministic tie breaking and a visible uncertainty queue help explain triage decisions. Evidence assertions are supplied, not verified by this tool; recorded_at is retained as provenance text and does not establish freshness. No real scanning, remote advisory queries, personal information, exploit generation, auto-suppression or automatic remediation. Maximum 1000 components/findings and 2 MB per input. Public-tool and advisory comparisons are documented in docs/RESEARCH.md.

## Verification and publication

Evidence labels: VERIFIED = checked against a stated criterion; OBSERVED = measured execution; INFERRED = interpretation; HYPOTHESIS = proposed explanation; NOT_VERIFIED = missing evidence. Local status and executed commands are in `results/validation.json` and `docs/REVIEW.md`. Synthetic validation establishes implementation behavior, not production accuracy.

This is an independent Git repository with original MIT project code. Publication-gate evidence is in `results/publication-gate-20261012.json` and `docs/PUBLICATION_REVIEW.md`. The original local-delivery records are retained as historical evidence. CI uses public dependency registries and requires no secrets. See `docs/PROVENANCE.md` for dependency and advisory review scope.

## License

MIT; see LICENSE.

## Reproducing development checks

Optional public-registry dependency review: `python3 tools/dependency_audit.py .` writes `results/dependency-audit.json`. This developer check uses the free OSV API and is separate from offline application execution. Zero listed advisories does not prove absence of vulnerabilities. License evidence is in results/licenses.json and, for scientific projects, results/python-licenses.json.

Install `requirements-dev.txt` to run the recorded Ruff 0.17.0 source checks. Commands, actual versions, failed attempts, review corrections and measured peak RSS are retained in results/validation.json, results/tool-versions.json and docs/REVIEW.md. Check the GitHub Actions run for the exact commit before claiming hosted CI success; older local-delivery records retain their as-of NOT_VERIFIED status.
