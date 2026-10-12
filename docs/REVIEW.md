# Critical review — SBOM Risk Prioritizer

Reviewer: separate same-model agent, not an independent model or external audit. Scope: authorized offline synthetic inventory joins and prioritization, accepted input gates, deterministic evidence reports and local checks. No third-party scanning, exploitation or vulnerability discovery.

VERIFIED: **VALIDATED_LOCAL** for `docs/ACCEPTANCE.md`. Required local checks passed and no critical defect remains within the narrow synthetic profile. Manual publication still requires the developer's final repository/privacy/artifact check. Hosted CI and full CycloneDX compliance are NOT_VERIFIED.

## Independent checks and critique

OBSERVED: `timeout 90 cargo test --locked --jobs 2` passed five Rust tests, `cargo fmt --check` and `cargo clippy --locked -- -D warnings` passed, and `python3 -m unittest discover -s tests -v` passed two report tests. These cover fixture intervals, unknown status, rejected refs/severity/provenance, deterministic ordering and HTML escaping.

OBSERVED: five extra CLI cases completed within individual 3-second limits. Baseline and reversed component/finding orders produced identical JSON; non-synthetic wrapper, invalid provenance classification and unsupported finding field exited 2 with no fresh report. Omission of `--synthetic` also exited 2. Evidence is preserved in `results/reviewer-fixtures/observations.json` and `retest-observations.json`.

The standalone renderer initially warranted attention because reports can be supplied separately from the Rust generator. Developer proactively applied escaping to policy and score interval in addition to identifiers, references and action text. VERIFIED: crafted benign HTML in policy and score values no longer appears literally in rendered Markdown; saved probe and retest artifacts remain. Arbitrary third-party Markdown-engine behavior is NOT_VERIFIED.

VERIFIED by inspection: exact bom-ref membership joins do not use fuzzy package matching; duplicate component refs and finding IDs reject; no findings are removed because of low severity or missing context. The fixture explicitly yields [0,15], [14.8,14.8] and [2,2]. Unassessed components retain NOT_ASSESSED; supplied provenance is copied to JSON without being promoted to tool-verified facts. Unknown severity/exploitability/exposure widen the interval. Score ties use finding IDs, and reference order uses sorted sets.

## Interpretation, security and limitations

INFERRED: explainable triage ordering offers credible portfolio value, especially the visible missing-context review action. Ranking the upper bound deliberately puts unknown context ahead of a high known score; this is an explicit conservative policy choice, not a calibrated risk estimate. A provided `none_observed` exploitability assertion contributes zero under this heuristic but does not establish absence of exploitation. Safe flags remain false and no suppression or remediation is automatic.

VERIFIED by inspection: no runtime network calls, real infrastructure targeting, secrets or personal datasets are required. Scope is explicit in `docs/SCOPE.md`, a CLI flag and synthetic wrapper marker. The marker is a user assertion, not a detector proving data origin. Bounds are 2 MB/file and 1000 records/components. Recorded timestamps are opaque provenance text; freshness and chronology are NOT_VERIFIED. The purl check is only a restricted prefix/length check, not full package-URL validation. Markdown is a summary; complete evidence metadata stays in JSON.

OBSERVED: research acknowledges existing Dependency-Track and Grype capabilities and records primary issue/PR/advisory/fix/changelog and acknowledgement sources with root-cause distinctions. No new vulnerability or novelty finding is claimed. This reviewer inspected the research record, not every remote linked history. Original authorship beyond supplied development/provenance records is NOT_VERIFIED.

OBSERVED: MIT project license, locked dependencies, dependency license metadata and OSV queries are present. Zero returned advisories is bounded database evidence, not absence-of-vulnerability proof; exhaustive legal review and supply-chain authenticity remain NOT_VERIFIED. CI configuration runs deterministic Rust/Python checks against local fixtures and needs no credentials.

Follow-up: keep the upper-bound policy, assertion status and timestamp limits explicit; improve component-name/version visibility in reports if the tool expands beyond exact-ref fixture demonstrations. No production prioritization accuracy or complete standard support is accepted.
