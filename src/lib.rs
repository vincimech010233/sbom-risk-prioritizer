use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sbom {
    #[serde(rename = "bomFormat")]
    pub format: String,
    #[serde(rename = "specVersion")]
    pub spec: String,
    pub version: u32,
    pub components: Vec<Component>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    #[serde(rename = "bom-ref")]
    pub reference: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub purl: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: String,
    pub reference: String,
    pub recorded_at: String,
    pub classification: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Findings {
    pub synthetic: bool,
    pub schema_version: u32,
    pub records: Vec<Finding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub component_ref: String,
    pub severity: Option<f64>,
    pub exploitability: String,
    pub exposure: String,
    pub fixed_version: Option<String>,
    pub evidence: Vec<Evidence>,
}
fn nonempty(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control)
}
pub fn prioritize(sbom: Sbom, findings: Findings) -> Result<Value, String> {
    if sbom.format != "CycloneDX"
        || sbom.spec != "1.5"
        || sbom.version != 1
        || !findings.synthetic
        || findings.schema_version != 1
    {
        return Err("restricted CycloneDX 1.5 / synthetic findings v1 profile required".into());
    }
    if sbom.components.len() > 1000 || findings.records.len() > 1000 {
        return Err("profile maximum 1000 components/findings".into());
    }
    let mut refs = BTreeSet::new();
    for c in &sbom.components {
        if !["library", "application"].contains(&c.kind.as_str())
            || !nonempty(&c.reference)
            || !nonempty(&c.name)
            || !nonempty(&c.version)
            || c.purl
                .as_ref()
                .is_some_and(|p| !nonempty(p) || !p.starts_with("pkg:"))
            || !refs.insert(c.reference.clone())
        {
            return Err("invalid or duplicate component".into());
        }
    }
    let mut ids = BTreeSet::new();
    let mut assessed = BTreeSet::new();
    let mut queue = vec![];
    for f in findings.records {
        if !nonempty(&f.id) || !ids.insert(f.id.clone()) || !refs.contains(&f.component_ref) {
            return Err("invalid/duplicate finding id or unknown component ref".into());
        }
        if f.severity
            .is_some_and(|s| !s.is_finite() || !(0.0..=10.0).contains(&s))
            || f.fixed_version.as_ref().is_some_and(|s| !nonempty(s))
        {
            return Err("invalid severity/fixed version".into());
        }
        if f.evidence.is_empty()
            || f.evidence.iter().any(|e| {
                !nonempty(&e.source)
                    || !nonempty(&e.reference)
                    || !nonempty(&e.recorded_at)
                    || ![
                        "VERIFIED",
                        "OBSERVED",
                        "INFERRED",
                        "HYPOTHESIS",
                        "NOT_VERIFIED",
                    ]
                    .contains(&e.classification.as_str())
            })
        {
            return Err("nonempty classified evidence provenance required".into());
        }
        let severity = if let Some(s) = f.severity {
            [s, s]
        } else {
            [0., 10.]
        };
        let exploit = match f.exploitability.as_str() {
            "confirmed" => [3., 3.],
            "suspected" => [1., 1.],
            "none_observed" => [0., 0.],
            "unknown" => [0., 3.],
            _ => return Err("invalid exploitability".into()),
        };
        let exposure = match f.exposure.as_str() {
            "internet" => [2., 2.],
            "internal" => [1., 1.],
            "isolated" => [0., 0.],
            "unknown" => [0., 2.],
            _ => return Err("invalid exposure".into()),
        };
        let uncertain =
            f.severity.is_none() || f.exploitability == "unknown" || f.exposure == "unknown";
        let interval = [
            severity[0] + exploit[0] + exposure[0],
            severity[1] + exploit[1] + exposure[1],
        ];
        assessed.insert(f.component_ref.clone());
        queue.push(json!({"id":f.id,"component_ref":f.component_ref,"score_interval":interval,"classification":"INFERRED","uncertainty":if uncertain{"missing context"}else{"input assertions only; no runtime verification"},"action":if uncertain{"resolve missing evidence with owner"}else if f.fixed_version.is_some(){"review supplied patch version and test upgrade"}else{"ask owner for remediation options"},"severity":f.severity,"exploitability":f.exploitability,"exposure":f.exposure,"fixed_version":f.fixed_version,"evidence":f.evidence,"safe":false}));
    }
    queue.sort_by(|a, b| {
        b["score_interval"][1]
            .as_f64()
            .unwrap()
            .total_cmp(&a["score_interval"][1].as_f64().unwrap())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    let unassessed: Vec<_> = refs
        .difference(&assessed)
        .map(|r| json!({"component_ref":r,"status":"NOT_ASSESSED","safe":false}))
        .collect();
    Ok(
        json!({"profile":"cyclonedx-1.5-flat-v1","synthetic":true,"classification":"INFERRED","policy":"sort descending by upper score bound, then id; severity 0..10 + exploitability 0..3 + exposure 0..2. Heuristic score, not probability. Unknown creates a range; no finding is suppressed.","queue":queue,"unassessed_components":unassessed}),
    )
}
