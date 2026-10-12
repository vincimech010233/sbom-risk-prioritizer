use sbom_risk_prioritizer::{Findings, Sbom, prioritize};
use serde_json::{Value, json};
fn inputs() -> (Value, Value) {
    (
        serde_json::from_str(include_str!("../examples/sbom.json")).unwrap(),
        serde_json::from_str(include_str!("../examples/findings.json")).unwrap(),
    )
}
fn go(s: Value, f: Value) -> Result<Value, String> {
    prioritize(
        serde_json::from_value::<Sbom>(s).map_err(|e| e.to_string())?,
        serde_json::from_value::<Findings>(f).map_err(|e| e.to_string())?,
    )
}
#[test]
fn queue() {
    let (s, f) = inputs();
    let r = go(s, f).unwrap();
    assert_eq!(r["queue"][0]["id"], "SYN-UNKNOWN");
    assert_eq!(r["queue"][0]["score_interval"], json!([0., 15.]));
    assert_eq!(r["queue"][1]["score_interval"], json!([14.8, 14.8]));
    assert_eq!(r["unassessed_components"][0]["status"], "NOT_ASSESSED");
    assert!(
        r["queue"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["safe"] == false)
    );
}
#[test]
fn rejection() {
    for kind in 0..6 {
        let (mut s, mut f) = inputs();
        match kind {
            0 => f["synthetic"] = json!(false),
            1 => f["records"][0]["severity"] = json!(11),
            2 => f["records"][0]["component_ref"] = json!("orphan"),
            3 => f["records"][0]["evidence"] = json!([]),
            4 => {
                let dup = s["components"][0].clone();
                s["components"].as_array_mut().unwrap().push(dup)
            }
            _ => f["records"][1]["id"] = f["records"][0]["id"].clone(),
        }
        assert!(go(s, f).is_err());
    }
}
#[test]
fn no_findings_not_safe() {
    let (s, mut f) = inputs();
    f["records"] = json!([]);
    assert_eq!(
        go(s, f).unwrap()["unassessed_components"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
}
#[test]
fn deterministic_permutations() {
    let (s, f) = inputs();
    let a = go(s.clone(), f.clone()).unwrap();
    let mut reverse = f;
    reverse["records"].as_array_mut().unwrap().reverse();
    assert_eq!(a, go(s, reverse).unwrap());
}
#[test]
fn reject_unsupported() {
    let (mut s, f) = inputs();
    s["dependencies"] = json!([]);
    assert!(go(s, f).is_err());
}
