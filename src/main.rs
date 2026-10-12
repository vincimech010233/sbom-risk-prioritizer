use sbom_risk_prioritizer::{Findings, Sbom, prioritize};
fn read<T: serde::de::DeserializeOwned>(p: &str) -> Result<T, String> {
    if std::fs::metadata(p).map_err(|e| e.to_string())?.len() > 2_000_000 {
        return Err("input exceeds 2 MB".into());
    }
    serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
fn run() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 5 || a[1] != "--synthetic" {
        return Err("usage: sbom-risk-prioritizer --synthetic SBOM FINDINGS REPORT_JSON".into());
    }
    let report = prioritize(read::<Sbom>(&a[2])?, read::<Findings>(&a[3])?)?;
    std::fs::write(&a[4], serde_json::to_string_pretty(&report).unwrap()).map_err(|e| e.to_string())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
