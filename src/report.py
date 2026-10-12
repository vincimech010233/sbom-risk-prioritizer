"""Render an existing offline prioritization report; never fetch advisories."""

import json
import sys
import html
from pathlib import Path


def escape(value):
    return (
        html.escape(str(value))
        .replace("`", "&#96;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("\n", " ")
    )


def render(r):
    if r.get("synthetic") is not True or r.get("profile") != "cyclonedx-1.5-flat-v1":
        raise ValueError("unsupported report")
    lines = [
        "# SBOM remediation review queue",
        "",
        "INFERRED heuristic priority; all data synthetic. No safe or suppression decision.",
        "",
        escape(r["policy"]),
        "",
    ]
    for i, f in enumerate(r["queue"], 1):
        lines += [
            f"{i}. **{escape(f['id'])}** `{escape(f['component_ref'])}` — score range {escape(f['score_interval'])}; {escape(f['action'])}.",
            f"   Context: {escape(f['uncertainty'])}; provenance: "
            + ", ".join(escape(e["reference"]) for e in f["evidence"]),
        ]
    lines += [
        "",
        "Unassessed components (unknown, not safe): "
        + ", ".join(escape(x["component_ref"]) for x in r["unassessed_components"]),
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    try:
        p = Path(sys.argv[1])
        if p.stat().st_size > 2_000_000:
            raise ValueError("report exceeds 2 MB")
        Path(sys.argv[2]).write_text(render(json.loads(p.read_text())))
    except (ValueError, OSError, KeyError, IndexError, TypeError) as e:
        print(e, file=sys.stderr)
        sys.exit(2)
