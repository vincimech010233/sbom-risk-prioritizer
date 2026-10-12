import sys
import unittest
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from report import render


class ReportTests(unittest.TestCase):
    def test_expected_queue(self):
        r = json.loads(Path("results/report.json").read_text())
        self.assertEqual(
            [f["id"] for f in r["queue"]], ["SYN-UNKNOWN", "SYN-CRITICAL", "SYN-LOW"]
        )
        self.assertIn("unknown, not safe", render(r))
        self.assertIn("fixture:SYN-UNKNOWN", render(r))

    def test_html_escape(self):
        r = json.loads(Path("results/report.json").read_text())
        r["queue"][0]["id"] = "<script>x</script>"
        self.assertNotIn("<script>", render(r))


if __name__ == "__main__":
    unittest.main()
