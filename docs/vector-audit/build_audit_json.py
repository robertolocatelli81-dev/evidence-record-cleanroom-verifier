#!/usr/bin/env python3
"""build_audit_json.py — derive audit_69.json (machine-readable) from the table in AUDIT_69.md, and cross-check
its Q2 column against measures_q2q4.json (the measured ablation flips). Exit 1 on any mismatch."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    text = open(os.path.join(HERE, "AUDIT_69.md"), encoding="utf-8").read()
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\| (\d+) \| ([pn]\d+-[a-z0-9-]+) \| (\w+) \| ([^|]+) \| (.*) \| (.*) \| (.*) \| (.*) \| \*\*(CORRECT|DOUBTFUL|WRONG)(.*)\*\* \|$", line)
        if not m:
            continue
        n, file, kind, expect, q1, q2, q3, q4, outcome, clause = m.groups()
        q1v = "YES" if "**YES**" in q1 else ("AMBIGUOUS" if "**AMBIGUOUS**" in q1 else "NO")
        cls = re.search(r"\[([^\]]+)\]", q1)
        flips = re.match(r"n=(\d+)", q2.strip())
        rows.append({"n": int(n), "file": file + ".json", "kind": kind, "expect": expect.strip(), "q1": q1v,
                     "q1_source_class": cls.group(1) if cls else None, "q1_basis": q1, "q2": q2.strip(),
                     "q2_n_flips": int(flips.group(1)) if flips else None, "q3": q3.strip(), "q4": q4.strip(),
                     "outcome": outcome, "clause": clause.strip(" —")})
    assert len(rows) == 69, len(rows)
    meas = json.load(open(os.path.join(HERE, "measures_q2q4.json"), encoding="utf-8"))
    bad = []
    for r in rows:
        mv = meas["vectors"][r["file"]]
        if r["q2_n_flips"] != len(mv["flips"]):
            bad.append((r["file"], r["q2_n_flips"], len(mv["flips"])))
    counts = {"outcome": {k: sum(1 for r in rows if r["outcome"] == k) for k in ("CORRECT", "DOUBTFUL", "WRONG")},
              "q1": {k: sum(1 for r in rows if r["q1"] == k) for k in ("YES", "AMBIGUOUS", "NO")},
              "q1_yes_draft_pr2853_only": sum(1 for r in rows if r["q1_source_class"] == "draft-PR2853-only"),
              "q2_isolated_1": sum(1 for r in rows if r["q2_n_flips"] == 1),
              "q2_overdetermined_gt1": sum(1 for r in rows if (r["q2_n_flips"] or 0) > 1),
              "q2_unpinned_0": sum(1 for r in rows if r["q2_n_flips"] == 0),
              "denominator": 69}
    out = {"suite": "evidence-record-conformance 0.5.3 @0eda3038", "manifest_sha256": meas["header"]["manifest_sha256"],
           "verifier_sha256_at_measurement": meas["header"]["verifier_sha256"], "measured_at": meas["header"]["started"],
           "counts": counts, "q2_cross_check_mismatches": bad, "vectors": rows}
    with open(os.path.join(HERE, "audit_69.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    print(json.dumps(counts, indent=1))
    print("Q2 cross-check mismatches:", bad or "none")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
