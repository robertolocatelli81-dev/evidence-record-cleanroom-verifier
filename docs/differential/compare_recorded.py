#!/usr/bin/env python3
"""compare_recorded.py — out-of-suite differential: run ONLY this repository's verifier on the generated
variants and compare with the upstream verifier's RECORDED stdout on the same bytes (an output file; the
upstream code is never read here). Every number quoted in the README comes from the JSON this writes.

Recorded-output line format expected (one per variant):
    [PASS|FAIL] <file> -> valid|reject|malformed[/<reason>]  (<detail>)

Usage: python3 compare_recorded.py <variants_dir> [<recorded_stdout.txt>] <spec_dir> <out.json>
  <variants_dir>          holds MANIFEST.json + vectors/ as written by generate_variants.py
  <recorded_stdout.txt>   optional; default = upstream_stdout_0eda3038.txt next to this script (the recording
                          redistributed in this folder, see README.md for how it was produced)
  <spec_dir>              the 69 source vectors (to tell whether a variant touches `input`)
Paths written into the JSON are basenames only (no machine-specific paths).
"""
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
import verify_tersign as V  # noqa: E402

_LINE = re.compile(r"^\s*\[(PASS|FAIL)\]\s+(\S+)\s+->\s+(valid|reject|malformed)(?:/([a-z_]+))?\s*(?:\((.*)\))?\s*$")


def sha256_file(p):
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def parse_recorded(path):
    out, unparsed = {}, []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            m = _LINE.match(line)
            if not m:
                unparsed.append(line.rstrip("\n")[:120])
                continue
            out[m.group(2)] = {"verdict": m.group(3), "reason": m.group(4), "detail": m.group(5)}
    return out, unparsed


def main(argv):
    if len(argv) == 3:
        var_dir, spec_dir, out_path = argv
        rec_path = os.path.join(HERE, "upstream_stdout_0eda3038.txt")
    else:
        var_dir, rec_path, spec_dir, out_path = argv[:4]
    man_path = os.path.join(var_dir, "MANIFEST.json")
    with open(man_path, "r", encoding="utf-8") as fh:
        manifest = V.load_json(fh.read())
    recorded, unparsed = parse_recorded(rec_path)
    sources = {}
    for f in os.listdir(os.path.join(spec_dir, "vectors")):
        with open(os.path.join(spec_dir, "vectors", f), "r", encoding="utf-8") as fh:
            sources[f] = V.load_json(fh.read())
    rows = []
    for entry in manifest["vectors"]:
        f = entry["file"]
        src_name = f.split("-", 1)[1]
        path = os.path.join(var_dir, "vectors", f)
        verdict, reason, detail = V.verify_file(path, entry.get("kind"))
        try:
            with open(path, "r", encoding="utf-8") as fh:
                mut = V.load_json(fh.read())
            touches_input = mut.get("input") != sources[src_name].get("input")
        except Exception:
            touches_input = True
        t = recorded.get(f)
        ours_accept = verdict == "valid"
        if t is None:
            cls, agree = "recorded_missing", None
        else:
            agree = ours_accept == (t["verdict"] == "valid")
            if agree:
                if t["verdict"] == "malformed":
                    cls = "agree_nonaccept_upstream_malformed"
                elif t["verdict"] == "reject" and t["reason"] != reason:
                    cls = "agree_verdict_reason_differs"
                else:
                    cls = "agree"
            elif t["verdict"] == "valid":
                cls = "A_upstream_valid_ours_reject"
            elif t["verdict"] == "malformed":
                cls = "B_upstream_malformed_ours_valid"
            else:
                cls = "A2_upstream_reject_ours_valid"
        rows.append({"file": f, "source": src_name, "kind": entry.get("kind"), "touches_input": touches_input,
                     "ours": verdict, "ours_reason": reason, "ours_detail": detail,
                     "upstream": t["verdict"] if t else None, "upstream_reason": t["reason"] if t else None,
                     "upstream_detail": t["detail"] if t else None, "agree_accept": agree, "class": cls})

    def count(rs):
        nonmal = [r for r in rs if r["upstream"] in ("valid", "reject")]
        classes = {}
        for r in rs:
            classes[r["class"]] = classes.get(r["class"], 0) + 1
        return {"n": len(rs), "agree_accept_nonaccept": sum(1 for r in rs if r["agree_accept"]),
                "non_malformed": len(nonmal),
                "agree_verdict_and_reason_on_non_malformed": sum(1 for r in nonmal if r["agree_accept"] and (r["upstream"] != "reject" or r["upstream_reason"] == r["ours_reason"])),
                "classes": classes,
                "upstream_verdicts": {k: sum(1 for r in rs if r["upstream"] == k) for k in ("valid", "reject", "malformed")},
                "ours_verdicts": {k: sum(1 for r in rs if r["ours"] == k) for k in ("valid", "reject")}}

    res = {"run_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"),
           "python": sys.version.split()[0],
           "inputs": {"variants_MANIFEST.json": sha256_file(man_path), "recorded_output": {"file": os.path.basename(rec_path), "sha256": sha256_file(rec_path)},
                      "verify_tersign.py": sha256_file(os.path.join(HERE, "..", "..", "verify_tersign.py")),
                      "spec_MANIFEST.json": sha256_file(os.path.join(spec_dir, "MANIFEST.json"))},
           "recorded_lines_parsed": len(recorded), "recorded_lines_unparsed": unparsed,
           "all": count(rows), "touching_input": count([r for r in rows if r["touches_input"]]),
           "not_touching_input": count([r for r in rows if not r["touches_input"]]),
           "disagreements": [r for r in rows if not r["agree_accept"]], "rows": rows}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    print(f"run_at {res['run_at']}  python {res['python']}")
    for k, v in res["inputs"].items():
        print(f"  sha256 {k}: {v}")
    print(f"recorded lines parsed {len(recorded)} (unparsed {len(unparsed)}: {[u[:60] for u in unparsed]})")
    for label in ("all", "touching_input", "not_touching_input"):
        c = res[label]
        print(f"[{label}] n={c['n']}  accept/non-accept agree {c['agree_accept_nonaccept']}/{c['n']}  "
              f"verdict+reason agree {c['agree_verdict_and_reason_on_non_malformed']}/{c['non_malformed']} (non-malformed)  "
              f"classes {c['classes']}  upstream {c['upstream_verdicts']}  ours {c['ours_verdicts']}")
    print(f"disagreements ({len(res['disagreements'])}):")
    for r in res["disagreements"]:
        print(f"  {r['class']:<34} {r['file']:<52} touches_input={r['touches_input']}  upstream={r['upstream']}/{r['upstream_reason']} ({(r['upstream_detail'] or '')[:60]})  ours={r['ours']}/{r['ours_reason']} ({r['ours_detail'][:60]})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
