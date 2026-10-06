#!/usr/bin/env python3
"""Step 6: mutation test of harness / comparison runner / checker on the rev-9 pipeline.
A mutant is KILLED when, against the unmutated baseline, any of these changes: the per-vector RESULTS (not the echoed
input), the three counts or the second-condition list, the positive controls' all_pass, the exit status of
selftest_filed.py, or the pipeline crashes.
usage: mutanti.py CORPUS.json WORKDIR OUT.json"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("harness.py", "confronto.py", "controlli.py", "es_check_filed.py", "selftest_filed.py")
MUTANTS = [
    ("M01 H1 off", "harness.py", 'es["evidence_set_version"] = C.VERSION; log.append("H1")', 'log.append("H1")'),
    ("M02 H2 entry not in a list", "harness.py", 'es = {"sources": [inp["entry"]]}', 'es = {"sources": inp["entry"]}'),
    ("M03 H4 off", "harness.py", 'es["retrieved_at"] = inp["set_retrieved_at"]; log.append("H4")', 'log.append("H4")'),
    ("M04 H3 overwrites a carried root", "harness.py", 'and "evidence_root" not in es and not about_root', 'and not about_root'),
    ("M05 H3 injects null when not computable", "harness.py", 'log.append("H3:not_computable")', 'es["evidence_root"] = None; log.append("H3:not_computable")'),
    ("M06 L3 drops the pinned-is-boolean guard", "harness.py", 'if not all(isinstance(e.get("pinned"), bool) for e in sources):\n        return None', 'pass'),
    ("M07 L3 drops the string-members guard", "harness.py", 'if not all(isinstance(e.get(k), str) for e in pinned for k in ("url", "snippet_sha256", "content_kind", "retrieved_at")):\n        return None', 'pass'),
    ("M08 L5 content_matches ignored", "harness.py", 'elif inp.get("content_matches") is True:', 'elif False:'),
    ("M09 L5 recomputed digest ignored", "harness.py", 'if "verifier_recomputed_sha256" in inp:', 'if False:'),
    ("M10 L4 root over all entries, not pinned only", "harness.py", 'return C.evidence_root([e for e in entries if e.get("pinned") is True])', 'return C.evidence_root(list(entries))'),
    ("M11 harness rule = first reported only", "confronto.py", 'h_ok = res["result"]["outcome"] == "malformed" and named in reported', 'h_ok = res["result"]["outcome"] == "malformed" and reported[:1] == [named]'),
    ("M12 strict = superset", "confronto.py", 's_ok = res["result"]["outcome"] == "malformed" and reported == [named]', 's_ok = res["result"]["outcome"] == "malformed" and named in reported'),
    ("M13 rubric 'differ' ignores equality", "confronto.py", 'return ok_vals and not r["equal"], "roots differ, each == computed"', 'return ok_vals, "roots differ, each == computed"'),
    ("M14 rubric drops the 'not a root mismatch' clause", "confronto.py", 'ok = ok and "root_not_recomputable_from_sources" not in conds', 'pass'),
    ("M15 rubric MALFORMED accepts any outcome", "confronto.py", 'ok = out == "malformed"\n', 'ok = True\n'),
    ("M16 checker held_sha256 compare inverted", "es_check_filed.py", 'per.append("content_matches" if held_sha256[i] == e["snippet_sha256"] else "content_differs")', 'per.append("content_matches" if held_sha256[i] != e["snippet_sha256"] else "content_differs")'),
    ("M17 checker present_when_unpinned suppressed by hex failure", "es_check_filed.py", '            elif snip is not None:\n                conds.add("snippet_sha256_present_when_unpinned")', '            elif snip is not None and "snippet_sha256" not in failed:\n                conds.add("snippet_sha256_present_when_unpinned")'),
    ("M18 checker odd node duplicated", "es_check_filed.py", 'nxt.append(level[-1])', 'nxt.append(hashlib.sha256(b"ao-evidence-node-v1\\x00" + level[-1] + b"\\x00" + level[-1]).digest())'),
    ("M19 checker set retrieved_at over pinned only", "es_check_filed.py", 'least = min(e["retrieved_at"].encode() for e in sources)', 'least = min(e["retrieved_at"].encode() for e in sources if e.get("pinned") is True)'),
    ("M20 checker duplicates over pinned only", "es_check_filed.py", '                if any(_same_retrieval(sources[i], sources[j]) for j in range(i + 1, n)):', '                if sources[i].get("pinned") and any(sources[j].get("pinned") and _same_retrieval(sources[i], sources[j]) for j in range(i + 1, n)):'),
]


def pipeline(work, corpus):
    py = sys.executable
    r1 = subprocess.run([py, "-B", "harness.py", corpus, "g.json"], cwd=work, capture_output=True, text=True)
    if r1.returncode:
        return {"crash": "harness: " + r1.stderr.strip().splitlines()[-1]}
    r2 = subprocess.run([py, "-B", "confronto.py", corpus, "g.json", "c.json"], cwd=work, capture_output=True, text=True)
    if r2.returncode:
        return {"crash": "confronto: " + r2.stderr.strip().splitlines()[-1]}
    r3 = subprocess.run([py, "-B", "controlli.py", corpus, "k.json"], cwd=work, capture_output=True, text=True)
    k = json.load(open(os.path.join(work, "k.json"))) if r3.returncode == 0 else {"all_pass": "crash"}
    r4 = subprocess.run([py, "-B", "selftest_filed.py"], cwd=work, capture_output=True, text=True)
    g = json.load(open(os.path.join(work, "g.json")))
    c = json.load(open(os.path.join(work, "c.json")))
    s = c["summary"]
    return {"results": [(x["id"], x["result"]) for x in g["results"]],
            "counts": [s["verdict_agree"], s["harness_rule_agree"], s["strict_agree"]],
            "second": s["with_second_condition"], "controls": k.get("all_pass"), "selftest": r4.returncode == 0}


def main():
    corpus, work, outp = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3]
    def fresh():
        shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
        for f in FILES:
            shutil.copy(os.path.join(HERE, f), work)
    fresh(); base = pipeline(work, corpus)
    assert "crash" not in base and base["controls"] is True and base["selftest"] is True
    rows = []
    for name, f, old, new in MUTANTS:
        fresh()
        p = os.path.join(work, f); src = open(p).read()
        assert src.count(old) == 1, (name, src.count(old))
        open(p, "w").write(src.replace(old, new))
        m = pipeline(work, corpus)
        if "crash" in m:
            killed, how = True, m["crash"]
        else:
            diffs = [k for k in ("results", "counts", "second", "controls", "selftest") if m[k] != base[k]]
            killed, how = bool(diffs), ",".join(diffs) + (" counts=%s" % m["counts"] if "counts" in diffs else "")
        rows.append({"mutant": name, "file": f, "killed": killed, "how": how})
        print(("KILLED " if killed else "ALIVE  ") + name + "  " + how)
    print("killed %d/%d" % (sum(r["killed"] for r in rows), len(rows)))
    json.dump({"baseline_counts": base["counts"], "rows": rows}, open(outp, "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
