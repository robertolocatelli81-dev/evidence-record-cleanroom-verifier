#!/usr/bin/env python3
"""Comparison runner (PREREG «Metro»). The ONLY place that reads `expect`, `condition` and the values of `computed`.
Written AFTER OUTPUT_grezzi.json was frozen (OUTPUT_grezzi.sha256, 2026-10-06T17:43:13Z).

The `expect` members are prose. Each rubric below is our reading of that prose (LETTURA NOSTRA), quoted beside it.

usage: confronto.py CORPUS.json GREZZI.json OUT.json
Metrics:
  verdict  — the checker's outcome against `expect` (and, for root vectors, the roots against `computed`)
  harness  — the notes' rule: a MALFORMED vector agrees when the checker halts and the named condition is reported
  strict   — a MALFORMED vector agrees only when the reported set == {named condition}
"""
import json
import sys


def rubric(vec, res):
    """Returns (verdict_ok, why)."""
    vid, des, exp = vec["id"], vec["designation"], vec["expect"]
    comp = vec.get("computed", {})
    r = res["result"]
    if res["kind"] == "root":
        if "set_1" in vec["input"]:
            ok_vals = r["root_1"] == comp.get("root_1") and r["root_2"] == comp.get("root_2")
            if exp.startswith("identical") or "stable root" in exp:
                return ok_vals and r["equal"], "identical roots == computed root_1/root_2"
            if "differ" in exp:
                return ok_vals and not r["equal"], "roots differ, each == computed"
        if "normative_root" in comp:   # "evidence_root MUST equal normative_root and MUST NOT equal counter_construction_root"
            return r["root"] == comp["normative_root"] and r["root"] != comp["counter_construction_root"], "== normative, != counter"
        if "root" in comp:            # "root matches promote-not-duplicate"
            return r["root"] == comp["root"], "== computed root"
        raise SystemExit("no rubric for root vector " + vid)
    out, conds, per, tok = r["outcome"], r["conditions"], r["per_item"], r["token"]
    if des == "MALFORMED":            # "halt, malformed …"
        ok = out == "malformed"
        if "not a root mismatch" in exp or "MUST NOT reach leafHash" in exp:
            ok = ok and "root_not_recomputable_from_sources" not in conds
        return ok, "halt, malformed"
    rules = {
        # "accepted; NOT malformed …"
        "evi-fully-pinned-fallback-derives-from-sources-accepted": (out != "malformed", "not malformed"),
        "evi-root-present-pinned-count-absent-accepted": (out != "malformed", "not malformed"),
        "evi-unpinned-members-absent-accepted": (out != "malformed", "not malformed"),
        "evi-declared-partial-is-not-invalid": (out != "malformed", "not malformed; MUST NOT halt"),
        "evi-set-retrieved-at-equals-unpinned-value": (out != "malformed", "well-formed; MUST NOT halt"),
        "evi-empty-root-null": (out != "malformed", "evidence_root null; well-formed"),
        # "accepted; NOT malformed … step resolves unknown (not fully pinned)"
        "evi-pinned-unpinned-same-url-distinct-time-accepted": (out == "unknown" and tok == "unknown", "not malformed; unknown"),
        # "step resolves on the derived values (…fully_pinned=true); MUST NOT halt" — with content_matches: true for
        # both pinned items we read "resolves" as the token `resolved` (LETTURA NOSTRA)
        "evi-resolve-all-counts-absent-accepted": (out == "resolved" and tok == "resolved", "resolved"),
        "evi-step-resolves-affirmatively": (out == "resolved" and tok == "resolved", "resolved, not unknown, not halt"),
        "evi-absent-unknown": (out == "unknown" and tok == "unknown", "unknown; MUST NOT halt"),
        "evi-partial-resolves-unknown": (out == "unknown" and tok == "unknown", "unknown"),
        "evi-content-mismatch-unknown": (out == "unknown" and per == ["content_differs"], "unknown; per-item content_differs"),
        "evi-content-not-held-unknown": (out == "unknown" and per == ["content_not_held"], "unknown; per-item content_not_held"),
        "evi-unpinned-item-reason-content-not-held": (out == "unknown" and per == ["content_not_held"],
                                                      "unknown; per-item content_not_held present for the unpinned entry"),
    }
    if vid not in rules:
        raise SystemExit("no rubric for " + vid)
    return rules[vid]


def compare(corpus, grezzi):
    by_id = {x["id"]: x for x in grezzi["results"]}
    assert len(by_id) == len(corpus["vectors"]) == len(grezzi["results"])
    rows = []
    for vec in corpus["vectors"]:
        res = by_id[vec["id"]]
        vok, why = rubric(vec, res)
        named = vec.get("condition")
        reported = res["result"].get("conditions", []) if res["kind"] == "resolve" else []
        if vec["designation"] == "MALFORMED":
            h_ok = res["result"]["outcome"] == "malformed" and named in reported
            s_ok = res["result"]["outcome"] == "malformed" and reported == [named]
            second = [c for c in reported if c != named]
        else:
            h_ok = s_ok = vok
            second = []
        rows.append({"id": vec["id"], "designation": vec["designation"], "named_condition": named,
                     "reported": reported, "outcome": res["result"].get("outcome"), "verdict_ok": vok,
                     "harness_ok": h_ok, "strict_ok": s_ok, "second_conditions": second, "rubric": why})
    n = len(rows)
    summary = {"vectors": n,
               "verdict_agree": sum(r["verdict_ok"] for r in rows),
               "harness_rule_agree": sum(r["harness_ok"] for r in rows),
               "strict_agree": sum(r["strict_ok"] for r in rows),
               "with_second_condition": [{"id": r["id"], "named": r["named_condition"], "also": r["second_conditions"]}
                                         for r in rows if r["second_conditions"]],
               "disagreements_verdict": [r["id"] for r in rows if not r["verdict_ok"]],
               "disagreements_harness_rule": [r["id"] for r in rows if not r["harness_ok"]]}
    return {"summary": summary, "rows": rows}


if __name__ == "__main__":
    corpus = json.load(open(sys.argv[1], encoding="utf-8"))
    grezzi = json.load(open(sys.argv[2], encoding="utf-8"))
    res = compare(corpus, grezzi)
    with open(sys.argv[3], "w", encoding="utf-8") as f:
        json.dump(res, f, sort_keys=True, indent=1, ensure_ascii=True)
        f.write("\n")
    s = res["summary"]
    print("verdict %d/%d  harness-rule %d/%d  strict %d/%d" % (s["verdict_agree"], s["vectors"], s["harness_rule_agree"],
                                                              s["vectors"], s["strict_agree"], s["vectors"]))
    for w in s["with_second_condition"]:
        print("  second:", w["id"], w["named"], "+", w["also"])
    for d in s["disagreements_verdict"]:
        print("  VERDICT DISAGREE:", d)
    for d in s["disagreements_harness_rule"]:
        print("  HARNESS-RULE DISAGREE:", d)
