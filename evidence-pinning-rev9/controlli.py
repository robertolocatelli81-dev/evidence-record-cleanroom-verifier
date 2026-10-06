#!/usr/bin/env python3
"""Positive controls P1-P3 of the PREREG. Each must make the bench report a disagreement (or a drop).
usage: controlli.py CORPUS.json OUT.json"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness   # noqa: E402
import confronto  # noqa: E402


def counts(corpus, h3=True):
    g = {"results": harness.run(corpus, h3=h3)}
    return confronto.compare(corpus, g)


def vec(corpus, vid):
    return next(v for v in corpus["vectors"] if v["id"] == vid)


def main():
    corpus = json.load(open(sys.argv[1], encoding="utf-8"))
    base = counts(corpus)["summary"]
    out = {"base": {k: base[k] for k in ("verdict_agree", "harness_rule_agree", "strict_agree")}}

    # P1 — altered expectation: the named condition of one vector changed; and one computed root changed
    p1 = []
    c = copy.deepcopy(corpus); vec(c, "evi-duplicate-bound-tuple-rejects")["condition"] = "source_count_mismatch"
    s = counts(c)["summary"]; p1.append({"alter": "condition of evi-duplicate-bound-tuple-rejects -> source_count_mismatch",
                                         "harness_rule_disagree": s["disagreements_harness_rule"], "pass": s["disagreements_harness_rule"] == ["evi-duplicate-bound-tuple-rejects"]})
    c = copy.deepcopy(corpus); r = vec(c, "evi-root-odd-promotion")["computed"]; r["root"] = r["root"][:-1] + ("0" if r["root"][-1] != "0" else "1")
    s = counts(c)["summary"]; p1.append({"alter": "computed.root of evi-root-odd-promotion, last hex digit",
                                         "verdict_disagree": s["disagreements_verdict"], "pass": s["disagreements_verdict"] == ["evi-root-odd-promotion"]})
    out["P1"] = p1

    # P2 — H3 off: the number of agreements must go down
    s = counts(corpus, h3=False)["summary"]
    out["P2"] = {"h3_off": {k: s[k] for k in ("verdict_agree", "harness_rule_agree", "strict_agree")},
                 "verdict_disagree": s["disagreements_verdict"],
                 "pass": s["verdict_agree"] < base["verdict_agree"] and s["harness_rule_agree"] < base["harness_rule_agree"]}

    # P3 — one byte of the INPUT of a positive vector altered
    def flip(cc, vid, path, old, new):
        node = vec(cc, vid)["input"]
        for k in path[:-1]:
            node = node[k]
        assert node[path[-1]] == old, (vid, path, node[path[-1]])
        assert len(old) == len(new) and sum(a != b for a, b in zip(old, new)) == 1
        node[path[-1]] = new
    cases = [
        ("evi-root-present-pinned-count-absent-accepted", ["evidence_set", "sources", 0, "url"], "https://example.org/a", "https://example.org/c", True),
        ("evi-pinned-unpinned-same-url-distinct-time-accepted", ["evidence_set", "sources", 1, "retrieved_at"],
         "2026-09-01T12:00:01.000Z", "2026-09-01T12:00:00.000Z", True),
        ("evi-root-order-independent", ["set_2", 0, "url"], "https://example.org/b", "https://example.org/d", True),
        # added 2026-10-06 ~17:49Z, AFTER the freeze, because mutant M15 (verdict rubric on MALFORMED accepting any
        # outcome) survived: a MALFORMED vector whose input no longer violates anything must be caught
        ("evi-duplicate-bound-tuple-rejects", ["sources", 1, "url"], "https://example.org/a", "https://example.org/e", True),
        # expected NOT to be caught: H3 recomputes the root from the altered entry and L5 takes the held digest from
        # the entry itself (content_matches: true) — a limit of the harness, reported as such
        ("evi-step-resolves-affirmatively", ["evidence_set", "sources", 0, "snippet_sha256"],
         "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
         "9ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8", False),
    ]
    p3 = []
    for vid, path, old, new, should_catch in cases:
        c = copy.deepcopy(corpus); flip(c, vid, path, old, new)
        s = counts(c)["summary"]
        caught = vid in s["disagreements_verdict"]
        p3.append({"vector": vid, "path": [str(x) for x in path], "old": old, "new": new, "caught": caught,
                   "expected_caught": should_catch, "other_disagreements": [d for d in s["disagreements_verdict"] if d != vid],
                   "pass": caught == should_catch})
    out["P3"] = p3
    out["all_pass"] = all(x["pass"] for x in p1) and out["P2"]["pass"] and all(x["pass"] for x in p3)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f, sort_keys=True, indent=1, ensure_ascii=True); f.write("\n")
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
