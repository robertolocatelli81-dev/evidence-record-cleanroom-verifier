#!/usr/bin/env python3
"""Harness H1-H4 for the rev-9 evidence-pinning corpus, readings in records/HARNESS_LETTURE.md (L1-L8).

Produces the checker's RAW output per vector. It never reads a vector's `expect`, `condition`, `designation`,
`contributed_checker_result`, or the VALUES of `computed` (only whether `computed` is present).

usage: harness.py CORPUS.json OUT.json [--no-h3] [--root-reading=id]
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import es_check_filed as C  # noqa: E402

FORBIDDEN = ("expect", "condition", "designation", "contributed_checker_result")


def _root_computable(sources):
    """L3."""
    if not isinstance(sources, list) or not all(isinstance(e, dict) for e in sources):
        return None
    if not all(isinstance(e.get("pinned"), bool) for e in sources):
        return None
    pinned = [e for e in sources if e["pinned"] is True]
    if not pinned:
        return None
    if not all(isinstance(e.get(k), str) for e in pinned for k in ("url", "snippet_sha256", "content_kind", "retrieved_at")):
        return None
    return C.evidence_root(pinned)


def _pinned_root(entries):
    return C.evidence_root([e for e in entries if e.get("pinned") is True])


def build(vec, h3=True, root_reading="computability"):
    """Returns ("root", {...}) for root-only vectors (L4) or ("resolve", payload, held_sha256, harness_log)."""
    inp = copy.deepcopy(vec["input"])
    has_computed = "computed" in vec
    log = []
    # L4: root-only vectors — input carries no evidence_set and the vector carries `computed`
    if isinstance(inp, list):
        return ("root", {"root": _pinned_root(inp)})
    if has_computed and "evidence_set" not in inp:
        if "set_1" in inp:
            r1, r2 = _pinned_root(inp["set_1"]), _pinned_root(inp["set_2"])
            return ("root", {"root_1": r1, "root_2": r2, "equal": r1 == r2})
        if "sources" in inp:
            return ("root", {"root": _pinned_root(inp["sources"])})
        if "entry" in inp:
            return ("root", {"root": _pinned_root([inp["entry"]])})
        raise SystemExit("unclassified root vector " + vec["id"])
    # L6: no evidence_set member
    if "receipt_shape" in inp:
        return ("resolve", {}, {}, ["L6:no_evidence_set"])
    # H2 / L1
    if "evidence_set" in inp:
        es = inp["evidence_set"]
    elif "entry" in inp:
        es = {"sources": [inp["entry"]]}; log.append("H2:entry")
    elif "sources" in inp:
        es = {"sources": inp["sources"]}; log.append("H2:sources")
    else:
        raise SystemExit("unclassified vector " + vec["id"])
    # H4
    if "set_retrieved_at" in inp:
        es["retrieved_at"] = inp["set_retrieved_at"]; log.append("H4")
    # H1
    if isinstance(es, dict) and "evidence_set_version" not in es:
        es["evidence_set_version"] = C.VERSION; log.append("H1")
    # H3 (L2, L3)
    about_root = root_reading == "id" and "root" in vec["id"]
    if h3 and isinstance(es, dict) and "evidence_root" not in es and not about_root:
        root = _root_computable(es.get("sources"))
        if root is not None:
            es["evidence_root"] = root; log.append("H3:injected")
        else:
            log.append("H3:not_computable")
    # L5: held content
    held = {}
    hb = inp.get("verifier_holds_bytes_for", None)
    if hb is not None:
        urls = hb if isinstance(hb, list) else [hb]
        srcs = es.get("sources") if isinstance(es, dict) else None
        for i, e in enumerate(srcs if isinstance(srcs, list) else []):
            if isinstance(e, dict) and e.get("pinned") is True and e.get("url") in urls:
                if "verifier_recomputed_sha256" in inp:
                    held[i] = inp["verifier_recomputed_sha256"]
                elif inp.get("content_matches") is True:
                    held[i] = e.get("snippet_sha256")
        log.append("L5:held=%d" % len(held))
    return ("resolve", {"evidence_set": es}, held, log)


def run(corpus, h3=True, root_reading="computability"):
    out = []
    for vec in corpus["vectors"]:
        b = build(vec, h3=h3, root_reading=root_reading)
        if b[0] == "root":
            out.append({"id": vec["id"], "kind": "root", "result": b[1]})
            continue
        _, payload, held, log = b
        r = C.resolve(payload, held_sha256=held)
        out.append({"id": vec["id"], "kind": "resolve", "harness": log,
                    "input_sent": payload,
                    "result": {"outcome": r["outcome"], "token": r["token"], "conditions": sorted(r["conditions"]),
                               "reason": r["reason"], "per_item": r["per_item"]}})
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    corpus = json.load(open(args[0], encoding="utf-8"))
    res = run(corpus, h3="--no-h3" not in flags,
              root_reading="id" if "--root-reading=id" in flags else "computability")
    with open(args[1], "w", encoding="utf-8") as f:
        json.dump({"corpus_vectors": len(corpus["vectors"]), "results": res}, f, sort_keys=True, indent=1, ensure_ascii=True)
        f.write("\n")
    print(args[1], len(res), "vectors")
