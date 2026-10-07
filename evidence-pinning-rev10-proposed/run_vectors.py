#!/usr/bin/env python3
"""Control runner: the proposed vectors against one or more evidence-set checkers.

    python3 run_vectors.py --ours PATH/es_check_filed.py --bbv PATH/evidence_set_check.py [--vectors FILE] [--json]

--ours: robertolocatelli81-dev/evidence-record-cleanroom-verifier, evidence-pinning-rev9/es_check_filed.py
        (resolve(payload, held={entry index: bytes}))
--bbv:  babyblueviper1/preaction-governance-conformance, tools/evidence_set_check.py
        (resolve(payload, held={"hashes": set, "by_url": {url: sha256 hex}}))

No harness step is applied: every vector is a complete evidence_set. Candidate bytes are taken from
verifier_holds_bytes_hex (hex-decoded); the runner never reads a digest or content_matches from the vector.
A vector passes for a checker when the reported condition set EQUALS expected_conditions, the outcome
(halt / unknown / resolved) is the expected one, and, where stated, the per-item reasons equal
expected_item_reasons in sources order. Exit 0 only if every vector passes for every checker given;
an empty or non-array vector file, a duplicate key or a non-finite number in it, and a vector without
`designation` are errors (exit 2), never a pass. verifier_holds_bytes_hex values must be lowercase hex.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VECTORS = os.path.join(HERE, "proposed_vectors_presence_rule_candidate_bytes.json")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"error: {path}: not a Python module file")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _no_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_nonfinite(c):
    raise ValueError(f"non-finite number {c}")


def load_vectors(raw):
    """The vector array, parsed strictly: duplicate keys and NaN/Infinity are errors; the top level must be a
    non-empty array of objects, so that an empty file can never count as a pass."""
    vectors = json.loads(raw, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_nonfinite)
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("the vector file must be a non-empty JSON array")
    for vec in vectors:
        if not isinstance(vec, dict) or "id" not in vec or "designation" not in vec or "input" not in vec:
            raise ValueError("every vector must be an object with id, designation and input")
    return vectors


def held_bytes(inp):
    """{url: bytes} from verifier_holds_bytes_hex; empty when the vector holds nothing.
    The hex must be lowercase (the form the vectors state); anything else is an error for that vector."""
    out = {}
    for u, h in (inp.get("verifier_holds_bytes_hex") or {}).items():
        if not isinstance(h, str) or h != h.lower():
            raise ValueError(f"verifier_holds_bytes_hex[{u!r}] is not lowercase hex")
        out[u] = bytes.fromhex(h)
    return out


def run_ours(mod, vec):
    inp = vec["input"]
    srcs = inp["evidence_set"]["sources"]
    by_url = held_bytes(inp)
    urls = [e.get("url") for e in srcs]
    assert len(set(urls)) == len(urls) or not by_url, "candidate bytes are keyed by url: urls must be distinct"
    held = {i: by_url[u] for i, u in enumerate(urls) if u in by_url}
    r = mod.resolve({"evidence_set": inp["evidence_set"]}, held=held)
    outcome = "halt" if r["outcome"] == "malformed" else r["token"]
    return {"outcome": outcome, "conditions": sorted(r["conditions"]), "item_reasons": r["per_item"]}


def run_bbv(mod, vec):
    inp = vec["input"]
    by_url = held_bytes(inp)
    held = {"hashes": {hashlib.sha256(b).hexdigest() for b in by_url.values()},
            "by_url": {u: hashlib.sha256(b).hexdigest() for u, b in by_url.items()}}
    token, rep = mod.resolve({"evidence_set": inp["evidence_set"]}, held)
    items = [it["reason"] for it in rep["items"]] if "items" in rep else None
    return {"outcome": token, "conditions": sorted(rep.get("conditions", [])), "item_reasons": items}


def expected(vec):
    if vec["designation"] == "MALFORMED":
        out = "halt"
    else:
        out = vec["expected_token"]
    return {"outcome": out, "conditions": sorted(vec["expected_conditions"]),
            "item_reasons": vec.get("expected_item_reasons")}


def compare(got, want):
    ok = got["outcome"] == want["outcome"] and set(got["conditions"]) == set(want["conditions"])
    if want["item_reasons"] is not None:
        ok = ok and got["item_reasons"] == want["item_reasons"]
    return ok


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours")
    ap.add_argument("--bbv")
    ap.add_argument("--vectors", default=DEFAULT_VECTORS)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    checkers = []
    try:
        if a.ours:
            checkers.append(("ours", run_ours, load(a.ours, "ours_checker")))
        if a.bbv:
            checkers.append(("bbv", run_bbv, load(a.bbv, "bbv_checker")))
    except (OSError, SystemExit, SyntaxError) as exc:
        print(f"error: cannot load checker: {exc}", file=sys.stderr)
        return 2
    if not checkers:
        ap.error("give at least one checker")
    try:
        with open(a.vectors, "rb") as f:
            raw = f.read()
        vectors = load_vectors(raw)
    except (OSError, ValueError) as exc:              # unreadable or malformed vector file: an error, not a pass
        print(f"error: {a.vectors}: {exc}", file=sys.stderr)
        return 2
    rows, fails = [], 0
    for vec in vectors:
        want = expected(vec)
        row = {"id": vec["id"], "expected": want}
        for name, fn, mod in checkers:
            try:
                got = fn(mod, vec)
            except Exception as exc:          # a crash is a failure, never a pass
                got = {"outcome": "crash", "conditions": [repr(exc)], "item_reasons": None}
            row[name] = got
            row[name + "_pass"] = compare(got, want)
            fails += not row[name + "_pass"]
        rows.append(row)
    summary = {"vectors_sha256": hashlib.sha256(raw).hexdigest(), "python": sys.version.split()[0],
               "vectors": len(vectors),
               "passed": {name: sum(r[name + "_pass"] for r in rows) for name, _, _ in checkers}}
    if a.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=1, sort_keys=True))
    else:
        for r in rows:
            print(r["id"], " ".join(f"{n}={'PASS' if r[n + '_pass'] else 'FAIL'}" for n, _, _ in checkers))
            for n, _, _ in checkers:
                g = r[n]
                print(f"   {n}: {g['outcome']} {g['conditions']} {g['item_reasons']}")
        print(json.dumps(summary, sort_keys=True))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
