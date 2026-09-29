#!/usr/bin/env python3
"""generate_variants.py — deterministic OUT-OF-SUITE variant generator for the 69 upstream vectors.

For every vector of a manifest (in manifest order) it derives up to 11 variants with a seeded RNG:
  hexflip  : last nibble of up to 3 hex strings (0x + >= 8 hex) flipped
  int+1    : up to 2 integers incremented
  case     : up to 2 alphabetic strings (not 0x…, not under description/provenance/note) case-swapped
  delkey   : up to 2 object keys deleted (objects not under description/provenance)
  droplist / swaplist : up to 2 lists (len >= 2) with one element dropped or two adjacent elements swapped
and writes them as `mutNNNN-<source>.json` plus a mutated MANIFEST.json in which every variant is listed
with the SOURCE entry's kind and `expect` forced to "valid" (the manifest's expect is NOT an oracle for a
variant; the differential compares two verifiers on the same bytes, not a verifier against `expect`).

Determinism: `random.Random(seed)` consumed in manifest order and in sorted key order. With seed 20260928
on spec/ (upstream 0.5.3 @ 0eda3038) the generator produced the 524 variants whose comparison with the
upstream verifier's recorded output is in results/ (regeneration verified byte-identical on Python
3.9 / 3.11 / 3.13; the variant bytes are `json.dump(..., indent=1, ensure_ascii=False)` of the parsed
object, so a non-integer token such as 1e2 would be re-serialized as 100.0 — none of the 69 sources
carries such a token; 1.1 and 3.0 round-trip unchanged).

Usage: python3 generate_variants.py <spec_dir> <out_dir> [--seed 20260928]
"""
import argparse
import copy
import json
import os
import random
import re
import sys


def leaves(o, path=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from leaves(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, path + (i,))
    else:
        yield path, o


def containers(o, path=()):
    if isinstance(o, (dict, list)):
        yield path, o
        for k, v in (o.items() if isinstance(o, dict) else enumerate(o)):
            yield from containers(v, path + (k,))


def get(o, p):
    for k in p:
        o = o[k]
    return o


def mutants(vec, rng):
    out = []
    L = list(leaves(vec))
    hexl = [(p, v) for p, v in L if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]{8,}", v)]
    for p, v in rng.sample(hexl, min(3, len(hexl))):
        m = copy.deepcopy(vec)
        c = v[-1]
        get(m, p[:-1])[p[-1]] = v[:-1] + ("0" if c != "0" else "1")
        out.append(("hexflip:" + "/".join(map(str, p)), m))
    ints = [(p, v) for p, v in L if isinstance(v, int) and not isinstance(v, bool)]
    for p, v in rng.sample(ints, min(2, len(ints))):
        m = copy.deepcopy(vec)
        get(m, p[:-1])[p[-1]] = v + 1
        out.append(("int+1:" + "/".join(map(str, p)), m))
    strs = [(p, v) for p, v in L if isinstance(v, str) and not v.startswith("0x") and any(ch.isalpha() for ch in v)
            and p and p[0] not in ("description", "provenance", "note")]
    for p, v in rng.sample(strs, min(2, len(strs))):
        m = copy.deepcopy(vec)
        get(m, p[:-1])[p[-1]] = v.upper() if v != v.upper() else v.lower()
        out.append(("case:" + "/".join(map(str, p)), m))
    dicts = [(p, o) for p, o in containers(vec) if isinstance(o, dict) and p and p[0] not in ("description", "provenance")]
    for p, o in rng.sample(dicts, min(2, len(dicts))):
        if not o:
            continue
        k = rng.choice(sorted(o))
        m = copy.deepcopy(vec)
        del get(m, p)[k]
        out.append(("delkey:" + "/".join(map(str, p + (k,))), m))
    lists = [(p, o) for p, o in containers(vec) if isinstance(o, list) and len(o) >= 2]
    for p, o in rng.sample(lists, min(2, len(lists))):
        m = copy.deepcopy(vec)
        lst = get(m, p)
        i = rng.randrange(len(lst))
        if rng.random() < 0.5:
            del lst[i]
            tag = "droplist"
        else:
            j = (i + 1) % len(lst)
            lst[i], lst[j] = lst[j], lst[i]
            tag = "swaplist"
        out.append((tag + ":" + "/".join(map(str, p)), m))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("spec_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--seed", type=int, default=20260928)
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)
    with open(os.path.join(args.spec_dir, "MANIFEST.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    os.makedirs(os.path.join(args.out_dir, "vectors"), exist_ok=True)
    entries, meta = [], {}
    for e in man["vectors"]:
        with open(os.path.join(args.spec_dir, "vectors", e["file"]), encoding="utf-8") as fh:
            vec = json.load(fh)
        for tag, m in mutants(vec, rng):
            f = "mut%04d-%s.json" % (len(entries), e["file"][:-5])
            entries.append(dict(e, file=f, expect="valid"))
            meta[f] = {"source": e["file"], "kind": e["kind"], "mutation": tag}
            with open(os.path.join(args.out_dir, "vectors", f), "w", encoding="utf-8") as fh:
                json.dump(m, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(args.out_dir, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(dict(man, vectors=entries), fh, indent=1, ensure_ascii=False)
    with open(os.path.join(args.out_dir, "VARIANTS.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": args.seed, "n": len(entries), "variants": meta}, fh, indent=1, ensure_ascii=False)
    print(f"seed {args.seed}: {len(entries)} variants written to {os.path.relpath(args.out_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
