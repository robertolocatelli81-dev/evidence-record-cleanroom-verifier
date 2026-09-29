#!/usr/bin/env python3
"""positive_controls.py — checks that do NOT depend on the manifest's `expect` field, so that a
69/69 result cannot be a tautology of the harness:

  1. Keccak-256 against public values, and ≠ SHA3-256.
  2. n29's claimed prefixDigest must equal sha3_256 over the SAME canonical bytes this verifier
     builds (the vector says so): an independent pin of the boundary prefix digest domain.
  3. p27 provenance: keccak256(canonical(commitment)) == commitment_digest and
     sha256(commitment_digest) == anchored_digest (the anchor relation on live data).
  4. p1 genesis digest is seq 1 of p27 (live chain consistency) and p4's artifact.
  5. p13 digest: recomputed on two pipelines — this JCS and Python json.dumps(sort_keys,
     separators) which agrees only for ASCII/BMP keys — must agree here (no exotic keys).

Usage: python3 positive_controls.py spec/
"""
import hashlib
import json
import os
import sys

import verify_tersign as V


def load(spec, name):
    with open(os.path.join(spec, "vectors", name), "r", encoding="utf-8") as fh:
        return V.load_json(fh.read())


def main(argv=None) -> int:
    spec = (argv or sys.argv[1:])[0]
    ok_all = True

    def check(label, cond, extra=""):
        nonlocal ok_all
        ok_all &= bool(cond)
        print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")

    check("keccak256('') public value", V.keccak256_pure(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    check("keccak256('abc') public value", V.keccak256_pure(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    check("keccak256 != sha3_256", V.keccak256_pure(b"abc") != hashlib.sha3_256(b"abc").digest())

    n29 = load(spec, "n29-suite-transition-redigests-prefix.json")
    cb = V.jcs(n29["input"]["prefix"])
    s3 = hashlib.sha3_256(cb).hexdigest()
    check("n29 prefixDigest == sha3_256(canonical(prefix)) [independent pin of the prefix domain]",
          s3 == n29["input"]["boundary_event"]["prefixDigest"][2:], f"bytes={cb.decode()}")

    p27 = load(spec, "p27-live-chain-commitment-genesis-chain.json")
    c = p27["provenance"]["commitment"]
    cd = V.keccak256_pure(V.jcs(c))
    check("p27 keccak256(canonical(commitment)) == provenance.commitment_digest",
          cd.hex() == p27["provenance"]["commitment_digest"][2:], f"canonical={V.jcs(c).decode()}")
    check("p27 sha256(commitment_digest) == provenance.anchored_digest",
          hashlib.sha256(cd).hexdigest() == p27["provenance"]["anchored_digest"][2:])
    check("p27 head.acc == provenance.commitment.acc", p27["input"]["head"]["acc"] == c["acc"])

    p1 = load(spec, "p1-live-genesis-receipt.json")
    p4 = load(spec, "p4-chain-link-genesis.json")
    g = "0x" + V.keccak256_pure(V.jcs(p1["input"]["payload"])).hex()
    check("p1 genesis digest == p27 seq-1 artifact", g == p27["input"]["records"][0]["artifact_digest"])
    check("p1 genesis digest == p4 artifact_digest", g == p4["input"]["artifact_digest"])

    p13 = load(spec, "p13-decimal-string-beside-integer.json")
    alt = json.dumps(p13["input"]["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    check("p13 canonical bytes agree with json.dumps(sort_keys) on BMP-ASCII keys", alt == V.jcs(p13["input"]["payload"]))
    p14 = load(spec, "p14-supplementary-plane-key-order.json")
    alt14 = json.dumps(p14["input"]["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    check("p14 canonical bytes DIFFER from json.dumps(sort_keys) (code-point sort) — the class p14/n12 pins",
          alt14 != V.jcs(p14["input"]["payload"]))

    print("ALL PASS" if ok_all else "SOME FAIL")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
