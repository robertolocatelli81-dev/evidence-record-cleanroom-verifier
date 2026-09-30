#!/usr/bin/env python3
"""verify_countersig.py — clean-room runner for the counter-signature ("crypto profile") vectors proposed in
tersignhq/evidence-record-conformance PR #11 (head 399bcf8a, 2026-09-29).

Clean-room rule, as for the core suite: written from the PR's crypto/README.md (the four-step check and the four
reject reasons), its MANIFEST.json and its vectors ONLY. The PR's verify_crypto.py and secp256k1_recover.py were not
read while this runner and its tests were written (2026-09-30, first version 01:41Z); they were later downloaded with
a clone of the fork and EXECUTED as a black box for differential runs, and a separate local patching experiment read
verify_crypto.py after that (not used by this file). Hashing and chain_link come from this repository's own verify_tersign.py; the
secp256k1 arithmetic is this repository's own (docs/vector-audit/live_check.py, 2026-09-29), with the canonical
checks added here.

The check, per crypto/README.md:
  1. link = chain_link(artifact_digest, prev_digest, seq)            (the core link, recomputed from the vector)
  2. countersignature = 65 bytes r||s||v with v in {27, 28}           else malformed_signature
  3. low-s (EIP-2): s <= n/2                                          else non_canonical_s
  4. EIP-191 personal_sign recovery over the 32 link bytes            unrecoverable if no point / r, s out of range
     must equal ledger_signer (0x-address, strip + lowercase)         else signer_mismatch
Choices the README leaves open, stated: r or s outside [1, n-1] and an x without a curve point are
`unrecoverable`; a non-hex or wrong-length hex string is `malformed_signature`; the recovery id is v-27 only
(x = r, never r + n, since v is restricted to 27/28). The README does not say what a runner does with a malformed
LINK field, and both this runner (before 2026-09-30) and the PR runner crashed on some and silently accepted
others (seq "1", 1.0 or true; digests of the wrong length). Chosen here, outside the README's four reasons:
reject `malformed_input` when artifact_digest / prev_digest are not "0x" + 64 hex (prev may be null), seq is not
an integer in [0, 2^64 - 1] (bool excluded), ledger_signer is not "0x" + 40 hex after strip, prev_digest is absent
(absent is not null), or another link field is missing. The form of every field, ledger_signer included, is
checked before the signature; a missing or non-string countersignature is then `malformed_signature`. The signature hex must be "0x" + hex
digits only: bytes.fromhex skips whitespace, so it is checked before decoding. No value of `input` makes the runner raise (a vector FILE that is not a JSON object is outside this rule).

Usage:  python3 verify_countersig.py <dir with MANIFEST.json and vectors/> [--mutants] [--json out.json]
Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Callable, Dict, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import verify_tersign as V  # noqa: E402  (this repository's keccak256 and chain_link)

P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

MALFORMED, NON_CANONICAL, UNRECOVERABLE, MISMATCH = (
    "malformed_signature", "non_canonical_s", "unrecoverable", "signer_mismatch")
MALFORMED_INPUT = "malformed_input"          # outside the README's four reasons: a declared choice (see docstring)
INTERNAL_ERROR = "internal_error"            # never expected: a test fails if any input produces it
_HEX = set("0123456789abcdefABCDEF")


class Reject(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def address_of_point(Q) -> str:
    return "0x" + V.keccak256_pure(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[12:].hex()


def personal_hash(msg: bytes) -> bytes:
    return V.keccak256_pure(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)


def parse_sig(sig_hex, allow_v=(27, 28)) -> Tuple[int, int, int]:
    if not isinstance(sig_hex, str) or not sig_hex.startswith("0x"):
        raise Reject(MALFORMED, "countersignature is not a 0x-hex string")
    if not set(sig_hex[2:]) <= _HEX:           # bytes.fromhex would silently skip spaces, tabs, newlines
        raise Reject(MALFORMED, "countersignature contains non-hex characters")
    try:
        sig = bytes.fromhex(sig_hex[2:])
    except ValueError:
        raise Reject(MALFORMED, "countersignature is not valid hex") from None
    if len(sig) != 65:
        raise Reject(MALFORMED, f"countersignature is {len(sig)} bytes, not 65")
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if v not in allow_v:
        raise Reject(MALFORMED, f"v = {v}, not in {{27, 28}}")
    return r, s, v


def recover(h32: bytes, r: int, s: int, v: int) -> str:
    if not (1 <= r < N and 1 <= s < N):
        raise Reject(UNRECOVERABLE, "r or s outside [1, n-1]")
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise Reject(UNRECOVERABLE, "r is not the x of a curve point")
    if y % 2 != (v - 27) % 2:
        y = P - y
    e = int.from_bytes(h32, "big")
    Q = _mul(pow(r, -1, N), _add(_mul(s, (x, y)), _mul((-e) % N, G)))
    if Q is None:
        raise Reject(UNRECOVERABLE, "recovered point at infinity")
    return address_of_point(Q)


def _hex_field(inp: Dict, key: str, nbytes: int, nullable: bool = False) -> Optional[bytes]:
    if key not in inp:
        raise Reject(MALFORMED_INPUT, f"{key} missing")
    val = inp[key]
    if val is None and nullable:
        return None
    if not (isinstance(val, str) and val.startswith("0x") and len(val) == 2 + 2 * nbytes and set(val[2:]) <= _HEX):
        raise Reject(MALFORMED_INPUT, f"{key} is not 0x + {2 * nbytes} hex")
    return bytes.fromhex(val[2:])


def link_of(inp: Dict) -> bytes:
    art = _hex_field(inp, "artifact_digest", 32)
    prev = _hex_field(inp, "prev_digest", 32, nullable=True)
    seq = inp.get("seq")
    if type(seq) is not int or not (0 <= seq <= 2 ** 64 - 1):
        raise Reject(MALFORMED_INPUT, "seq is not an integer in [0, 2^64 - 1]")
    return V.chain_link(art, prev, seq)


def signer_of(inp: Dict) -> str:
    val = inp.get("ledger_signer")
    val = val.strip().lower() if isinstance(val, str) else val      # README: compared after strip + lowercase
    if not (isinstance(val, str) and val.startswith("0x") and len(val) == 42 and set(val[2:]) <= _HEX):
        raise Reject(MALFORMED_INPUT, "ledger_signer is not 0x + 40 hex")
    return val.lower()


def check(inp: Dict, *, low_s=True, eip191=True, allow_v=(27, 28), fixed_signer: Optional[str] = None,
          link_fn: Callable[[Dict], bytes] = link_of) -> Tuple[str, Optional[str], str]:
    """Returns (verdict, reject_reason, detail). Keyword switches exist only to build the mutants below."""
    try:
        if not isinstance(inp, dict):
            raise Reject(MALFORMED_INPUT, "vector input is absent or not a JSON object")
        link = link_fn(inp)
        want = fixed_signer or signer_of(inp)       # every field's FORM is checked before the signature
        r, s, v = parse_sig(inp.get("countersignature"), allow_v)
        if v not in (27, 28):          # mutant path: an out-of-range v "normalised" instead of refused
            v = 27 + (v - 27) % 2
        if low_s and s > N // 2:
            raise Reject(NON_CANONICAL, "s > n/2 (EIP-2)")
        h = personal_hash(link) if eip191 else link
        got = recover(h, r, s, v)
        if got != want:
            raise Reject(MISMATCH, f"recovered {got} != ledger_signer {want}")
        return "valid", None, f"recovers to {got}"
    except Reject as e:
        return "reject", e.reason, str(e)
    except Exception as e:  # last resort: never crash, but never disguise a runner bug as a verdict reason
        return "reject", INTERNAL_ERROR, f"runner bug: {type(e).__name__}: {e}"


LEDGER = "0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6"
MUTANTS = {
    "no_low_s": dict(low_s=False),
    "no_eip191_prefix": dict(eip191=False),
    "v_normalised_not_refused": dict(allow_v=tuple(range(256))),
    "hardcoded_ledger_signer": dict(fixed_signer=LEDGER),
    "link_ignores_seq": dict(link_fn=lambda inp: link_of(dict(inp, seq=1))),
}


def run(spec_dir: str, **kw):
    man = json.load(open(os.path.join(spec_dir, "MANIFEST.json"), encoding="utf-8"))
    rows = []
    for ent in man["vectors"]:
        vec = json.load(open(os.path.join(spec_dir, "vectors", ent["file"]), encoding="utf-8"))
        verdict, reason, detail = check(vec.get("input") if isinstance(vec, dict) else None, **kw)
        exp_v, exp_r = vec.get("expect"), vec.get("reject_reason")
        ok = verdict == exp_v and (exp_v != "reject" or reason == exp_r)
        rows.append({"file": ent["file"], "expect": exp_v, "expect_reason": exp_r, "verdict": verdict,
                     "reason": reason, "detail": detail, "concordant": ok})
    return man, rows


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    spec = argv[0]
    man, rows = run(spec)
    for r in rows:
        print(f"[{'OK' if r['concordant'] else 'DIFF'}] {r['file']:48s} -> {r['verdict']}"
              f"{'/' + r['reason'] if r['reason'] else ''}  ({r['detail'][:70]})")
    n_ok = sum(r["concordant"] for r in rows)
    print(f"concordant {n_ok}/{len(rows)}")
    out = {"spec_manifest_sha256": hashlib.sha256(open(os.path.join(spec, "MANIFEST.json"), "rb").read()).hexdigest(),
           "rows": rows, "concordant": n_ok, "n": len(rows)}
    if "--mutants" in argv:
        out["mutants"] = {}
        for name, kw in MUTANTS.items():
            _, mrows = run(spec, **kw)
            killers = [r["file"] for r in mrows if not r["concordant"]]
            out["mutants"][name] = killers
            print(f"mutant {name:26s} {'KILLED by ' + ', '.join(killers) if killers else 'SURVIVES'}")
    if "--json" in argv:
        json.dump(out, open(argv[argv.index("--json") + 1], "w", encoding="utf-8"), indent=1)
    return 0 if n_ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
