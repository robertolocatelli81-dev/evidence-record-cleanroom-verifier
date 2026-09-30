#!/usr/bin/env python3
"""verify_countersig.py — clean-room runner for the counter-signature ("crypto profile") vectors of
tersignhq/evidence-record-conformance PR #11. Current target: the PR at 410869732eb0 (4108697, 2026-09-30, rebased on
ab7704d, Tersign's merge list applied): 37 vectors, six reject reasons.

Clean-room rule, as for the core suite: written from the PR's crypto/README.md, its MANIFEST.json and its vectors ONLY.
The PR's verify_crypto.py and secp256k1_recover.py were not read while this runner and its tests were written (first
version 2026-09-30 01:41Z); they were later downloaded with a clone of the fork and EXECUTED as a black box for
differential runs, and a separate local patching experiment read verify_crypto.py after that (not used by this file).
Hashing and chain_link come from this repository's own verify_tersign.py; the secp256k1 arithmetic is this repository's
own (docs/vector-audit/live_check.py, 2026-09-29), with the canonical checks added here.

The check, in the order of the PR README at 4108697 (the first failing step decides the reason):
  1. artifact_digest, seq, countersignature and ledger_signer are present            else malformed_input
  2. field domain: artifact_digest, prev_digest (when present) and ledger_signer are stripped of leading/trailing
     Unicode White_Space (the explicit set WHITE_SPACE below, NOT str.strip()) and lower-cased, then must be exactly
     0x + 64 hex (digests) or 0x + 40 hex (signer); an omitted or null prev_digest means genesis (32 zero bytes);
     seq is an integer (never bool/str/float) in [1, 2^53 - 1]                        else malformed_input
  3. link_version: absent means 1; any value other than the integer 1                else unsupported_link_version
  4. link = keccak256(artifact_digest || prev_digest or 32 zero bytes || uint64_be(seq))
  5. countersignature matched whole, never normalized: a string, 0x + 130 hex digits (no whitespace, no 0X), v in
     {27, 28}                                                                          else malformed_signature
  6. low-s (EIP-2, s <= n/2), checked on the signature bytes before recovery         else non_canonical_s
  7. EIP-191 personal_sign recovery over the 32 link bytes defines a public key       else unrecoverable
  8. its address equals the normalized ledger_signer                                  else signer_mismatch
Choices the README does not spell out, stated: r outside [1, n-1], s = 0, an x without a curve point and a
recovered point at infinity are `unrecoverable`; s > n/2 (s >= n included) is `non_canonical_s`, because step 6
precedes step 7; the recovery id is v-27 only (x = r, never r + n). A vector whose `input` is absent or not a JSON
object is `malformed_input`, and so is a vector file that is not UTF-8 JSON or nests arrays/objects deeper than
MAX_DEPTH (900) levels. Integers are parsed without Python's int-string limit (an integer too long for int() becomes a
non-integer marker: seq -> malformed_input, link_version -> unsupported_link_version, countersignature ->
malformed_signature, an unread key -> ignored), so the verdict does not depend on PYTHONINTMAXSTRDIGITS or on the
interpreter's recursion limit. A MANIFEST.json that cannot be loaded, or a listed vector file that cannot be opened
(missing, a directory, a broken link), stops the run with a one-line message and exit code 2, no traceback. Any other
unexpected exception while checking a loaded vector is reported as `internal_error`, never as a verdict reason.
History: earlier readings of ours (absent prev_digest malformed; ledger_signer checked without strip, cn18 at
d7c7fdc; seq in [0, 2^64 - 1]) were replaced by the suite's as each was pinned (cp3 at 1e08f4e; merge list at 4108697).

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
MALFORMED_INPUT = "malformed_input"          # suite reason at 4108697 (step 1-2)
INTERNAL_ERROR = "internal_error"            # never expected: the unit tests assert it on a set of hostile inputs; benches count it
UNSUPPORTED_LINK_VERSION = "unsupported_link_version"   # suite at 4108697, step 3
# Unicode White_Space property (the core's identifier_normalization set), listed explicitly: str.strip() is NOT this set
# (it also strips U+001C..U+001F, which are not White_Space). U+FEFF is not White_Space and is not stripped (vector cn17).
WHITE_SPACE = ("\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
               "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
               "\u2028\u2029\u202f\u205f\u3000")
SEQ_MAX = 2 ** 53 - 1
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


def _identifier(inp: Dict, key: str, nbytes: int, nullable: bool = False) -> Optional[bytes]:
    """Suite at 4108697, step 2: strip leading/trailing Unicode White_Space, lowercase, then exactly 0x + 2*nbytes hex."""
    if key not in inp:
        if nullable:
            return None                      # an absent prev_digest means genesis (cp3)
        raise Reject(MALFORMED_INPUT, f"{key} missing")
    val = inp[key]
    if val is None and nullable:
        return None
    if not isinstance(val, str):
        raise Reject(MALFORMED_INPUT, f"{key} is not a string")
    val = val.strip(WHITE_SPACE).lower()
    if not (val.startswith("0x") and len(val) == 2 + 2 * nbytes and set(val[2:]) <= _HEX):
        raise Reject(MALFORMED_INPUT, f"{key} is not 0x + {2 * nbytes} hex after White_Space strip and lowercase")
    return bytes.fromhex(val[2:])


def link_of(inp: Dict) -> bytes:
    """Steps 1-4 of the suite at 4108697 (required fields, field domain, link_version, link)."""
    for key in ("artifact_digest", "seq", "countersignature", "ledger_signer"):
        if key not in inp:
            raise Reject(MALFORMED_INPUT, f"{key} missing")                      # step 1
    art = _identifier(inp, "artifact_digest", 32)
    prev = _identifier(inp, "prev_digest", 32, nullable=True)
    _identifier(inp, "ledger_signer", 20)
    seq = inp.get("seq")
    if type(seq) is not int or not (1 <= seq <= SEQ_MAX):
        raise Reject(MALFORMED_INPUT, "seq is not an integer in [1, 2^53 - 1]")    # step 2
    if "link_version" in inp and not (type(inp["link_version"]) is int and inp["link_version"] == 1):
        raise Reject(UNSUPPORTED_LINK_VERSION, f"link_version {inp['link_version']!r} is not the integer 1")  # step 3
    return V.chain_link(art, prev, seq)                                            # step 4


def signer_of(inp: Dict) -> str:
    return "0x" + _identifier(inp, "ledger_signer", 20).hex()


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


class Oversized:
    """An integer literal too long for int() under the interpreter's int-string limit: not an int, never a crash."""
    def __init__(self, digits: str):
        self.digits = len(digits)

    def __repr__(self):
        return f"<integer of {self.digits} digits>"


def _parse_int(text: str):
    try:
        return int(text)
    except ValueError:
        return Oversized(text)


MAX_DEPTH = 900   # below every supported interpreter's JSON recursion limit (3.9/3.11 fail near 1000 levels)


def _depth(text: str) -> int:
    """Deepest [ / { nesting outside JSON strings (a pre-scan, so json never recurses past MAX_DEPTH)."""
    if text.count("[") + text.count("{") <= MAX_DEPTH:
        return 0   # cannot nest deeper than MAX_DEPTH: skip the per-character scan
    depth = deepest = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


class RunStopped(Exception):
    """The vector SET cannot be read (manifest unloadable, a listed file that cannot be opened): the run stops."""


def load_vector(path: str):
    """Return (vector, None) or (None, reason text). OSError is not a vector verdict: it raises RunStopped."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise RunStopped(f"vector file cannot be opened: {path}: {type(e).__name__}: {e.strerror or e}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "vector file is not UTF-8"
    if _depth(text) > MAX_DEPTH:
        return None, f"vector file nests deeper than {MAX_DEPTH} levels"
    try:
        return json.loads(text, parse_int=_parse_int), None
    except (ValueError, RecursionError) as e:
        return None, f"vector file not loadable as JSON: {type(e).__name__}"


def run(spec_dir: str, **kw):
    try:
        with open(os.path.join(spec_dir, "MANIFEST.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        entries = man["vectors"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise RunStopped(f"MANIFEST.json cannot be loaded from {spec_dir}: {type(e).__name__}: {e}")
    rows = []
    for ent in entries:
        vec, load_error = load_vector(os.path.join(spec_dir, "vectors", ent["file"]))
        if load_error:
            verdict, reason, detail = "reject", MALFORMED_INPUT, load_error
        else:
            verdict, reason, detail = check(vec.get("input") if isinstance(vec, dict) else None, **kw)
        exp_v = vec.get("expect") if isinstance(vec, dict) else ent.get("expect")
        exp_r = vec.get("reject_reason") if isinstance(vec, dict) else ent.get("reject_reason")
        ok = verdict == exp_v and (exp_v != "reject" or reason == exp_r)
        rows.append({"file": ent["file"], "expect": exp_v, "expect_reason": exp_r, "verdict": verdict,
                     "reason": reason, "detail": detail, "concordant": ok})
    return man, rows


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    spec = argv[0]
    try:
        man, rows = run(spec)
    except RunStopped as e:
        print(f"run stopped: {e}", file=sys.stderr)
        return 2
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
        json.dump(out, open(argv[argv.index("--json") + 1], "w", encoding="utf-8"), indent=1, default=repr)   # Oversized
    return 0 if n_ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
