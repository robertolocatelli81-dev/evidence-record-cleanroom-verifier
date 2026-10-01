#!/usr/bin/env python3
"""verify_eip712.py — independent runner for x402 receipt payload signatures (format "eip712"), written for the EIP-712
milestone of tersignhq/evidence-record-conformance PR #11 BEFORE the milestone's own vectors and runner were revealed.

Sources: EIP-712 (ethereum/EIPs EIPS/eip-712.md @0b06de5e), x402 extension-offer-and-receipt (x402-foundation/x402 @69652a69,
sections 3.2 and 5.3-5.5), the construction published on PR #11 (domain {name "x402 receipt", version "1", chainId 1},
Receipt type, payload as served). Keccak-256, EIP-712 encoding and secp256k1 recovery: lib/ (stdlib only), copied from
x402-signature-vectors @985b46d.

The check, in order (the first failing step decides the reason):
  1. input is an object with `artifact` (object whose keys are format, payload and signature only: x402 says domain and
     types "MUST NOT be transmitted on the wire") and `expected_signer` (0x + 40 hex, any case)  else malformed_input
  2. artifact.format == "eip712"                                                                    else unsupported_format
  3. payload is an object whose keys are Receipt fields only; version, network, resourceUrl, payer and issuedAt are
     present; version/issuedAt are JSON integers (not bool, not string, not float) in [0, 2^256 - 1]; the others are
     strings that are valid Unicode (a lone surrogate has no UTF-8 bytes to hash); an absent `transaction` equals "" (x402: "MUST treat empty-string optional fields as equivalent to
     absence")                                                                                       else malformed_payload
  4. payload.version == 1                                                                           else unsupported_version
  5. signature: a string, "0x" + 130 hex digits, taken whole (no strip, no case-folding of the prefix); v in {27, 28}
                                                                                                    else malformed_signature
  6. r in [1, n-1] and s != 0                                                                        else unrecoverable
     s <= n/2 (EIP-2), checked on the bytes before recovery                                         else non_canonical_s
  7. EIP-712 digest over the spec's domain and Receipt type (never taken from the artifact); recovery with id v-27
     defines a public key                                                                            else unrecoverable
  8. its address equals expected_signer (case-insensitive: an address, not a payload string)        else signer_mismatch
Strings in the payload are hashed as written: `payer` re-cased is a different message.
Readings the sources do not decide, chosen here and declared: extra keys in the payload or the artifact reject (steps 1, 3);
uint256 only as a JSON integer (no decimal string, no 1.0); the signature prefix is exactly "0x" (hex digits in either case)
and v in {27, 28}; low-s is required, by analogy with the crypto profile's rule for counter-signature suites that each suite
states its own canonical encoding; a payload string with a lone surrogate rejects; expected_signer is compared
case-insensitively; `network` is not checked against "eip155:<chainId>"; the issuedAt policy (x402 5.5 step 6) and signer
authorization (4.5.1) are not checked, the vector names the expected signer. A vector file that is not UTF-8, is not JSON
(NaN, Infinity and -Infinity included), has a duplicate object key or nests deeper than 900 levels is malformed_input; a
MANIFEST.json or a listed vector file that cannot be read stops the run (exit 2). Order inside step 6: the range of r and
s = 0 are checked before low-s.

Usage: python3 verify_eip712.py <dir with MANIFEST.json and vectors/> [--mutants] [--json out.json]      Stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import eip712 as E  # noqa: E402
import secp256k1 as S  # noqa: E402

N = S.N
DOMAIN = {"name": "x402 receipt", "version": "1", "chainId": 1}
FIELDS = [("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
          ("issuedAt", "uint256"), ("transaction", "string")]
TYPES = {"Receipt": [{"name": n, "type": t} for n, t in FIELDS]}
REQUIRED = [n for n, _ in FIELDS if n != "transaction"]

MALFORMED_INPUT, UNSUPPORTED_FORMAT, MALFORMED_PAYLOAD, UNSUPPORTED_VERSION = (
    "malformed_input", "unsupported_format", "malformed_payload", "unsupported_version")
MALFORMED_SIGNATURE, NON_CANONICAL_S, UNRECOVERABLE, SIGNER_MISMATCH = (
    "malformed_signature", "non_canonical_s", "unrecoverable", "signer_mismatch")
REASONS = [MALFORMED_INPUT, UNSUPPORTED_FORMAT, MALFORMED_PAYLOAD, UNSUPPORTED_VERSION,
           MALFORMED_SIGNATURE, NON_CANONICAL_S, UNRECOVERABLE, SIGNER_MISMATCH]
INTERNAL_ERROR = "internal_error"   # never expected; benches count it

_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_SIG = re.compile(r"0x[0-9a-fA-F]{130}")


class Reject(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason


def _uint256(v) -> bool:
    return type(v) is int and 0 <= v < 2 ** 256


def payload_message(payload) -> dict:
    """Step 3: the Receipt message exactly as transmitted, with an absent transaction as ""."""
    if not isinstance(payload, dict):
        raise Reject(MALFORMED_PAYLOAD, "payload is not an object")
    extra = sorted(k for k in payload if k not in dict(FIELDS))
    if extra:
        raise Reject(MALFORMED_PAYLOAD, f"payload keys outside the Receipt type: {extra}")
    for name in REQUIRED:
        if name not in payload:
            raise Reject(MALFORMED_PAYLOAD, f"payload.{name} missing")
    for name, typ in FIELDS:
        if name not in payload:
            continue
        val = payload[name]
        if typ == "uint256" and not _uint256(val):
            raise Reject(MALFORMED_PAYLOAD, f"payload.{name} is not a JSON integer in [0, 2^256 - 1]")
        if typ == "string" and not isinstance(val, str):
            raise Reject(MALFORMED_PAYLOAD, f"payload.{name} is not a string")
        if typ == "string":
            try:
                val.encode("utf-8")
            except UnicodeEncodeError:   # a lone surrogate: no UTF-8 bytes exist to hash
                raise Reject(MALFORMED_PAYLOAD, f"payload.{name} is not valid Unicode (lone surrogate)")
    msg = dict(payload)
    msg.setdefault("transaction", "")
    return msg


def digest(msg: dict, domain: dict = DOMAIN, types: dict = TYPES) -> bytes:
    return E.signing_digest(domain, "Receipt", types, msg)


def check(inp, *, low_s=True, allow_v=(27, 28), digest_fn=digest, extra_ok=False, signer_case_sensitive=False,
          artifact_extra_ok=False):
    """Returns (verdict, reason, detail). Keyword switches exist only to build mutants."""
    try:
        if not isinstance(inp, dict) or not isinstance(inp.get("artifact"), dict):
            raise Reject(MALFORMED_INPUT, "input or input.artifact is not an object")
        want = inp.get("expected_signer")
        if not isinstance(want, str) or not _ADDR.fullmatch(want):
            raise Reject(MALFORMED_INPUT, "expected_signer is not 0x + 40 hex")
        art = inp["artifact"]
        if not artifact_extra_ok and set(art) - {"format", "payload", "signature"}:
            raise Reject(MALFORMED_INPUT, f"artifact keys outside format/payload/signature: {sorted(set(art) - {'format', 'payload', 'signature'})}")
        if art.get("format") != "eip712":
            raise Reject(UNSUPPORTED_FORMAT, f"format {art.get('format')!r} is not \"eip712\"")
        payload = art.get("payload")
        if extra_ok and isinstance(payload, dict):
            payload = {k: v for k, v in payload.items() if k in dict(FIELDS)}
        msg = payload_message(payload)
        if msg["version"] != 1:
            raise Reject(UNSUPPORTED_VERSION, f"payload.version {msg['version']} is not 1")
        sig = art.get("signature")
        if not isinstance(sig, str) or not _SIG.fullmatch(sig):
            raise Reject(MALFORMED_SIGNATURE, "signature is not \"0x\" + 130 hex digits")
        raw = bytes.fromhex(sig[2:])
        r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
        if v not in allow_v:
            raise Reject(MALFORMED_SIGNATURE, f"v = {v}, not in {{27, 28}}")
        if not (1 <= r < N) or s == 0:
            raise Reject(UNRECOVERABLE, "r outside [1, n-1] or s = 0")
        if low_s and s > N // 2:
            raise Reject(NON_CANONICAL_S, "s > n/2 (EIP-2)")
        if s >= N:
            raise Reject(UNRECOVERABLE, "s >= n")
        h = digest_fn(msg)
        try:
            got = S.public_key_to_address(S.recover_public_key(h, r, s, v - 27), E.keccak256)
        except ValueError as e:
            raise Reject(UNRECOVERABLE, str(e))
        same = got == want if signer_case_sensitive else got.lower() == want.lower()
        if not same:
            raise Reject(SIGNER_MISMATCH, f"recovered {got} != expected_signer {want}")
        return "valid", None, f"recovers to {got}"
    except Reject as e:
        return "reject", e.reason, str(e)
    except Exception as e:  # last resort: never crash, never disguise a runner bug as a verdict reason
        return "reject", INTERNAL_ERROR, f"runner bug: {type(e).__name__}: {e}"


class RunStopped(Exception):
    pass


class Oversized:
    """An integer literal int() refuses under the interpreter's int-string limit: not an int, so never a uint256."""
    def __init__(self, text):
        self.digits = len(text)

    def __repr__(self):
        return f"<integer of {self.digits} digits>"


def _parse_int(text):
    try:
        return int(text)
    except ValueError:
        return Oversized(text)


MAX_DEPTH = 900   # below the JSON recursion limit of every supported interpreter


def _depth(text):
    if text.count("[") + text.count("{") <= MAX_DEPTH:
        return 0
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


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (RFC 8259)")


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate object key")   # the shown value may not be the signed one
    return dict(pairs)


def load_vector(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise RunStopped(f"vector file cannot be opened: {path}: {type(e).__name__}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "vector file is not UTF-8"
    if _depth(text) > MAX_DEPTH:
        return None, f"vector file nests deeper than {MAX_DEPTH} levels"
    try:
        return json.loads(text, parse_int=_parse_int, parse_constant=_no_constant, object_pairs_hook=_no_duplicates), None
    except (ValueError, RecursionError) as e:
        return None, f"vector file not loadable as JSON: {type(e).__name__}"


def run(spec_dir, **kw):
    try:
        with open(os.path.join(spec_dir, "MANIFEST.json"), encoding="utf-8") as fh:
            entries = json.load(fh)["vectors"]
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        raise RunStopped(f"MANIFEST.json cannot be loaded: {type(e).__name__}")
    if not isinstance(entries, list) or not all(isinstance(e, dict) and isinstance(e.get("file"), str) for e in entries):
        raise RunStopped("MANIFEST.json: vectors must be a list of objects with a string \"file\"")
    rows = []
    for ent in entries:
        vec, err = load_vector(os.path.join(spec_dir, "vectors", ent["file"]))
        if err:
            verdict, reason, detail = "reject", MALFORMED_INPUT, err
        else:
            verdict, reason, detail = check(vec.get("input") if isinstance(vec, dict) else None, **kw)
        exp_v = ent.get("expect")
        exp_r = ent.get("reject_reason")
        ok = verdict == exp_v and (exp_v != "reject" or reason == exp_r)
        rows.append({"file": ent["file"], "expect": exp_v, "expect_reason": exp_r, "verdict": verdict,
                     "reason": reason, "detail": detail, "concordant": ok})
    return rows


MUTANTS = {
    "no_low_s": dict(low_s=False),
    "v_any": dict(allow_v=tuple(range(256))),
    "extra_keys_ignored": dict(extra_ok=True),
    "signer_case_sensitive": dict(signer_case_sensitive=True),
    "chain_id_8453": dict(digest_fn=lambda m: digest(m, dict(DOMAIN, chainId=8453))),
    "domain_name_typo": dict(digest_fn=lambda m: digest(m, dict(DOMAIN, name="x402 reciept"))),
    "payer_lowercased": dict(digest_fn=lambda m: digest(dict(m, payer=m["payer"].lower()))),
    "type_reordered": dict(digest_fn=lambda m: digest(m, types={"Receipt": [TYPES["Receipt"][i] for i in (1, 0, 2, 3, 4, 5)]})),
    "personal_sign_over_digest": dict(digest_fn=lambda m: E.keccak256(b"\x19Ethereum Signed Message:\n32" + digest(m))),
    "artifact_extra_keys_ignored": dict(artifact_extra_ok=True),
    "transaction_dropped_from_type": dict(digest_fn=lambda m: E.signing_digest(
        DOMAIN, "Receipt", {"Receipt": TYPES["Receipt"][:5]}, {k: v for k, v in m.items() if k != "transaction"})),
}


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    if "--json" in argv and (argv.index("--json") + 1 >= len(argv) or argv[argv.index("--json") + 1].startswith("-")):
        print("usage error: --json needs an output path", file=sys.stderr)
        return 2
    try:
        rows = run(argv[0])
    except RunStopped as e:
        print(f"run stopped: {e}", file=sys.stderr)
        return 2
    for r in rows:
        print(f"[{'OK' if r['concordant'] else 'DIFF'}] {r['file']:52s} -> {r['verdict']}"
              f"{'/' + r['reason'] if r['reason'] else ''}  ({r['detail'][:70]})")
    ok = sum(r["concordant"] for r in rows)
    print(f"concordant {ok}/{len(rows)}")
    out = {"rows": rows, "concordant": ok, "n": len(rows)}
    if "--mutants" in argv:
        out["mutants"] = {}
        for name, kw in MUTANTS.items():
            killers = [r["file"] for r in run(argv[0], **kw) if not r["concordant"]]
            out["mutants"][name] = killers
            print(f"mutant {name:30s} {'KILLED by ' + ', '.join(killers[:4]) if killers else 'SURVIVES'}")
    if "--json" in argv:
        try:
            with open(argv[argv.index("--json") + 1], "w", encoding="utf-8") as fh:
                json.dump(out, fh, indent=1, default=repr)
        except OSError as e:
            print(f"run stopped: --json output cannot be written: {type(e).__name__}", file=sys.stderr)
            return 2
    return 0 if ok == len(rows) and ("--mutants" not in argv or all(out["mutants"].values())) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
