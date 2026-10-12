#!/usr/bin/env python3
"""verify_tersign.py — INDEPENDENT (clean-room) structural verifier for the Tersign
`evidence-record-conformance` suite v0.5.7 (162 vectors, upstream tag v0.5.7 = commit 112b3ed6; the same
MANIFEST.json and vectors at 9be9eec9). Written first against v0.5.3 (69 vectors, upstream commit 0eda3038);
aligned to v0.5.7 on 2026-10-12 from the v0.5.7 MANIFEST.json rule texts and vector files only.

Written 2026-09-28 in a separate, isolated session (clean room) from ONLY:
  * spec/MANIFEST.json  (rule texts per kind, reject reasons, profile)
  * spec/vectors/*.json (the 69 vectors, incl. their `description` fields)
  * vendor/roberto_x402_eip712.py (keccak256, copied below with provenance)
  * public specifications read online: RFC 8785 (JCS), RFC 7493 (I-JSON),
    x402 PR #2853 `specs/extensions/compliance_fields.md` @ b8a81c0 (read via jsdelivr),
    MCP issue #3004 (comments read via api.github.com).
NOT read: Tersign's verify.py / keccak.py / tools/ / crypto/ / README / CONTRIBUTORS / TypeScript engine
(neither in the 2026-09-28 session nor in the 2026-10-12 alignment to v0.5.7).

Usage:
    python3 verify_tersign.py spec-0.5.7/          # run the 162 vectors of v0.5.7, print verdict+reason, exit 1 on discord
    python3 verify_tersign.py spec/                # the 69 vectors of v0.5.3 (byte-identical to the same files in v0.5.7)
    python3 verify_tersign.py spec/ --json out.json
    python3 verify_tersign.py spec/ --ablate keccak_to_sha3     # disable one rule (ablation study)
    python3 verify_tersign.py spec/ --flip-expect               # positive control on the harness itself
    python3 verify_tersign.py spec/ --mutate                    # positive control: mutated vectors must flip

Profile (MANIFEST "profile"): structural only — digests, canonical bytes, chain arithmetic,
sequence closure, declared-claim evaluation. NO counter-signature recovery, NO attestor
identity binding, NO anchoring proof (OpenTimestamps / Bitcoin) — those are the crypto and
existence profiles, outside the stdlib core. This verifier says so and does not pretend.

Runtime: Python stdlib only (json, hashlib, re, sys, argparse, copy). Tested on 3.9/3.11/3.13.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "0.2.0"
SUITE_VERSION = "0.5.7"

# ════════════════════════════════════════════════════════════════════════════════════════
# 0. Reject reasons — the closed vocabulary used by MANIFEST.json `reason` fields.
# ════════════════════════════════════════════════════════════════════════════════════════
R_RECOMPUTE = "recompute_mismatch"
R_CANON = "canonicalization_reject"
R_NUMBER = "number_domain_reject"
R_CONTINUITY = "continuity_reject"
R_COMPLETENESS = "completeness_reject"
R_EXISTENCE = "existence_reject"
R_PHASE = "phase_reject"
R_INDEPENDENCE = "independence_reject"
R_BOUNDARY = "boundary_reject"
R_BINDING = "binding_reject"
R_INPUT = "input_reject"          # NOT in the manifest vocabulary: vector file unreadable / kind unknown


class Reject(Exception):
    """Raised by a criterion when the vector must reject. Carries (reason, detail)."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


# Ablation switches (for the ablation study; default = none). Each name disables ONE rule.
ABLATIONS = {
    "keccak_to_sha3": "content address / links / delivery digest computed with SHA3-256 instead of Keccak-256",
    "codepoint_key_order": "JCS keys sorted by Unicode code point instead of UTF-16 code units",
    "no_number_domain": "non-integer number tokens and integers beyond 2^53-1 are serialized instead of rejected",
    "no_seq_completeness": "chain_set skips the every-seq-exactly-once check (missing / duplicate)",
    "no_link_recompute": "chain_set does not recompute a presented `link`",
    "no_accumulator": "chain_commitment does not compare head.acc with the fold",
    "no_independence": "independence_claim does not require a non-party attestor",
    "no_identity_normalization": "identities compared byte-exact (no strip / lowercase / trailing-punctuation fold)",
    "no_record_commits_presence": "a declared `record_commits` field is ignored instead of rejected",
    "declared_commits": "commitments are read from a declared `record_commits` list when present (the n22 override bug)",
    "no_position_binding": "boundary_binding does not require `position`",
    "no_coverage_bound": "boundary_binding does not compare covered_through with attestedPrefixLength",
    "phase_any": "phase_claim accepts any phase token (no vocabulary, no equality)",
    "no_unknown_claim_reject": "unknown independence claim tokens are ignored instead of rejected",
    # added 2026-10-12 with the v0.5.7 rules (each one rule of the v0.5.7 MANIFEST, see the code that reads it)
    "no_seq_domain": "chain_link accepts any uint64 seq instead of an integer token in [1, 2^53-1]",
    "no_surrogate_first": "payload_text: number tokens are checked before an unpaired surrogate",
    "no_own_reason": "offer/decision-evidence/boundary criteria name canonicalization_reject for an object with no canonical form",
    "no_pair_join": "a surrogate pair written half raw, half escaped stays two code points (names compared as code points)",
    "python_whitespace_strip": "identifiers and digests stripped with Python str.strip() (also strips U+001C-U+001F)",
    "no_percent_rule": "percent-encoded triplets are neither decoded nor refused",
    "no_dot_segment_rule": "`?` and dot-segments do not make an identifier unparseable",
    "no_address_alias": "a scheme-qualified identifier ending in a 0x-address does not name that address",
}
_ABLATE: Set[str] = set()


def _on(name: str) -> bool:
    """True when the named rule is ENABLED (i.e. not ablated)."""
    return name not in _ABLATE


# ════════════════════════════════════════════════════════════════════════════════════════
# 1. Keccak-256 — core (round constants, rotation offsets, permutation, sponge) copied VERBATIM from
#    vendor/roberto_x402_eip712.py (Roberto Locatelli, Apache-2.0, x402-signature-vectors/lib/eip712.py
#    @ 985b46d, sha256 8f1ae285…804e608); the wrapper is renamed keccak256_pure and its EIP-712 section
#    is not copied. Keccak-256 (pad 0x01) ≠ SHA3-256 (pad 0x06): MANIFEST
#    "content_address": "keccak256(utf8(canonical(payload)))".
# ════════════════════════════════════════════════════════════════════════════════════════
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & _MASK & B[(x + 2) % 5][y])
        A[0][0] ^= _RC[rnd]
    return A


def keccak256_pure(data: bytes) -> bytes:
    """Keccak-256 originale (padding 0x01), quello usato da Ethereum — non SHA3-256 (0x06)."""
    rate = 136
    A = [[0] * 5 for _ in range(5)]
    m = bytearray(data)
    m.append(0x01)                                   # padding Keccak, NON 0x06
    while len(m) % rate != 0:
        m.append(0x00)
    m[-1] |= 0x80
    for off in range(0, len(m), rate):
        blocco = m[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blocco[i * 8:(i + 1) * 8], "little")
        A = _keccak_f(A)
    out = b""
    while len(out) < 32:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += A[x][y].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            A = _keccak_f(A)
    return bytes(out[:32])


def keccak256(data: bytes) -> bytes:
    """The suite's digest function. Ablation `keccak_to_sha3` swaps in SHA3-256 (must break every digest vector)."""
    if _on("keccak_to_sha3"):
        return keccak256_pure(data)
    return hashlib.sha3_256(data).digest()


# ════════════════════════════════════════════════════════════════════════════════════════
# 2. JSON loading that preserves the TOKEN class of numbers and refuses duplicate names.
#    MANIFEST "canonicalization": "non-integer JSON number TOKENS rejected (number_domain_reject) —
#    the boundary is the token class, so a fraction or exponent form rejects even when
#    integer-valued (2.0, 1e2; p25/n35); duplicate object names rejected".
#    RFC 7493 §2.3: "Objects in I-JSON messages MUST NOT have members with duplicate names."
# ════════════════════════════════════════════════════════════════════════════════════════
class NumberToken(str):
    """A JSON number token that is NOT an integer token (has a fraction and/or exponent part).
    Python's json module calls parse_float for exactly that class (RFC 8259 §6: int [frac] [exp]),
    so the literal text is kept and the value is never collapsed (3.0 stays a non-integer token)."""


class DuplicateName(ValueError):
    pass


# MANIFEST v0.5.7 "canonicalization": duplicate names reject "where names compare after decoding, as UTF-16 code units,
# and only within one object, so a surrogate pair written with one half raw and the other escaped repeats the same pair
# written as two escapes (canonicalization_reject; p30/n41/n42/n93)". Python's json joins only an ESCAPED pair; a pair
# whose high half is a raw code unit (possible only inside a str such as `payload_text`, which the vector file carries
# as an escape) decodes to two code points. _join_pairs re-reads every string as UTF-16 code units, so both spellings
# become the same code point. READING (declared, "no vector pins whether a pair written half raw accepts where it
# repeats no name"): after the join such a pair is an ordinary paired code point, so it canonicalizes and accepts.
_RE_SURROGATE = re.compile("[\ud800-\udfff]")


def _join_pairs(t: str) -> str:
    if not _on("no_pair_join") or not _RE_SURROGATE.search(t):
        return t
    return t.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _pairs_no_dup(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        k = _join_pairs(k)
        if k in seen:
            raise DuplicateName(f"duplicate object name {k!r}")
        seen.add(k)
        out[k] = v
    return out


def _bad_constant(name):
    # RFC 8785 §3.2.2.3: "NaN and Infinity are not permitted in JSON"
    raise ValueError(f"non-JSON constant {name}")


def _join_values(x: Any) -> Any:
    """Iterative walk (no recursion limit beyond the parser's own): joins half-raw pairs in string VALUES."""
    if isinstance(x, str):
        return _join_pairs(x)
    stack = [x]
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            for k, v in c.items():
                if isinstance(v, str) and not isinstance(v, NumberToken):
                    c[k] = _join_pairs(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(c, list):
            for i, v in enumerate(c):
                if isinstance(v, str) and not isinstance(v, NumberToken):
                    c[i] = _join_pairs(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
    return x


def load_json(text: str) -> Any:
    v = json.loads(text, parse_float=NumberToken, parse_constant=_bad_constant,
                   object_pairs_hook=_pairs_no_dup)
    if _RE_SURROGATE.search(text):    # a split pair needs a raw surrogate code unit in the text itself
        v = _join_values(v)
    return v


def lone_surrogate(x: Any) -> Optional[str]:
    """The first string (name or value) holding a surrogate that is not half of a pair, or None. Iterative.
    MANIFEST v0.5.7 "canonicalization": "a name or string value containing a surrogate that is not half of a pair is
    outside I-JSON (RFC 7493 section 2.1) and has no canonical form (RFC 8785 section 3.2.2.2)"."""
    stack = [x]
    while stack:
        c = stack.pop()
        if isinstance(c, str) and not isinstance(c, NumberToken):
            if _RE_SURROGATE.search(c):
                return c
        elif isinstance(c, dict):
            for k, v in c.items():
                if isinstance(k, str) and _RE_SURROGATE.search(k):
                    return k
                stack.append(v)
        elif isinstance(c, list):
            stack.extend(c)
    return None


def is_int(v: Any) -> bool:
    """An integer TOKEN: Python int that is neither bool nor a NumberToken."""
    return isinstance(v, int) and not isinstance(v, bool)


def is_text(v: Any) -> bool:
    """A JSON STRING. NumberToken subclasses str only to keep a non-integer number token's text; the JSON value 1.5 is
    a number, not a string (until 2026-10-12, review: `transaction: 1.5` committed a settlement and `deliverable_bytes:
    1.5` was hashed as the text "1.5")."""
    return isinstance(v, str) and not isinstance(v, NumberToken)


# ════════════════════════════════════════════════════════════════════════════════════════
# 3. JCS — RFC 8785 canonical bytes, restricted to the I-JSON integer domain of this suite.
#    Written from the RFC text; NOT copied from any engine. (vendor/roberto_omega_evidence_aat.py
#    was available and consulted for its UTF-16 key sort idea, but this is a fresh implementation.)
# ════════════════════════════════════════════════════════════════════════════════════════
I_JSON_MAX = 2 ** 53 - 1   # RFC 7493 §2.2: exact integers only within [-(2**53)+1, (2**53)-1]


def _jcs_string(s: str) -> str:
    # RFC 8785 §3.2.2.2: enclose in double quotes; U+0000–U+001F "MUST be serialized using lowercase
    # hexadecimal Unicode notation (\uhhhh) unless it is in the set of predefined JSON control
    # characters U+0008, U+0009, U+000A, U+000C, or U+000D, which MUST be serialized as \b, \t, \n,
    # \f, and \r"; the quotation mark and reverse solidus are escaped as \" and \\; everything else
    # (including U+007F and non-ASCII) is emitted literally.
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    # RFC 8785 §3.2.3: "Property name strings to be sorted are formatted as arrays of UTF-16 code
    # units" compared as unsigned integers, lexicographically. Big-endian UTF-16 bytes compared
    # bytewise realise exactly that order (a surrogate pair 0xD800.. sorts below U+E000..U+FFFF).
    return k.encode("utf-16-be", "surrogatepass")


def _jcs(x: Any, depth: int) -> str:
    if depth > 512:
        raise Reject(R_CANON, "nesting deeper than 512")
    if x is None:
        return "null"                                 # RFC 8785 §3.2.2.1 literals
    if x is True:
        return "true"
    if x is False:
        return "false"
    if isinstance(x, NumberToken):
        if _on("no_number_domain"):
            raise Reject(R_NUMBER, f"non-integer number token {str(x)!r} in the digest domain")
        return str(x)                                 # ablated: emit the token as-is
    if isinstance(x, int):
        if abs(x) > I_JSON_MAX and _on("no_number_domain"):
            raise Reject(R_NUMBER, f"integer {x} outside the I-JSON exact range |n| <= 2^53-1")
        return str(x)                                 # ES6 Number::toString of an integer is its decimal digits
    if isinstance(x, float):                          # only reachable if a caller bypasses load_json
        if _on("no_number_domain"):
            raise Reject(R_NUMBER, "non-integer number (float) in the digest domain")
        return repr(x)
    if isinstance(x, str):
        return _jcs_string(x)
    if isinstance(x, list):
        return "[" + ",".join(_jcs(i, depth + 1) for i in x) + "]"
    if isinstance(x, dict):
        for k in x:
            if not isinstance(k, str):
                raise Reject(R_CANON, "object name is not a string")
        keys = sorted(x.keys(), key=_utf16_key) if _on("codepoint_key_order") else sorted(x.keys())
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(x[k], depth + 1) for k in keys) + "}"
    raise Reject(R_CANON, f"unsupported JSON value type {type(x).__name__}")


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical UTF-8 bytes (no whitespace, §3.2.1). Raises Reject on domain violations."""
    try:
        return _jcs(obj, 0).encode("utf-8")           # RFC 8785 §3.2 output is UTF-8
    except UnicodeEncodeError:
        # RFC 7493 §2.1: strings "MUST NOT include code points that identify Surrogates"
        raise Reject(R_CANON, "lone surrogate is not valid I-JSON / not UTF-8 encodable")


def content_address(payload: Any) -> bytes:
    """MANIFEST "content_address": "keccak256(utf8(canonical(payload)))"."""
    return keccak256(jcs(payload))


# ════════════════════════════════════════════════════════════════════════════════════════
# 4. Small parsers with fail-closed behaviour.
# ════════════════════════════════════════════════════════════════════════════════════════
_RE_HEX32 = re.compile(r"0x[0-9a-f]{64}\Z")

# MANIFEST v0.5.7 "identifier_normalization" (1): "Strip leading and trailing characters with the Unicode White_Space
# property, U+0009-U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F and U+3000,
# and no others (n13/p33); a character without the property is not stripped, so an identifier padded with U+FEFF (a
# format character) or U+001C (a control character without the property) does not parse (n52/n53)".
# Python's str.strip() is NOT this set: it also strips U+001C-U+001F (str.isspace() is True for them).
WHITE_SPACE = ("\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
               + "".join(chr(c) for c in range(0x2000, 0x200B)) + "\u2028\u2029\u202f\u205f\u3000")


def ws_strip(t: str) -> str:
    if not _on("python_whitespace_strip"):
        return t.strip()
    return t.strip(WHITE_SPACE)


def parse_digest(v: Any) -> Optional[bytes]:
    """A 32-byte digest written as 0x + 64 hex digits, or None. MANIFEST v0.5.7 "identifier_normalization", last
    sentence: "Digests compare after the same whitespace strip, lowercased". READING (declared): the lowercase applies
    to the whole stripped string, so a `0X` prefix reads as `0x` (no vector pins a digest written with `0X`)."""
    if not isinstance(v, str):
        return None
    t = ws_strip(v).lower()
    if not _RE_HEX32.match(t):
        return None
    return bytes.fromhex(t[2:])


def hex32(v: Any, reason: str, what: str) -> bytes:
    """parse_digest, failing closed with the kind's reason."""
    if not isinstance(v, str):
        raise Reject(reason, f"{what} is not a string")
    d = parse_digest(v)
    if d is None:
        raise Reject(reason, f"{what} is not a 0x-prefixed 32-byte hex digest")
    return d


def need_dict(v: Any, reason: str, what: str) -> Dict[str, Any]:
    if not isinstance(v, dict):
        raise Reject(reason, f"{what} is not a JSON object")
    return v


def need_list(v: Any, reason: str, what: str) -> List[Any]:
    if not isinstance(v, list):
        raise Reject(reason, f"{what} is not a JSON array")
    return v


# ════════════════════════════════════════════════════════════════════════════════════════
# 5. Criteria, one per manifest `kind`. Each returns a detail string or raises Reject.
# ════════════════════════════════════════════════════════════════════════════════════════
def k_digest_recompute(inp: Dict[str, Any]) -> str:
    # MANIFEST "content_address": "keccak256(utf8(canonical(payload)))"; reason for a mismatch is
    # `recompute_mismatch` (n1); a number outside the domain rejects earlier as number_domain_reject (n11).
    if "payload" not in inp:
        raise Reject(R_RECOMPUTE, "no payload presented")
    got = content_address(inp["payload"])
    exp = hex32(inp.get("expected_digest"), R_RECOMPUTE, "expected_digest")
    if got != exp:
        raise Reject(R_RECOMPUTE, f"recomputed 0x{got.hex()} != expected 0x{exp.hex()}")
    return f"digest recomputes: 0x{got.hex()}"


def k_canonical_bytes(inp: Dict[str, Any]) -> str:
    # MANIFEST "canonicalization": "RFC 8785 (JCS); vector domain is I-JSON with integer numerics";
    # p25/n35 present the payload as raw text (`payload_text`) so the TOKEN class is observable.
    if "payload_text" in inp:
        if not is_text(inp["payload_text"]):
            raise Reject(R_CANON, "payload_text is not a string")
        try:
            payload = load_json(inp["payload_text"])
        except DuplicateName as e:
            raise Reject(R_CANON, str(e))
        except ValueError as e:
            raise Reject(R_CANON, f"payload_text is not parseable JSON: {e}")
        # MANIFEST v0.5.7 "canonicalization": a payload_text's "shape, an unpaired surrogate included, is decided before
        # its number tokens (n92)". For a `payload` given as an object (not as text) no clause orders the two faults:
        # there the number domain is met first while serializing (K2 below), and that order is a reading, not pinned.
        lone = lone_surrogate(payload) if _on("no_surrogate_first") else None
        if lone is not None:
            raise Reject(R_CANON, f"payload_text holds an unpaired surrogate in {lone!r}: no canonical form (n81-n84, n92)")
    elif "payload" in inp:
        payload = inp["payload"]
    else:
        raise Reject(R_CANON, "no payload presented")
    # K2 (2026-09-29, clause-driven): the payload's number domain is evaluated BEFORE anything about the
    # claimed bytes. MANIFEST `canonicalization`: "non-integer JSON number TOKENS rejected (number_domain_reject)";
    # x402 compliance_fields §Canonicalization: "A record containing a non-integer JSON number anywhere is
    # non-conformant. Verifiers MUST reject it before computing recordDigest"; declared order in REPORT §3:
    # number domain → canonicalization → digest.
    got = jcs(payload)
    claimed = inp.get("claimed_canonical")
    if not isinstance(claimed, str):
        raise Reject(R_CANON, "claimed_canonical is not a string")
    if got != claimed.encode("utf-8"):
        raise Reject(R_CANON, f"canonical bytes {got.decode('utf-8')!r} != claimed {claimed!r}")
    return f"canonical bytes match ({len(got)} bytes)"


def chain_link(artifact: bytes, prev: Optional[bytes], seq: int) -> bytes:
    # MANIFEST "chain_link": "keccak256(artifact_digest || prev_digest || seq_uint64_be) — wire form of a
    # genesis predecessor is null; 32 zero bytes is the hashing-time substitution for null".
    return keccak256(artifact + (prev if prev is not None else bytes(32)) + seq.to_bytes(8, "big"))


def k_chain_link(inp: Dict[str, Any]) -> str:
    art = hex32(inp.get("artifact_digest"), R_CONTINUITY, "artifact_digest")
    prev = None if inp.get("prev_digest") is None else hex32(inp["prev_digest"], R_CONTINUITY, "prev_digest")
    seq = inp.get("seq")
    # MANIFEST v0.5.7 "chain_link": "seq is an integer TOKEN in [1, 2^53-1] ... A seq of 0 (n75), a seq past 2^53-1
    # (n76), or a seq that is not an integer token (a fraction form, n77; an exponent form, n97; a string, n87; a
    # boolean, n88; null, n89) rejects with continuity_reject; p4 accepts the lower bound and p43 the upper".
    lo, hi = (1, I_JSON_MAX) if _on("no_seq_domain") else (0, 2 ** 64 - 1)
    if not is_int(seq) or not (lo <= seq <= hi):
        raise Reject(R_CONTINUITY, f"seq {seq!r} is not an integer token in [{lo}, {hi}]")
    got = chain_link(art, prev, seq)
    exp = hex32(inp.get("expected_link"), R_CONTINUITY, "expected_link")
    if got != exp:
        raise Reject(R_CONTINUITY, f"link recomputes to 0x{got.hex()}, claimed 0x{exp.hex()} (prev/seq do not bind)")
    return f"link recomputes: 0x{got.hex()}"


def k_anchor_relation(inp: Dict[str, Any]) -> str:
    # MANIFEST "anchor_relation": "anchored_digest = sha256(subject_digest_bytes)"; reason `existence_reject` (n5).
    subj = hex32(inp.get("subject_digest"), R_EXISTENCE, "subject_digest")
    anch = hex32(inp.get("anchored_digest"), R_EXISTENCE, "anchored_digest")
    got = hashlib.sha256(subj).digest()
    if got != anch:
        raise Reject(R_EXISTENCE, f"sha256(subject) = 0x{got.hex()} does not equal the anchored digest")
    return "anchored digest binds the subject (existence of the anchor itself NOT checked: structural profile)"


def _chain_set_links(inp: Dict[str, Any]) -> Tuple[int, List[bytes]]:
    """Shared by chain_set and chain_commitment. Returns (head.seq, recomputed links seq 1..head.seq).

    MANIFEST "chain_set": "records chain raw artifact digests via prev pointers (genesis prev = null);
    head.digest equals the final record's artifact digest; completeness = every seq 1..head.seq present
    exactly once (a second record at an occupied seq rejects: n39); where a record presents a link, it
    must recompute as keccak256(artifact || prev || seq_be8)".
    MANIFEST "witnessed_inclusion": witness material is "permitted and NOT load-bearing" — never read.
    MANIFEST "duplicate_sequence": "the issuer's `attestations` are permitted and not read".
    n38: "a sequence number is an integer TOKEN" — a non-integer token rejects as completeness_reject.
    """
    head = need_dict(inp.get("head"), R_COMPLETENESS, "head")
    hseq = head.get("seq")
    if not is_int(hseq) or hseq < 1:
        raise Reject(R_COMPLETENESS, f"head.seq {hseq!r} is not a positive integer token")
    hdig = hex32(head.get("digest"), R_CONTINUITY, "head.digest")
    records = need_list(inp.get("records"), R_COMPLETENESS, "records")
    by_seq: Dict[int, Dict[str, Any]] = {}
    duplicates: List[int] = []
    for r in records:
        r = need_dict(r, R_COMPLETENESS, "record")
        s = r.get("seq")
        if not is_int(s):
            raise Reject(R_COMPLETENESS, f"record seq {s!r} is not an integer token")
        if s in by_seq:
            duplicates.append(s)
        else:
            by_seq[s] = r
    beyond = sorted(s for s in by_seq if s < 1 or s > hseq)
    if _on("no_seq_completeness"):
        if duplicates:
            raise Reject(R_COMPLETENESS, f"duplicate seq {sorted(set(duplicates))} under committed head")
        # REVIEW FIX F2 (2026-09-29): never materialize range(1, head.seq + 1) — a presented head.seq of 10^12 used to
        # exhaust memory (OOM kill, no verdict). The count of in-range records decides; the list is only a message.
        in_range = sum(1 for s in by_seq if 1 <= s <= hseq)
        if in_range < hseq:
            scan_to = hseq if hseq <= 100_000 else len(by_seq) + 1
            missing = [s for s in range(1, scan_to + 1) if s not in by_seq]
            raise Reject(R_COMPLETENESS, f"missing seq {missing} under committed head")
        if beyond:
            raise Reject(R_COMPLETENESS, f"seq {beyond} outside 1..head.seq")
    present = sorted(s for s in by_seq if 1 <= s <= hseq)
    if not present:
        raise Reject(R_COMPLETENESS, "no record under the committed head")
    last_art = hex32(by_seq[present[-1]].get("artifact_digest"), R_CONTINUITY, "artifact_digest")
    if present[-1] == hseq and last_art != hdig:
        raise Reject(R_CONTINUITY, "head.digest does not equal the final record's artifact digest")
    links: List[bytes] = []
    prev_art: Optional[bytes] = None
    for s in present:
        r = by_seq[s]
        art = hex32(r.get("artifact_digest"), R_CONTINUITY, f"artifact_digest at seq {s}")
        if "prev_digest" not in r:
            raise Reject(R_CONTINUITY, f"record at seq {s} presents no prev_digest")
        pd = r["prev_digest"]
        if s == 1:
            if pd is not None:
                raise Reject(R_CONTINUITY, "genesis record (seq 1) must carry a null prev_digest")
        else:
            if pd is None or hex32(pd, R_CONTINUITY, f"prev_digest at seq {s}") != prev_art:
                raise Reject(R_CONTINUITY, f"prev_digest at seq {s} is not the previous record's artifact digest")
        link = chain_link(art, prev_art, s)
        if "link" in r and _on("no_link_recompute"):
            claimed = hex32(r["link"], R_CONTINUITY, f"link at seq {s}")
            if claimed != link:
                raise Reject(R_CONTINUITY, f"link at seq {s} does not recompute as keccak256(artifact || prev || seq_be8)")
        links.append(link)
        prev_art = art
    return hseq, links


def k_chain_set(inp: Dict[str, Any]) -> str:
    hseq, links = _chain_set_links(inp)
    return f"seq 1..{hseq} present exactly once, prevs continuous, {len(links)} links recompute, head binds final record"


ACC_SEED = b"tersign-chain-commitment-v1"


def k_chain_commitment(inp: Dict[str, Any]) -> str:
    # MANIFEST "chain_commitment": "acc_0 = keccak256(utf8('tersign-chain-commitment-v1')); acc_n =
    # keccak256(acc_{n-1} || link_n) over the recomputed links of a chain_set-valid set; head.acc must
    # equal acc_{head.seq}"; "a prefix that passes the structural chain_set predicate but was not the
    # one the commitment was built over rejects here" (reason continuity_reject: n36/n37/n40).
    hseq, links = _chain_set_links(inp)
    head = inp["head"]
    if "acc" not in head:
        raise Reject(R_CONTINUITY, "head.acc absent: no commitment over the links to check (fails closed)")
    claimed = hex32(head["acc"], R_CONTINUITY, "head.acc")
    acc = keccak256(ACC_SEED)
    for link in links:
        acc = keccak256(acc + link)
    if _on("no_accumulator") and acc != claimed:
        raise Reject(R_CONTINUITY, f"accumulator mismatch: fold over {len(links)} links = 0x{acc.hex()}, head.acc = 0x{claimed.hex()}")
    return f"head.acc equals the fold over all {hseq} recomputed links"


# x402 compliance-fields extension (PR #2853, specs/extensions/compliance_fields.md @ b8a81c0),
# §"Independence and economic phase (normative)": "Payment flows decompose into distinct phases —
# funding, delivery, settlement, and where applicable refund or reversal"; "Verifiers MUST NOT treat a
# record evidencing one economic phase as evidence of any later phase". n18: "A phase token outside the
# declared vocabulary … must not verify as ANY phase".
PHASES = ("funding", "delivery", "settlement", "refund", "reversal")


def k_phase_claim(inp: Dict[str, Any]) -> str:
    rec = need_dict(inp.get("record"), R_PHASE, "record")
    phase = rec.get("economic_phase")
    presented = inp.get("presented_as")
    if not _on("phase_any"):
        return "phase check ablated"
    if not isinstance(phase, str) or phase not in PHASES:
        raise Reject(R_PHASE, f"economic_phase {phase!r} is outside the declared vocabulary {list(PHASES)}")
    if not isinstance(presented, str) or presented not in PHASES:
        raise Reject(R_PHASE, f"presented_as {presented!r} is outside the declared vocabulary")
    # READING (stricter than the spec's "any later phase"): a record verifies only as evidence of ITS OWN
    # phase. Declared choice, see README.md «Readings where the manifest is silent» (economic phase vocabulary).
    if phase != presented:
        raise Reject(R_PHASE, f"a {phase}-phase record presented as {presented} evidence")
    return f"record phase {phase} == presented phase"


# ── identities ─────────────────────────────────────────────────────────────────────────
# MANIFEST v0.5.7 "identifier_normalization" (quoted in full in README.md): one rule for every identifier, in `parties`
# and in an attestation's `by`, folding toward SAME PARTY; an identifier the rule cannot decide does not parse and
# fails the claim closed. The steps below are numbered as in the manifest. (v0.5.3 read scheme-qualified identifiers
# case-significant and with one colon only; v0.5.7 replaced that text, and p31/p37/p38/n45 pin the new one.)
_RE_ADDR = re.compile(r"0[xX][0-9a-fA-F]{40}\Z")
_RE_ADDR_LOWER = re.compile(r"0x[0-9a-f]{40}\Z")
_RE_SCHEME_ANY = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:[\x21-\x7e]+\Z")
_RE_SCHEME_LOWER = re.compile(r"[a-z][a-z0-9+.\-]*:[\x21-\x7e]+\Z")
_RE_TRIPLET = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _decode_unreserved(t: str) -> str:
    # (3) "Every percent-encoded triplet (either hex case) that encodes an unreserved character (A-Z a-z 0-9 `-` `.`
    # `_` `~`) is decoded, in one left-to-right pass that is never repeated (RFC 3986 sections 6.2.2.2 and 2.4)".
    # re.sub scans left to right over the ORIGINAL text and never rescans what it produced (n56: "%%37%34" -> "%74").
    def one(m):
        c = chr(int(m.group(1), 16))
        return c if c in _UNRESERVED else m.group(0)
    return _RE_TRIPLET.sub(one, t)


def normalize_identity(v: Any) -> Optional[str]:
    """Returns the comparison key, or None when the identifier does not parse (fail closed).
    The key is "addr:0x<40 lowercase hex>" when the identifier names a 0x-address (step 5), else "uri:<normalized>"."""
    if not isinstance(v, str):
        return None
    if not _on("no_identity_normalization"):
        return v if v else None
    t = ws_strip(v)                                    # (1) White_Space only, U+FEFF / U+001C are not stripped
    if _RE_ADDR.match(t):                              # (2) 0x or 0X, 40 hex digits either case, lowercased with
        return "addr:" + t.lower()                     #     its prefix
    if not _RE_SCHEME_ANY.match(t):                    # (3) letter, then letters/digits/+/./-, one colon, then one or
        return None                                    #     more printable non-space ASCII; else (4) does not parse
    if _on("no_percent_rule"):
        t = _decode_unreserved(t)
        if "%" in t:                                   # "if any `%` remains, the identifier does not parse"
            return None
    if _on("no_dot_segment_rule"):
        if "?" in t:                                   # "If it contains `?` (a query component) ... it does not parse"
            return None
        path = t.split(":", 1)[1].split("#", 1)[0]     # "its path, from the colon to the first `?` or `#`"
        if any(seg in (".", "..") for seg in path.split("/")):
            return None                                # "has a segment that is exactly `.` or `..`"
    t = t.lower().rstrip("/.#")                        # "The result is lowercased, the scheme included ... and every
    if "#" in t:                                       #  trailing `/`, `.` and `#` is removed"; "if a `#` remains
        return None                                    #  (a fragment with content), it does not parse"
    if not _RE_SCHEME_LOWER.match(t):                  # "it must still match the grammar with a lowercase scheme and a
        return None                                    #  non-empty path (n51)"
    if _on("no_address_alias"):
        last = t.rsplit(":", 1)[1]                     # (5) "a scheme-qualified identifier whose final colon-separated
        if _RE_ADDR_LOWER.match(last):                 #  component is a 0x-address ... names that address, whatever
            return "addr:" + last                      #  the scheme ... on either side and whatever the chain reference"
    return "uri:" + t


CLAIM_ASSERTING = ("independent",)
CLAIM_SILENT = ("none", "issuer_attested")   # p9: "claims nothing about independence"; p11: "asserts nothing about independence"
DERIVABLE_FIELDS = ("settlement_result", "deliverable_bytes", "deliverable_digest")


def derive_commitments(inp: Dict[str, Any]) -> Optional[Set[str]]:
    """MANIFEST "commitment_derivation" (v0.5.3 text; v0.5.7 adds the whitespace strip, see below): "`settlement` when
    settlement_result.success is true and transaction is a non-empty string; `network` when settlement_result.network
    is a non-empty string;
    `delivery` when keccak256(utf8(deliverable_bytes)) == deliverable_digest. A record presenting none of
    these fields has no evaluable commitments (…); a record presenting them and committing to none has
    an EMPTY commitment set". Returns None when unevaluable."""
    if not any(k in inp for k in DERIVABLE_FIELDS):
        return None
    c: Set[str] = set()
    sr = inp.get("settlement_result")
    if isinstance(sr, dict):
        # v0.5.7: "transaction is a string that is not empty after the whitespace strip of identifier_normalization
        # (a result with no transaction member commits to no settlement: n104/p54 ...)"; network: "such a string".
        tx = sr.get("transaction")
        if sr.get("success") is True and is_text(tx) and ws_strip(tx) != "":
            c.add("settlement")
        net = sr.get("network")
        if is_text(net) and ws_strip(net) != "":
            c.add("network")
    if "deliverable_bytes" in inp and "deliverable_digest" in inp:
        b, d = inp["deliverable_bytes"], parse_digest(inp["deliverable_digest"])
        if is_text(b) and d is not None:
            try:
                bb = b.encode("utf-8")
            except UnicodeEncodeError:
                # no clause or vector decides this case: fail closed with the criterion's reason (until 2026-10-12 it
                # surfaced as input_reject "internal error UnicodeEncodeError")
                raise Reject(R_INDEPENDENCE, "deliverable_bytes holds an unpaired surrogate: no utf8 bytes to digest")
            if keccak256(bb) == d:
                c.add("delivery")
    return c


def k_independence_claim(inp: Dict[str, Any]) -> str:
    # p9: "the criterion disqualifies unsupported CLAIMS"; n8/n9: "A conformant verifier fails closed on a
    # claim it cannot interpret"; p10: the claim may be a SET (list).
    # K1 (2026-09-29, clause-driven): an ABSENT `claimed` field is silence, not an uninterpretable claim.
    # p9: "A record that claims nothing about independence … Silence is a valid state: the criterion
    # disqualifies unsupported CLAIMS"; n8/n9 fail closed on a claim that is PRESENT and cannot be read.
    # MANIFEST `identifier_normalization` pins fail-closed for identifiers, not for a missing claim.
    if "claimed" not in inp:
        return "no `claimed` field: nothing is claimed about independence (silence, p9)"
    claimed = inp["claimed"]
    tokens = [claimed] if isinstance(claimed, str) else claimed
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        raise Reject(R_INDEPENDENCE, "claim is neither a string nor a list of strings")
    unknown = [t for t in tokens if t not in CLAIM_ASSERTING and t not in CLAIM_SILENT]
    if unknown and _on("no_unknown_claim_reject"):
        raise Reject(R_INDEPENDENCE, f"claim member(s) {unknown} cannot be interpreted (fails closed)")
    if not any(t in CLAIM_ASSERTING for t in tokens):
        return "no independence claimed (silence): nothing to disqualify"
    # ── an independence claim is asserted ──
    # n22/n23/n24: "The declared field's PRESENCE is now the reject, whatever it holds" (also explicit null,
    # also without `covers`).
    if "record_commits" in inp and _on("no_record_commits_presence") and _on("declared_commits"):
        raise Reject(R_INDEPENDENCE, "declared `record_commits` present: a scope a record asserts about itself is not evidence of that scope")
    # n7: "attested only by parties … an evaluator MUST NOT treat issuer-attested composition as a neutral
    # finding"; p8: "holds when at least one attestation comes from outside the transaction's parties".
    parties = need_list(inp.get("parties"), R_INDEPENDENCE, "parties")
    party_keys = set()
    for p in parties:
        k = normalize_identity(p)
        if k is None:
            raise Reject(R_INDEPENDENCE, f"party identifier {p!r} does not parse (fails closed)")
        party_keys.add(k)
    if "attestations" not in inp:
        raise Reject(R_INDEPENDENCE, "independence claimed with no attestations to evaluate (n15)")
    atts = need_list(inp["attestations"], R_INDEPENDENCE, "attestations")
    outside = 0
    for a in atts:
        if not isinstance(a, dict) or "by" not in a:
            raise Reject(R_INDEPENDENCE, "attestation is not an object naming its attestor (n16)")
        k = normalize_identity(a["by"])
        if k is None:
            raise Reject(R_INDEPENDENCE, f"attestor identifier {a['by']!r} does not parse (n14, fails closed)")
        if k not in party_keys:
            outside += 1
    if outside == 0 and _on("no_independence"):
        raise Reject(R_INDEPENDENCE, "attested only by parties to the transaction: structure, not independence")
    # ── commitment scope ── MANIFEST "commitment_derivation": "an independence claim reaches exactly as
    # far as the record's DERIVED commitments, never a declared list".
    if "covers" in inp:
        covers = need_list(inp["covers"], R_INDEPENDENCE, "covers")
        if not all(isinstance(c, str) for c in covers):
            raise Reject(R_INDEPENDENCE, "covers must be a list of strings")
        if not _on("declared_commits") and isinstance(inp.get("record_commits"), list):
            commitments: Optional[Set[str]] = set(inp["record_commits"])   # ablation: the n22 override bug
        else:
            commitments = derive_commitments(inp)
        if commitments is None:
            raise Reject(R_INDEPENDENCE, f"claim covers {covers} but commitments are not evaluable (no settlement_result / deliverable fields)")
        over = [c for c in covers if c not in commitments]
        if over:
            raise Reject(R_INDEPENDENCE, f"claim covers {over} — fact(s) the record does not commit to (derived commitments: {sorted(commitments)})")
        return f"{outside} non-party attestor(s); claim covers {covers} within derived commitments {sorted(commitments)}"
    return f"{outside} non-party attestor(s); no scope asserted"


def _bound_digest(obj: Any, reason: str, what: str) -> bytes:
    """keccak256 of the canonical bytes of an object a criterion BINDS. MANIFEST v0.5.7
    "canonicalization": an unpaired surrogate has no canonical form, "and a criterion that digests an object rejects it
    with its own reason (binding_reject for an offer, n94, and for decision evidence, n95; boundary_reject for a
    boundary prefix, n96)". READING (declared): every canonicalization_reject met while digesting the bound object
    (an unpaired surrogate, or nesting deeper than 512) takes the criterion's reason; a non-integer number token keeps
    number_domain_reject, since no clause or vector moves it."""
    try:
        cb = jcs(obj)
    except Reject as r:
        if r.reason == R_CANON and _on("no_own_reason"):
            raise Reject(reason, f"{what} has no canonical form ({r.detail}): no digest of it exists to bind")
        raise
    return keccak256(cb)


def k_offer_binding(inp: Dict[str, Any]) -> str:
    # MANIFEST "offer_binding": "receipt.offerDigest = keccak256(utf8(canonical(offer))); a receipt that
    # commits to no offer digest cannot bind terms and fails closed" (reason binding_reject: n19).
    offer = need_dict(inp.get("offer"), R_BINDING, "offer")
    receipt = need_dict(inp.get("receipt"), R_BINDING, "receipt")
    if "offerDigest" not in receipt:
        raise Reject(R_BINDING, "receipt commits to no offerDigest: terms cannot be bound (fails closed)")
    claimed = hex32(receipt["offerDigest"], R_BINDING, "receipt.offerDigest")
    got = _bound_digest(offer, R_BINDING, "offer")
    if got != claimed:
        raise Reject(R_BINDING, f"keccak256(canonical(offer)) = 0x{got.hex()} != receipt.offerDigest (terms substituted)")
    return "receipt.offerDigest binds the presented offer"


def k_decision_evidence_binding(inp: Dict[str, Any]) -> str:
    # MANIFEST "decision_evidence_binding": "record.decisionEvidenceDigest = keccak256(utf8(canonical(
    # decision_evidence))); a record presented as authority-decision evidence must bind the exact object"
    # (match / missing / mismatch; reason binding_reject: n27 missing, n28 mismatch).
    rec = need_dict(inp.get("record"), R_BINDING, "record")
    ev = need_dict(inp.get("decision_evidence"), R_BINDING, "decision_evidence")
    if "decisionEvidenceDigest" not in rec:
        raise Reject(R_BINDING, "record carries no decisionEvidenceDigest: the presented reduction is unbound")
    claimed = hex32(rec["decisionEvidenceDigest"], R_BINDING, "record.decisionEvidenceDigest")
    got = _bound_digest(ev, R_BINDING, "decision_evidence")
    if got != claimed:
        raise Reject(R_BINDING, f"keccak256(canonical(decision_evidence)) = 0x{got.hex()} != committed digest (substitution)")
    return "record binds the exact decision-evidence object"


# The manifest has NO top-level boundary rule; the criterion is taken from the vectors' descriptions and
# MCP #3004 (@navigatorbuilds 2026-08-08: "a boundary event binds (a) the digest of the prefix it extends
# and (b) its own position in that prefix's continuation"; @Tetsurohhori 2026-08-09: "Unattested is now a
# third outcome … offline snapshots cannot be distinguished from verified streams"). p20/n29: the prefix
# digest stays under the suite IN FORCE WHEN THE PREFIX WAS WRITTEN (keccak256-jcs), never re-digested.
BOUNDARY_EVENTS = {"witness_ref_introduced": "witness-ref-v1", "digest_suite_transition": "suite-transition-v1"}
PRIOR_SUITE = "keccak256-jcs"


def k_boundary_binding(inp: Dict[str, Any]) -> str:
    prefix = need_list(inp.get("prefix"), R_BOUNDARY, "prefix")
    ev = need_dict(inp.get("boundary_event"), R_BOUNDARY, "boundary_event")
    event = ev.get("event")
    if not isinstance(event, str) or event not in BOUNDARY_EVENTS:   # REVIEW FIX F4: a list/dict event is a boundary_reject, not an internal TypeError
        raise Reject(R_BOUNDARY, f"boundary event {event!r} is not interpretable (fails closed)")
    if ev.get("ruleVersion") != BOUNDARY_EVENTS[event]:
        raise Reject(R_BOUNDARY, f"ruleVersion {ev.get('ruleVersion')!r} unknown for {event}")
    if event == "digest_suite_transition":
        if ev.get("fromSuite") != PRIOR_SUITE:
            raise Reject(R_BOUNDARY, f"fromSuite {ev.get('fromSuite')!r} is not the suite this prefix was written under")
        if not isinstance(ev.get("toSuite"), str) or not ev["toSuite"]:
            raise Reject(R_BOUNDARY, "toSuite absent")
    # (a) prefix digest — READING: keccak256(utf8(canonical(prefix))) over the prefix as a JSON array,
    # under the PRIOR suite whatever `toSuite` says (calibrated on p18's pinned digest, see report).
    claimed = hex32(ev.get("prefixDigest"), R_BOUNDARY, "prefixDigest")
    got = _bound_digest(prefix, R_BOUNDARY, "prefix")
    if got != claimed:
        raise Reject(R_BOUNDARY, f"prefixDigest does not bind the prefix under {PRIOR_SUITE} (recomputed 0x{got.hex()}) — re-digested or forged history")
    # (b) position — READING: the event sits at the continuation point, position == number of prefix events.
    if _on("no_position_binding"):
        pos = ev.get("position")
        if not is_int(pos):
            raise Reject(R_BOUNDARY, "boundary event binds no position in the prefix's continuation (n25)")
        if pos != len(prefix):
            raise Reject(R_BOUNDARY, f"position {pos} is not the continuation point of a {len(prefix)}-event prefix")
    # (c) coverage within attestation — n26: "unattested must be its own outcome rather than a pass".
    apl = ev.get("attestedPrefixLength")
    if not is_int(apl) or apl < 0 or apl > len(prefix):
        raise Reject(R_BOUNDARY, f"attestedPrefixLength {apl!r} absent or outside 0..{len(prefix)}")
    # K3 (2026-09-29, clause-driven): p18 "the coverage IT CLAIMS is within the prefix its attestation actually
    # reaches" is conditional — with no `covered_through` there is no claimed coverage to compare. The reject on an
    # EMPTY attestation stays whatever is claimed: n26 "unattested must be its own outcome rather than a pass".
    ct = inp.get("covered_through")
    if "covered_through" in inp and (not is_int(ct) or ct < 0):
        raise Reject(R_BOUNDARY, "covered_through present but not a non-negative integer token")
    if _on("no_coverage_bound"):
        if apl == 0:
            raise Reject(R_BOUNDARY, "unattested prefix (attestedPrefixLength = 0) is its own outcome, not a pass (n26)")
        if ct is not None and ct > apl:
            raise Reject(R_BOUNDARY, f"coverage claimed through {ct} while the attestation reaches only {apl} (downgrade)")
    cov = f"coverage {ct} <= attested {apl}" if ct is not None else f"no coverage claimed; attested {apl}"
    return f"prefixDigest binds {len(prefix)} events under {PRIOR_SUITE}; position {ev.get('position')}; {cov}"


KINDS = {
    "digest_recompute": k_digest_recompute,
    "canonical_bytes": k_canonical_bytes,
    "chain_link": k_chain_link,
    "anchor_relation": k_anchor_relation,
    "chain_set": k_chain_set,
    "chain_commitment": k_chain_commitment,
    "phase_claim": k_phase_claim,
    "independence_claim": k_independence_claim,
    "offer_binding": k_offer_binding,
    "decision_evidence_binding": k_decision_evidence_binding,
    "boundary_binding": k_boundary_binding,
}


# ════════════════════════════════════════════════════════════════════════════════════════
# 6. Verdict for one vector.
# ════════════════════════════════════════════════════════════════════════════════════════
# `input` members — CLOSED, FIXED lists (input schema 1, 2026-10-11; replaces the 2026-10-10 version that LEARNED the
# known members from the suite under verification, so a member planted in that suite's vectors became "known" and was
# never named). Nothing here is learned at run time; nothing here changes a verdict.
#
# The suite's manifest does not say what a verifier does with an `input` member it does not define. This verifier keeps
# the manifest's verdict (the kind functions ignore members they do not read) and REPORTS, per vector, two lists:
#   * `input_members_not_read`  — every member present that is NOT in _INPUT_READ[kind], the members this verifier's
#     kind function for `kind` actually reads (written from the functions above; a test checks it against the reads
#     the functions make on every suite vector and against the source). Includes members the 0.5.3 vectors carry and
#     the manifest permits without reading them (chain_set `witness`, `attestations`).
#   * `unknown_input_members`   — the subset that is ALSO absent from _INPUT_SUITE_053_NOT_READ[kind], the members the
#     69 vectors of suite 0.5.3 (upstream 0eda3038) carry and this verifier does not read, frozen here on 2026-10-11.
#     "Unknown" therefore means: neither read by this verifier nor present in the suite version it was written against.
# Paths are RFC 6901 JSON Pointers, relative to `input` for the two input lists ("/witness", "/records/1/x") and relative
# to the vector for `unknown_vector_members` ("/extra"); only the TOPMOST member outside a list
# is named (nothing below it is walked). Members under a CONTENT position (payload, offer, decision_evidence, prefix,
# payload_text) are hashed or parsed content, not input members, and are never walked. A LEAF is a member read as one
# value; whatever it holds is the verdict's business. A one-element Python list [S] means "a JSON array whose object
# elements follow S". An unknown `kind` has no list: the vector rejects as input_reject and its two input lists are empty
# (`unknown_vector_members` does not depend on the kind and is still reported).
INPUT_SCHEMA_VERSION = "1"
LEAF = "leaf"
CONTENT = "content"
_CHAIN_RECORD = {"seq": LEAF, "artifact_digest": LEAF, "prev_digest": LEAF, "link": LEAF}
_INPUT_READ: Dict[str, Dict[str, Any]] = {
    "digest_recompute": {"payload": CONTENT, "expected_digest": LEAF},
    "canonical_bytes": {"payload_text": CONTENT, "payload": CONTENT, "claimed_canonical": LEAF},
    "chain_link": {"artifact_digest": LEAF, "prev_digest": LEAF, "seq": LEAF, "expected_link": LEAF},
    "anchor_relation": {"subject_digest": LEAF, "anchored_digest": LEAF},
    "chain_set": {"head": {"seq": LEAF, "digest": LEAF}, "records": [_CHAIN_RECORD]},
    "chain_commitment": {"head": {"seq": LEAF, "digest": LEAF, "acc": LEAF}, "records": [_CHAIN_RECORD]},
    "phase_claim": {"record": {"economic_phase": LEAF}, "presented_as": LEAF},
    "independence_claim": {"claimed": LEAF, "record_commits": LEAF, "parties": LEAF, "attestations": [{"by": LEAF}],
                           "covers": LEAF, "settlement_result": {"success": LEAF, "transaction": LEAF, "network": LEAF},
                           "deliverable_bytes": LEAF, "deliverable_digest": LEAF},
    "offer_binding": {"offer": CONTENT, "receipt": {"offerDigest": LEAF}},
    "decision_evidence_binding": {"record": {"decisionEvidenceDigest": LEAF}, "decision_evidence": CONTENT},
    "boundary_binding": {"prefix": CONTENT, "covered_through": LEAF,
                         "boundary_event": {"event": LEAF, "ruleVersion": LEAF, "fromSuite": LEAF, "toSuite": LEAF,
                                            "prefixDigest": LEAF, "position": LEAF, "attestedPrefixLength": LEAF}},
}
_INPUT_SUITE_053_NOT_READ: Dict[str, Dict[str, Any]] = {
    # MANIFEST "witnessed_inclusion": witness material "is permitted and NOT load-bearing" (p24, n34);
    # MANIFEST "duplicate_sequence": "the issuer's `attestations` are permitted and not read" (p28, n39).
    "chain_set": {"witness": {"checkpoint": {"origin": LEAF, "tree_size": LEAF, "cosignatures": LEAF, "quorum": LEAF},
                              "inclusion": [{"seq": LEAF, "leaf_index": LEAF}]},
                  "attestations": [{"by": LEAF, "role": LEAF}]},
    # MANIFEST "commitment_derivation": "Who delivered is not read by the derivation"; `payTo` is named in "field_naming".
    "independence_claim": {"attestations": [{"role": LEAF}], "deliverable_signer": LEAF, "payTo": LEAF},
    "decision_evidence_binding": {"record": {"outcome": LEAF}},
    "phase_claim": {"record": {"amount": LEAF, "asset": LEAF, "deliverable_digest": LEAF}},
}
# Top-level vector members: the verifier reads `kind` and `input`; the 0.5.3 vectors also carry these (metadata).
_VECTOR_READ = ("kind", "input")
_VECTOR_SUITE_053_NOT_READ = ("id", "expect", "reason", "description", "provenance")


def _merge_schema(a: Any, b: Any) -> Any:
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = _merge_schema(out[k], v) if k in out else v
        return out
    if isinstance(a, list) and isinstance(b, list):
        return [_merge_schema(a[0], b[0])]
    return a          # LEAF/CONTENT on either side: the read schema wins (nothing below it is walked)


_INPUT_DEFINED_053: Dict[str, Dict[str, Any]] = {k: _merge_schema(v, _INPUT_SUITE_053_NOT_READ.get(k, {}))
                                                 for k, v in _INPUT_READ.items()}


def _pointer(path: List[Any]) -> str:
    return "".join("/" + (str(p) if isinstance(p, int) else p.replace("~", "~0").replace("/", "~1")) for p in path)


def _outside(value: Any, schema: Any, path: List[Any], out: List[str]) -> None:
    """Appends the pointer of every member of `value` not in `schema` (topmost only)."""
    if isinstance(schema, dict) and isinstance(value, dict):
        for k in value:
            if k not in schema:
                out.append(_pointer(path + [k]))
            else:
                _outside(value[k], schema[k], path + [k], out)
    elif isinstance(schema, list) and isinstance(value, list):
        for i, v in enumerate(value):
            _outside(v, schema[0], path + [i], out)


def input_member_report(vec: Any, kind: Optional[str] = None) -> Dict[str, List[str]]:
    """Single-vector path: the three lists, never a verdict. All three empty when `vec` is not an object; the two input
    lists empty when `input` is not an object or `kind` has no list (those vectors reject on their own), while
    `unknown_vector_members` is still filled from the vector's top-level members."""
    out: Dict[str, List[str]] = {"unknown_input_members": [], "input_members_not_read": [], "unknown_vector_members": []}
    if not isinstance(vec, dict):
        return out
    out["unknown_vector_members"] = sorted(_pointer([k]) for k in vec
                                           if k not in _VECTOR_READ and k not in _VECTOR_SUITE_053_NOT_READ)
    kind = kind or vec.get("kind")
    inp = vec.get("input")
    if not isinstance(kind, str) or kind not in _INPUT_READ or not isinstance(inp, dict):
        return out
    nr: List[str] = []
    _outside(inp, _INPUT_READ[kind], [], nr)
    un: List[str] = []
    _outside(inp, _INPUT_DEFINED_053[kind], [], un)
    out["input_members_not_read"] = nr
    out["unknown_input_members"] = un
    return out


def unknown_input_members(vec: Any, kind: Optional[str] = None) -> List[str]:
    """`input` members neither read by this verifier nor present in suite 0.5.3 for `kind`: reported, never judged."""
    return input_member_report(vec, kind)["unknown_input_members"]


def input_members_not_read(vec: Any, kind: Optional[str] = None) -> List[str]:
    """`input` members this verifier does not read for `kind` (superset of unknown_input_members): reported, never judged."""
    return input_member_report(vec, kind)["input_members_not_read"]


def verify_vector(vec: Dict[str, Any], kind: Optional[str] = None) -> Tuple[str, Optional[str], str]:
    """Returns (verdict, reason, detail); verdict in {"valid", "reject"}; reason None when valid."""
    kind = kind or vec.get("kind")
    fn = KINDS.get(kind) if isinstance(kind, str) else None   # 2026-10-11: a list/object `kind` raised TypeError (no verdict)
    if fn is None:
        return "reject", R_INPUT, f"unknown kind {kind!r}"
    inp = vec.get("input")
    if not isinstance(inp, dict):
        return "reject", R_INPUT, "vector has no `input` object"
    try:
        return "valid", None, fn(inp)
    except Reject as r:
        return "reject", r.reason, r.detail
    except Exception as e:                            # a crash is a reject, never a missing verdict (n15/n16)
        return "reject", R_INPUT, f"internal error {type(e).__name__}: {e}"


def verify_file(path: str, kind: Optional[str] = None) -> Tuple[str, Optional[str], str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            vec = load_json(fh.read())
    except DuplicateName as e:
        return "reject", R_CANON, str(e)
    except Exception as e:                            # REVIEW FIX F1: RecursionError (nesting > ~1000) escaped as a crash, no verdict
        return "reject", R_INPUT, f"vector unreadable: {type(e).__name__}: {e}"
    if not isinstance(vec, dict):
        return "reject", R_INPUT, "vector is not a JSON object"
    return verify_vector(vec, kind)


# ════════════════════════════════════════════════════════════════════════════════════════
# 7. Harness over the manifest.
# ════════════════════════════════════════════════════════════════════════════════════════
def run_suite(spec_dir: str, flip_expect: bool = False) -> Dict[str, Any]:
    with open(os.path.join(spec_dir, "MANIFEST.json"), "r", encoding="utf-8") as fh:
        manifest = load_json(fh.read())
    rows = []
    for entry in manifest["vectors"]:
        path = os.path.join(spec_dir, "vectors", entry["file"])
        verdict, reason, detail = verify_file(path, entry.get("kind"))
        try:
            with open(path, "r", encoding="utf-8") as fh:
                members = input_member_report(load_json(fh.read()), entry.get("kind"))
        except Exception:  # noqa: BLE001 — a vector that does not even load has its own row above (a reject)
            members = input_member_report(None)
        expect = entry.get("expect")                  # REVIEW FIX F5: a manifest entry without `expect` is discordant, not a KeyError
        if flip_expect:
            expect = "reject" if expect == "valid" else "valid"
        exp_reason = entry.get("reason")
        verdict_ok = verdict == expect
        reason_ok = None if exp_reason is None else (reason == exp_reason)
        rows.append({"file": entry["file"], "kind": entry.get("kind"), "expect": expect, "expect_reason": exp_reason,
                     "verdict": verdict, "reason": reason, "detail": detail,
                     "verdict_ok": verdict_ok, "reason_ok": reason_ok,
                     "concordant": verdict_ok and (reason_ok is not False),
                     **members})   # reported, never judged (input schema 1, 2026-10-11)
    n = len(rows)
    import datetime
    return {"suite": manifest.get("suite"), "version": manifest.get("version"), "verifier": __version__,
            "python": sys.version.split()[0], "sys_version": sys.version,
            "cwd": ".",                                    # repo-relative on purpose: no machine paths in published artefacts
            "argv": [os.path.basename(sys.argv[0])] + [os.path.relpath(a) if os.path.exists(a) else a for a in sys.argv[1:]],
            "run_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"),
            "spec_dir": os.path.relpath(spec_dir),
            "ablations": sorted(_ABLATE), "flip_expect": flip_expect, "input_schema": INPUT_SCHEMA_VERSION,
            "n": n,
            "verdict_concordant": sum(r["verdict_ok"] for r in rows),
            "reason_named": sum(r["expect_reason"] is not None for r in rows),
            "reason_concordant": sum(bool(r["reason_ok"]) for r in rows),
            "concordant": sum(r["concordant"] for r in rows),
            "rows": rows}


def _shown(pointers: List[str]) -> str:
    """Member pointers as JSON strings, ASCII-escaped: a member name taken from the vector cannot add a line to the
    report (\\n), and a lone surrogate cannot make the print raise (review 2026-10-11)."""
    return ", ".join(json.dumps(p) for p in pointers)


def print_report(res: Dict[str, Any]) -> None:
    print(f"Tersign {res['suite']} v{res['version']} — independent verifier {res['verifier']} — Python {res['python']}"
          + (f" — ABLATED: {res['ablations']}" if res["ablations"] else "")
          + (" — EXPECT FLIPPED (positive control)" if res["flip_expect"] else ""))
    for r in res["rows"]:
        mark = "OK  " if r["concordant"] else "DISC"
        exp = str(r["expect"]) + (f"/{r['expect_reason']}" if r["expect_reason"] else "")   # REVIEW FIX F5: expect may be None
        got = r["verdict"] + (f"/{r['reason']}" if r["reason"] else "")
        print(f"{mark} {r['file']:<56} {str(r['kind']):<26} expect={exp:<34} got={got:<34} {r['detail']}"
              + (f"  [input members not read: {_shown(r['input_members_not_read'])}]" if r.get("input_members_not_read") else "")
              + (f"  [UNKNOWN input members (not read, not in suite 0.5.3): {_shown(r['unknown_input_members'])}]" if r.get("unknown_input_members") else "")
              + (f"  [UNKNOWN vector members: {_shown(r['unknown_vector_members'])}]" if r.get("unknown_vector_members") else ""))   # REVIEW FIX F3: kind may be None
    print(f"verdict concordant {res['verdict_concordant']}/{res['n']}; "
          f"reason concordant {res['reason_concordant']}/{res['reason_named']} (where the manifest names one); "
          f"fully concordant {res['concordant']}/{res['n']}")


# ── positive control: mutate each VALID vector so that it must reject ────────────────────
def _flip_hex(s: str) -> str:
    last = s[-1]
    return s[:-1] + ("0" if last.lower() != "0" else "1")


def mutations_for(vec: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Content-changing mutations of a vector's input; each must flip a valid vector to reject."""
    inp = vec["input"]
    out: List[Tuple[str, Dict[str, Any]]] = []

    def mut(name, fn):
        v = copy.deepcopy(vec)
        fn(v["input"])
        out.append((name, v))

    for key in ("expected_digest", "expected_link", "anchored_digest", "subject_digest", "claimed_canonical"):
        if isinstance(inp.get(key), str):
            mut(f"flip:{key}", lambda i, k=key: i.__setitem__(k, _flip_hex(i[k])))
    if "payload" in inp and isinstance(inp["payload"], dict):
        mut("payload:add-key", lambda i: i["payload"].__setitem__("zz_mutant", 1))
    if isinstance(inp.get("head"), dict):
        mut("head:flip-digest", lambda i: i["head"].__setitem__("digest", _flip_hex(i["head"]["digest"])))
        if "acc" in inp["head"]:
            mut("head:flip-acc", lambda i: i["head"].__setitem__("acc", _flip_hex(i["head"]["acc"])))
        if isinstance(inp.get("records"), list) and len(inp["records"]) > 1:
            mut("records:omit-seq2", lambda i: i["records"].pop(1))
            mut("records:dup-seq2", lambda i: i["records"].insert(1, copy.deepcopy(i["records"][1])))
            mut("records:flip-prev-last", lambda i: i["records"][-1].__setitem__("prev_digest", _flip_hex(i["records"][-1]["prev_digest"])))
    if isinstance(inp.get("receipt"), dict) and "offerDigest" in inp["receipt"]:
        mut("offer:change-amount", lambda i: i["offer"].__setitem__("amount", str(i["offer"]["amount"]) + "0"))
    if isinstance(inp.get("record"), dict) and "decisionEvidenceDigest" in inp["record"]:
        mut("evidence:change-policy", lambda i: i["decision_evidence"]["policy"].__setitem__("version", "9"))
    if isinstance(inp.get("boundary_event"), dict):
        mut("boundary:flip-prefixDigest", lambda i: i["boundary_event"].__setitem__("prefixDigest", _flip_hex(i["boundary_event"]["prefixDigest"])))
        mut("boundary:drop-position", lambda i: i["boundary_event"].pop("position", None))
        mut("boundary:coverage-beyond-attested", lambda i: i.__setitem__("covered_through", i["boundary_event"]["attestedPrefixLength"] + 1))
    if inp.get("claimed") == "independent" and isinstance(inp.get("attestations"), list):
        mut("independence:attestors-become-parties", lambda i: i.__setitem__("parties", list(i["parties"]) + [a["by"] for a in i["attestations"]]))
        mut("independence:declare-record_commits", lambda i: i.__setitem__("record_commits", ["settlement"]))
        if "covers" in inp:
            mut("independence:cover-uncommitted-fact", lambda i: i.__setitem__("covers", list(i["covers"]) + ["refund"]))
        if "deliverable_bytes" in inp:
            mut("independence:tamper-deliverable", lambda i: i.__setitem__("deliverable_bytes", i["deliverable_bytes"] + " "))
    if isinstance(inp.get("record"), dict) and "economic_phase" in inp["record"]:
        # 2026-10-12: was "set the record's phase to funding", a no-op on a funding record (p47, new in v0.5.7: the
        # mutant stayed valid); now the record's phase becomes a DIFFERENT vocabulary word
        mut("phase:record-other-phase", lambda i: i["record"].__setitem__(
            "economic_phase", "delivery" if i["record"]["economic_phase"] == "funding" else "funding"))
    return out


def run_mutations(spec_dir: str) -> Dict[str, Any]:
    with open(os.path.join(spec_dir, "MANIFEST.json"), "r", encoding="utf-8") as fh:
        manifest = load_json(fh.read())
    rows = []
    for entry in manifest["vectors"]:
        if entry["expect"] != "valid":
            continue
        with open(os.path.join(spec_dir, "vectors", entry["file"]), "r", encoding="utf-8") as fh:
            vec = load_json(fh.read())
        base = verify_vector(vec, entry["kind"])
        for name, mutant in mutations_for(vec):
            verdict, reason, detail = verify_vector(mutant, entry["kind"])
            rows.append({"file": entry["file"], "mutation": name, "base": base[0], "verdict": verdict,
                         "reason": reason, "flipped": base[0] == "valid" and verdict == "reject", "detail": detail})
    return {"n": len(rows), "flipped": sum(r["flipped"] for r in rows), "rows": rows}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("spec_dir", help="directory holding MANIFEST.json and vectors/")
    ap.add_argument("--json", help="write the full result table to this file")
    ap.add_argument("--ablate", action="append", default=[], choices=sorted(ABLATIONS), help="disable one rule (repeatable)")
    ap.add_argument("--flip-expect", action="store_true", help="positive control: invert every expect (all must discord)")
    ap.add_argument("--mutate", action="store_true", help="positive control: mutate the valid vectors (all must reject)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    _ABLATE.clear()
    _ABLATE.update(args.ablate)
    if args.mutate:
        res = run_mutations(args.spec_dir)
        for r in res["rows"]:
            mark = "FLIP" if r["flipped"] else "NOFLIP"
            if not args.quiet or not r["flipped"]:
                print(f"{mark} {r['file']:<56} {r['mutation']:<40} -> {r['verdict']}/{r['reason']}  {r['detail'][:90]}")
        print(f"mutations flipped valid->reject: {res['flipped']}/{res['n']}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=1, ensure_ascii=False)
        return 0 if res["flipped"] == res["n"] else 1
    res = run_suite(args.spec_dir, flip_expect=args.flip_expect)
    if not args.quiet:
        print_report(res)
    else:
        print(f"fully concordant {res['concordant']}/{res['n']}")
    if args.json:   # errors=backslashreplace: a lone surrogate (only possible inside a JSON string) is written as \uXXXX
        with open(args.json, "w", encoding="utf-8", errors="backslashreplace") as fh:
            json.dump(res, fh, indent=1, ensure_ascii=False)
    return 0 if res["concordant"] == res["n"] else 1


if __name__ == "__main__":
    sys.exit(main())
