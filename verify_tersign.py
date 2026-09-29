#!/usr/bin/env python3
"""verify_tersign.py — INDEPENDENT (clean-room) structural verifier for the Tersign
`evidence-record-conformance` suite v0.5.3 (69 vectors, upstream commit 0eda3038).

Written 2026-09-28 in a separate, isolated session (clean room) from ONLY:
  * spec/MANIFEST.json  (rule texts per kind, reject reasons, profile)
  * spec/vectors/*.json (the 69 vectors, incl. their `description` fields)
  * vendor/roberto_x402_eip712.py (keccak256, copied below with provenance)
  * public specifications read online: RFC 8785 (JCS), RFC 7493 (I-JSON),
    x402 PR #2853 `specs/extensions/compliance_fields.md` @ b8a81c0 (read via jsdelivr),
    MCP issue #3004 (comments read via api.github.com).
NOT read: Tersign's verify.py / keccak.py / tools/ / README / TypeScript engine.

Usage:
    python3 verify_tersign.py spec/                # run the 69 vectors, print verdict+reason, exit 1 on discord
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

__version__ = "0.1.0"
SUITE_VERSION = "0.5.3"

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


def _pairs_no_dup(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        if k in seen:
            raise DuplicateName(f"duplicate object name {k!r}")
        seen.add(k)
        out[k] = v
    return out


def _bad_constant(name):
    # RFC 8785 §3.2.2.3: "NaN and Infinity are not permitted in JSON"
    raise ValueError(f"non-JSON constant {name}")


def load_json(text: str) -> Any:
    return json.loads(text, parse_float=NumberToken, parse_constant=_bad_constant,
                      object_pairs_hook=_pairs_no_dup)


def is_int(v: Any) -> bool:
    """An integer TOKEN: Python int that is neither bool nor a NumberToken."""
    return isinstance(v, int) and not isinstance(v, bool)


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
_RE_HEX32 = re.compile(r"0x[0-9a-fA-F]{64}")


def hex32(v: Any, reason: str, what: str) -> bytes:
    """A 32-byte digest written as 0x + 64 hex digits. MANIFEST "identifier_normalization":
    "digests compare after strip + lowercase; identifiers that do not parse after normalization
    fail closed" — so surrounding whitespace is tolerated, anything else rejects with the kind's reason."""
    if not isinstance(v, str):
        raise Reject(reason, f"{what} is not a string")
    t = v.strip()
    if not _RE_HEX32.fullmatch(t):
        raise Reject(reason, f"{what} is not a 0x-prefixed 32-byte hex digest")
    return bytes.fromhex(t[2:].lower())


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
        if not isinstance(inp["payload_text"], str):
            raise Reject(R_CANON, "payload_text is not a string")
        try:
            payload = load_json(inp["payload_text"])
        except DuplicateName as e:
            raise Reject(R_CANON, str(e))
        except ValueError as e:
            raise Reject(R_CANON, f"payload_text is not parseable JSON: {e}")
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
    if not is_int(seq) or not (0 <= seq < 2 ** 64):
        raise Reject(R_CONTINUITY, "seq is not an integer token in uint64 range")
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
    # phase. Declared choice, see REPORT_FABLE.md §Ambiguità.
    if phase != presented:
        raise Reject(R_PHASE, f"a {phase}-phase record presented as {presented} evidence")
    return f"record phase {phase} == presented phase"


# ── identities ─────────────────────────────────────────────────────────────────────────
# MANIFEST "identifier_normalization": "two identity syntaxes … 0x-addresses compare after strip +
# lowercase; scheme-qualified identifiers (lowercase alnum scheme, one colon, printable non-space ASCII
# path) compare after strip, case-significant; … identifiers that do not parse after normalization fail closed".
# n31: the verifier "folds toward SAME PARTY (case, trailing `/` `.` `#`)". x402 compliance-fields:
# "the normalization MUST fold toward same party: … surrounding whitespace, letter case, an EIP-55
# checksum variant, or trailing punctuation is that party". CONFLICT on case for scheme identifiers
# (manifest: case-significant; n31 text / x402: fold) — the MANIFEST reading is implemented and the
# conflict is declared in the report. No vector separates the two readings.
_RE_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_RE_SCHEME = re.compile(r"([a-z0-9]+):([\x21-\x7e]+)")


def normalize_identity(v: Any) -> Optional[str]:
    """Returns the comparison key, or None when the identifier does not parse (fail closed)."""
    if not isinstance(v, str):
        return None
    if not _on("no_identity_normalization"):
        return v if v else None
    t = v.strip()
    if _RE_ADDR.fullmatch(t):
        return "addr:" + t.lower()
    m = _RE_SCHEME.fullmatch(t)
    if m and ":" not in m.group(2):                   # "one colon" read strictly: the path carries none
        path = m.group(2).rstrip("/.#")               # trailing punctuation folds toward same party (n31)
        if not path:
            return None
        return "uri:" + m.group(1) + ":" + path
    return None


CLAIM_ASSERTING = ("independent",)
CLAIM_SILENT = ("none", "issuer_attested")   # p9: "claims nothing about independence"; p11: "asserts nothing about independence"
DERIVABLE_FIELDS = ("settlement_result", "deliverable_bytes", "deliverable_digest")


def derive_commitments(inp: Dict[str, Any]) -> Optional[Set[str]]:
    """MANIFEST "commitment_derivation": "`settlement` when settlement_result.success is true and
    transaction is a non-empty string; `network` when settlement_result.network is a non-empty string;
    `delivery` when keccak256(utf8(deliverable_bytes)) == deliverable_digest. A record presenting none of
    these fields has no evaluable commitments (…); a record presenting them and committing to none has
    an EMPTY commitment set". Returns None when unevaluable."""
    if not any(k in inp for k in DERIVABLE_FIELDS):
        return None
    c: Set[str] = set()
    sr = inp.get("settlement_result")
    if isinstance(sr, dict):
        tx = sr.get("transaction")
        if sr.get("success") is True and isinstance(tx, str) and tx != "":
            c.add("settlement")
        net = sr.get("network")
        if isinstance(net, str) and net != "":
            c.add("network")
    if "deliverable_bytes" in inp and "deliverable_digest" in inp:
        b, d = inp["deliverable_bytes"], inp["deliverable_digest"]
        if isinstance(b, str) and isinstance(d, str) and _RE_HEX32.fullmatch(d.strip()):
            if keccak256(b.encode("utf-8")) == bytes.fromhex(d.strip()[2:]):
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


def k_offer_binding(inp: Dict[str, Any]) -> str:
    # MANIFEST "offer_binding": "receipt.offerDigest = keccak256(utf8(canonical(offer))); a receipt that
    # commits to no offer digest cannot bind terms and fails closed" (reason binding_reject: n19).
    offer = need_dict(inp.get("offer"), R_BINDING, "offer")
    receipt = need_dict(inp.get("receipt"), R_BINDING, "receipt")
    if "offerDigest" not in receipt:
        raise Reject(R_BINDING, "receipt commits to no offerDigest: terms cannot be bound (fails closed)")
    claimed = hex32(receipt["offerDigest"], R_BINDING, "receipt.offerDigest")
    got = content_address(offer)
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
    got = content_address(ev)
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
    got = keccak256(jcs(prefix))
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
def verify_vector(vec: Dict[str, Any], kind: Optional[str] = None) -> Tuple[str, Optional[str], str]:
    """Returns (verdict, reason, detail); verdict in {"valid", "reject"}; reason None when valid."""
    kind = kind or vec.get("kind")
    fn = KINDS.get(kind)
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
        expect = entry.get("expect")                  # REVIEW FIX F5: a manifest entry without `expect` is discordant, not a KeyError
        if flip_expect:
            expect = "reject" if expect == "valid" else "valid"
        exp_reason = entry.get("reason")
        verdict_ok = verdict == expect
        reason_ok = None if exp_reason is None else (reason == exp_reason)
        rows.append({"file": entry["file"], "kind": entry.get("kind"), "expect": expect, "expect_reason": exp_reason,
                     "verdict": verdict, "reason": reason, "detail": detail,
                     "verdict_ok": verdict_ok, "reason_ok": reason_ok,
                     "concordant": verdict_ok and (reason_ok is not False)})
    n = len(rows)
    import datetime
    return {"suite": manifest.get("suite"), "version": manifest.get("version"), "verifier": __version__,
            "python": sys.version.split()[0], "sys_version": sys.version,
            "cwd": ".",                                    # repo-relative on purpose: no machine paths in published artefacts
            "argv": [os.path.basename(sys.argv[0])] + [os.path.relpath(a) if os.path.exists(a) else a for a in sys.argv[1:]],
            "run_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"),
            "spec_dir": os.path.relpath(spec_dir),
            "ablations": sorted(_ABLATE), "flip_expect": flip_expect,
            "n": n,
            "verdict_concordant": sum(r["verdict_ok"] for r in rows),
            "reason_named": sum(r["expect_reason"] is not None for r in rows),
            "reason_concordant": sum(bool(r["reason_ok"]) for r in rows),
            "concordant": sum(r["concordant"] for r in rows),
            "rows": rows}


def print_report(res: Dict[str, Any]) -> None:
    print(f"Tersign {res['suite']} v{res['version']} — independent verifier {res['verifier']} — Python {res['python']}"
          + (f" — ABLATED: {res['ablations']}" if res["ablations"] else "")
          + (" — EXPECT FLIPPED (positive control)" if res["flip_expect"] else ""))
    for r in res["rows"]:
        mark = "OK  " if r["concordant"] else "DISC"
        exp = str(r["expect"]) + (f"/{r['expect_reason']}" if r["expect_reason"] else "")   # REVIEW FIX F5: expect may be None
        got = r["verdict"] + (f"/{r['reason']}" if r["reason"] else "")
        print(f"{mark} {r['file']:<56} {str(r['kind']):<26} expect={exp:<34} got={got:<34} {r['detail']}")   # REVIEW FIX F3: kind may be None
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
        mut("phase:record-funding", lambda i: i["record"].__setitem__("economic_phase", "funding"))
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
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, ensure_ascii=False)
    return 0 if res["concordant"] == res["n"] else 1


if __name__ == "__main__":
    sys.exit(main())
