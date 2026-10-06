#!/usr/bin/env python3
"""Cold implementation of draft-krausz-verification-state-03 §5.3 / §5.4.1 (evidence-set resolution step).

FILED-TEXT COPY (2026-10-06, third rev-9 runner): copy of gtm/x402_tsc4_dash03/es_check.py (sha256 0c430eca…), checked
against the FILED -03 (sha256 1d142b3e…dbed9, = IETF archive) §5.3 and §5.4.1 via DIFF_03_cold_vs_filed_5.3-5.4.txt.
Every filed sentence that touches this code is annotated `# FILED Mn` and listed in records/MODIFICHE_DA_TESTO_DEPOSITATO.md.
No semantic rule changed: the three filed changes that bear on §5.3/§5.4.1 (M1 presence check, M2 resource_sha256
null, M3 NUL content rule) were already implemented here by the 26-29/09 alignments; M5 adds a non-semantic input
`held_sha256` (a digest the verifier already computed over bytes it holds) for the harness.

Written from the draft text alone (spec/draft-03@5a718639288a.txt, sha256 ad009473…), before reading any vector or
anyone else's checker. Every place where the text leaves a choice open is marked `# CHOICE <n>` and listed in
records/AMBIGUITIES.md.

resolve(receipt_payload, held=None) -> {"token": "resolved"|"unknown"|None, "outcome": "malformed"|"unknown"|"resolved",
                                        "conditions": set[str], "reason": str|None, "per_item": list[str]|None}
`held` maps an entry index to the bytes the verifier holds for that pinned item (§5.4.1(d)).
"""
import hashlib
import json
import re
import sys
from datetime import datetime

VERSION = "ao-evidence-set-v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
# §5.3.2: UTC, Z designator, exactly three fractional-second digits; a valid instant, no leap second
RFC3339_CANON = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z")
CONTENT_KINDS = ("snippet", "excerpt", "full_resource")
UNPINNED_REASONS = ("no_content_returned", "provider_metadata_only")
_MISSING = object()


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _canon_time(v):
    if not isinstance(v, str):
        return False
    m = RFC3339_CANON.fullmatch(v)
    if not m:
        return False
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59):
        return False
    # a day that exists in that month and year — proleptic Gregorian, year 0000 included (RFC 3339 allows 0000-9999;
    # Python's datetime does not, which gave a false retrieved_at_not_canonical_form: independent review 26/09)
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    return 1 <= d <= (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[mo - 1]


def _has_nul(v):
    return isinstance(v, str) and "\x00" in v


def _get(e, k):
    return e.get(k, _MISSING)


def _check_entry(e):
    """§5.3.2 per entry. Returns (conditions, failed_members): failed_members = members whose own TYPE/FORM check
    failed, used by the whole-check suppression rule of §5.4.1(a)."""
    conds, failed = set(), set()
    url, snip, rat = _get(e, "url"), _get(e, "snippet_sha256"), _get(e, "retrieved_at")
    pinned, ck = _get(e, "pinned"), _get(e, "content_kind")
    res, ur = _get(e, "resource_sha256"), _get(e, "unpinned_reason")

    if not isinstance(url, str):
        conds.add("url_absent_or_not_string"); failed.add("url")
    if not _canon_time(rat):
        conds.add("retrieved_at_not_canonical_form"); failed.add("retrieved_at")
    pinned_ok = isinstance(pinned, bool)
    if not pinned_ok:
        conds.add("pinned_absent_or_not_boolean"); failed.add("pinned")

    # snippet_sha256 form: "a non-null value that is not exactly 64 lowercase hexadecimal characters" — a check on the
    # value alone, so it runs whatever pinned is.                                                          # CHOICE 1
    # FILED M1 (§5.3.2): "snippet_sha256_present_when_unpinned is a presence check: it takes the member's presence as
    # input, not its form, so it is evaluated whatever form the value takes, and an unpinned entry whose non-null value
    # is also not 64 lowercase hexadecimal characters reports it alongside snippet_sha256_not_lowercase_hex64. It still
    # takes pinned as input, so a malformed pinned value suppresses it" + §5.4.1(a) "Every condition named
    # *_present_when_* or *_absent_when_* takes the tested member's presence as its input, not its form". Code below
    # already does exactly this (present_when_unpinned under pinned_ok, not suppressed by the hex failure): no change.
    if snip is not _MISSING and snip is not None and not (isinstance(snip, str) and HEX64.fullmatch(snip)):
        conds.add("snippet_sha256_not_lowercase_hex64"); failed.add("snippet_sha256")
    if pinned_ok:                                   # everything below takes pinned as input
        if pinned:
            if snip is _MISSING or snip is None:
                conds.add("snippet_sha256_absent_when_pinned")
            if ck is _MISSING or ck is None or ck not in CONTENT_KINDS:
                conds.add("content_kind_absent_or_invalid_when_pinned"); failed.add("content_kind")
            # unpinned_reason on a pinned entry: the text defines no condition                                # CHOICE 2
        else:
            if snip is _MISSING:
                conds.add("snippet_sha256_member_absent")
            elif snip is not None:
                conds.add("snippet_sha256_present_when_unpinned")
            if ck is not _MISSING and ck is not None:
                conds.add("content_kind_present_when_unpinned")
            if ur is _MISSING or ur not in UNPINNED_REASONS:
                conds.add("unpinned_reason_absent_or_invalid")
    # resource_sha256: OPTIONAL. Aligned 2026-09-29 to -03 at 057abd7, §5.3.2 (drafts/draft-krausz-verification-state-03.txt
    # lines 917-925): "Absent and null are equivalent (as for content_kind): each records that no full-resource digest is
    # carried, neither is malformed, and neither is a digest, so a null value is never evidence toward a resolved result.
    # A non-null value MUST be exactly 64 lowercase hexadecimal characters; reported condition on violation:
    # resource_sha256_not_lowercase_hex64." Vector R1. (resolve() never reads resource_sha256 toward `resolved`: only
    # snippet_sha256 is compared in (d), so null contributes nothing there.) Before this date CHOICE 3 read the 5a71863
    # text "when present" as covering null, which reported R1 as malformed — the reading -03 did not adopt.
    # FILED M2 (§5.3.2 filed, lines 917-925): identical sentences to the 057abd7 text cited above. No change.
    if res is not _MISSING and res is not None and not (isinstance(res, str) and HEX64.fullmatch(res)):
        conds.add("resource_sha256_not_lowercase_hex64"); failed.add("resource_sha256")
    # "MUST be absent when content_kind is full_resource ... ranges over every entry regardless of pinned";
    # the text says "a non-null resource_sha256" here, so null does not trigger it                         # CHOICE 3b
    # FILED M2: "MUST be absent or null when content_kind is full_resource" — CHOICE 3b is now the text. No change.
    # OPEN (CHOICE 3c, not decided by the filed text): with a non-hex resource_sha256 this rule still fires beside
    # resource_sha256_not_lowercase_hex64. The filed presence exemption of §5.4.1(a) names only *_present_when_* /
    # *_absent_when_*; this condition is *_present_for_*. Kept as before; no rev-9 vector has a non-hex resource_sha256.
    if ck == "full_resource" and res is not _MISSING and res is not None:
        conds.add("resource_sha256_present_for_full_resource")
    for k, v in (("url", url), ("snippet_sha256", snip), ("content_kind", ck), ("retrieved_at", rat)):
        # member_contains_nul is a CONTENT rule, not a type or form check: it is reported beside the member's other
        # conditions and suppresses nothing (TKCollective's ruling on tsc#4, 26/09/2026; my first reading, CHOICE 9,
        # counted it as a form failure — changed after the ruling, so this is not independent agreement).
        # FILED M3 (§5.3.2): "member_contains_nul is a content rule, not a type or form check: it is reported alongside
        # whatever other conditions the same member's rules report, and it suppresses nothing" — now the text. No change.
        if _has_nul(v):
            conds.add("member_contains_nul")
    return conds, failed


def _leaf(e):
    return hashlib.sha256(b"ao-evidence-leaf-v2\x00" + e["url"].encode() + b"\x00" + e["snippet_sha256"].encode()
                          + b"\x00" + e["content_kind"].encode() + b"\x00" + e["retrieved_at"].encode()).digest()


def evidence_root(pinned_entries):
    """§5.3.3. Returns the root as lowercase hex (the encoding is not stated normatively)."""        # CHOICE 4
    ents = sorted(pinned_entries, key=lambda e: (e["url"].encode(), e["snippet_sha256"].encode(),
                                                 e["content_kind"].encode(), e["retrieved_at"].encode()))
    level = [_leaf(e) for e in ents]
    if not level:
        return None
    while len(level) > 1:
        nxt = [hashlib.sha256(b"ao-evidence-node-v1\x00" + level[i] + b"\x00" + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])                  # odd node promoted unchanged, rightmost
        level = nxt
    return level[0].hex()


def _same_retrieval(a, b):
    """§5.3.2 entry distinctness: same url and retrieved_at and, where both are pinned, same snippet and kind.
    A pinned and an unpinned entry sharing url and retrieved_at are one retrieval recorded twice."""
    if a["url"] != b["url"] or a["retrieved_at"] != b["retrieved_at"]:
        return False
    if a["pinned"] and b["pinned"]:
        return _get(a, "snippet_sha256") == _get(b, "snippet_sha256") and _get(a, "content_kind") == _get(b, "content_kind")
    return True


def resolve(payload, held=None, held_sha256=None):
    # FILED M5 (non-semantic): held_sha256 maps an entry index to the SHA-256 (lowercase hex) the verifier computed over
    # the bytes it holds for that item — §5.4.1(d) "compute its SHA-256 and compare with snippet_sha256". Same compare.
    held = held or {}
    held_sha256 = held_sha256 or {}
    out = {"token": None, "outcome": None, "conditions": set(), "reason": None, "per_item": None}
    # (e) no evidence_set → unknown, stop
    if not isinstance(payload, dict) or "evidence_set" not in payload:
        out.update(token="unknown", outcome="unknown", reason="no_evidence_set"); return out
    es = payload["evidence_set"]
    # (h) version-independent structural checks: that condition alone, stop
    if not isinstance(es, dict):
        out.update(outcome="malformed", conditions={"evidence_set_not_object"}); return out
    ver = es.get("evidence_set_version", _MISSING)
    if not isinstance(ver, str):
        out.update(outcome="malformed", conditions={"evidence_set_version_absent_or_not_string"}); return out
    # (h) version check
    if ver != VERSION:
        out.update(token="unknown", outcome="unknown", reason="evidence_set_version_unsupported"); return out

    # (a) — every condition, with whole-check suppression
    conds = set()
    sources = es.get("sources", _MISSING)
    if sources is _MISSING or sources is None or sources == []:
        conds.add("evidence_set_names_no_sources"); sources_ok = False
    elif not isinstance(sources, list):
        conds.add("sources_not_array"); sources_ok = False
    else:
        sources_ok = True

    entries_failed = []                            # per entry: members that failed type/form (None = entry not object)
    if sources_ok:
        for e in sources:
            if not isinstance(e, dict):
                conds.add("source_entry_not_object"); entries_failed.append(None); continue
            c, f = _check_entry(e)
            conds |= c; entries_failed.append(f)

    def all_ok(member):
        """True when every entry's `member` passed its own type/form check (and every entry is an object)."""
        return sources_ok and all(f is not None and member not in f for f in entries_failed)

    if sources_ok:
        n = len(sources)
        sc = es.get("source_count", _MISSING)
        # source_count: "MUST equal len(sources)"; a non-integer declared value cannot equal it              # CHOICE 5
        if sc is not _MISSING and not (_is_int(sc) and sc == n):
            conds.add("source_count_mismatch")
        sc_op = sc if (sc is not _MISSING and _is_int(sc)) else n
        pinned_known = all_ok("pinned")
        actual_pinned = sum(1 for e in sources if isinstance(e, dict) and e.get("pinned") is True) if pinned_known else None
        pc = es.get("pinned_count", _MISSING)
        if pinned_known and pc is not _MISSING and not (_is_int(pc) and pc == actual_pinned):
            conds.add("pinned_count_mismatch")
        # fully_pinned: derived from the count OPERANDS (declared when present, else fallback), per §5.3.1's
        # "operand for any check in this section"                                                          # CHOICE 6
        pc_op = pc if (pc is not _MISSING and _is_int(pc)) else actual_pinned
        fp = es.get("fully_pinned", _MISSING)
        counts_typed = not ((sc is not _MISSING and not _is_int(sc)) or (pc is not _MISSING and not _is_int(pc)))
        # §5.3.1 declares the counts "(integer)": a declared count of another type failed its own type check, so
        # fully_pinned (which takes it as input) is not evaluated — whole-check rule (independent review 26/09)
        if pc_op is not None and fp is not _MISSING and counts_typed:
            derived = (pc_op == sc_op) and sc_op > 0
            if fp is not derived:                  # a non-boolean declared value differs from the derivation   # CHOICE 7
                conds.add("fully_pinned_mismatch")
        # evidence_root presence: "with no pinned entry" / "with at least one pinned entry" = the entries   # CHOICE 8
        root = es.get("evidence_root", _MISSING)
        if pinned_known:
            if root is not _MISSING and root is not None and actual_pinned == 0:
                conds.add("evidence_root_present_with_no_pinned_items")
            if (root is _MISSING or root is None) and actual_pinned > 0:
                conds.add("evidence_root_absent_with_pinned_items")
        # set-level retrieved_at: bytewise-least over ALL entries; takes every entry's retrieved_at as input
        srat = es.get("retrieved_at", _MISSING)
        if srat is not _MISSING and all_ok("retrieved_at"):
            least = min(e["retrieved_at"].encode() for e in sources)
            if not (isinstance(srat, str) and srat.encode() == least):
                conds.add("set_retrieved_at_not_bytewise_least")
        # entry distinctness: inputs url, retrieved_at, pinned and — for PINNED entries only — snippet_sha256 and
        # content_kind. A malformed snippet on an unpinned entry is not an input of this rule and must not suppress it
        # (independent review 26/09, reproduced: two duplicated pinned entries went unreported).
        def pinned_ok_for(member):
            return sources_ok and all(f is not None and (member not in f or sources[i].get("pinned") is False)
                                      for i, f in enumerate(entries_failed))
        if all(all_ok(m) for m in ("url", "retrieved_at", "pinned")) and all(pinned_ok_for(m) for m in ("snippet_sha256", "content_kind")):
            for i in range(n):
                if any(_same_retrieval(sources[i], sources[j]) for j in range(i + 1, n)):
                    conds.add("duplicate_bound_tuple"); break
    if conds:
        out.update(outcome="malformed", conditions=conds); return out

    # (b) root recomputation, only if (a) reported none
    pinned_entries = [e for e in sources if e["pinned"]]
    root = es.get("evidence_root")
    if root is not None and evidence_root(pinned_entries) != root:
        out.update(outcome="malformed", conditions={"root_not_recomputable_from_sources"}); return out
    # (d) per item
    per = []
    for i, e in enumerate(sources):
        if e["pinned"] and i in held:
            per.append("content_matches" if hashlib.sha256(held[i]).hexdigest() == e["snippet_sha256"] else "content_differs")
        elif e["pinned"] and i in held_sha256:
            per.append("content_matches" if held_sha256[i] == e["snippet_sha256"] else "content_differs")
        else:
            per.append("content_not_held")
    out["per_item"] = per
    fully = (sum(1 for e in sources if e["pinned"]) == len(sources))
    # (c)+(i) under (j)
    if fully and all(p == "content_matches" for p in per):
        out.update(token="resolved", outcome="resolved")
    else:
        out.update(token="unknown", outcome="unknown",
                   reason="not_fully_pinned" if not fully else "content_not_recomputed")
    return out


if __name__ == "__main__":
    r = resolve(json.load(open(sys.argv[1])))
    r["conditions"] = sorted(r["conditions"])
    print(json.dumps(r, indent=1))
