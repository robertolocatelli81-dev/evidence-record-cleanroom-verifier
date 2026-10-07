#!/usr/bin/env python3
"""Deterministic generator for proposed_vectors_presence_rule_candidate_bytes.json.

Proposed vectors for review toward draft-krausz-verification-state-04 / evidence-pinning rev 10.
Separate from rev 9: nothing here reads or writes the rev 9 corpus. Stdlib only.

    python3 build.py            # writes the JSON next to this file
    python3 build.py --check    # exits 1 if the file on disk differs, byte for byte, from what this script builds

evidence_root is computed per Section 5.3.3 of the filed -03 text (leaf/node preimages, canonical order,
odd node promoted, one pinned item = its leaf), written here from the text, not imported from any checker.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "proposed_vectors_presence_rule_candidate_bytes.json")

URL_A = "https://example.org/a"
URL_B = "https://example.org/b"
TS_1 = "2026-09-01T12:00:00.000Z"
BYTES_A = b"alpha"            # sha256 = D_alpha of the rev 9 generator (h("alpha"))
BYTES_B = b"beta"             # sha256 = D_beta of the rev 9 generator (h("beta"))
BYTES_A_CHANGED = b"alphA"    # one byte changed: offset 4, 0x61 -> 0x41


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


D_ALPHA = sha256_hex(BYTES_A)
D_BETA = sha256_hex(BYTES_B)
MALFORMED_DIGEST = D_ALPHA.upper()          # 64 characters, uppercase hex: fails only the lowercase form rule
INVALID_KIND = "Full_Resource"              # outside the three-value domain; differs from full_resource only in case


def _leaf(e):
    return hashlib.sha256(b"ao-evidence-leaf-v2\x00" + e["url"].encode("utf-8") + b"\x00"
                          + e["snippet_sha256"].encode("utf-8") + b"\x00" + e["content_kind"].encode("utf-8")
                          + b"\x00" + e["retrieved_at"].encode("utf-8")).digest()


def evidence_root(sources):
    pinned = sorted((e for e in sources if e["pinned"] is True),
                    key=lambda e: tuple(e[k].encode("utf-8") for k in ("url", "snippet_sha256", "content_kind",
                                                                        "retrieved_at")))
    level = [_leaf(e) for e in pinned]
    if not level:
        return None
    while len(level) > 1:
        nxt = [hashlib.sha256(b"ao-evidence-node-v1\x00" + level[i] + b"\x00" + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def evidence_set(sources):
    """A complete evidence_set: every set-level member declared, root computed over the members as carried."""
    pc = sum(1 for e in sources if e["pinned"] is True)
    return {
        "evidence_set_version": "ao-evidence-set-v1",
        "retrieved_at": min((e["retrieved_at"] for e in sources), key=lambda s: s.encode("utf-8")),
        "source_count": len(sources),
        "pinned_count": pc,
        "fully_pinned": pc == len(sources) and len(sources) > 0,
        "evidence_root": evidence_root(sources),
        "sources": sources,
    }


def entry(url, digest, kind, **extra):
    e = {"url": url, "snippet_sha256": digest, "content_kind": kind, "retrieved_at": TS_1, "pinned": True}
    e.update(extra)
    return e


PRESENCE_BASIS = ("-03 Sections 5.3.2 and 5.4.1(a) with the presence-rule clarification proposed on "
                  "x402-foundation/tsc#4 (issuecomment-6024083056, 2026-10-06, for review). The filed -03 wording "
                  "does not settle this case: read literally, the general suppression rule of 5.4.1(a) would leave "
                  "only resource_sha256_not_lowercase_hex64.")


def build():
    v = []
    # 1. valid full_resource + malformed non-null resource_sha256: both conditions (the proposed clarification)
    v.append({
        "id": "evi-resource-sha256-malformed-with-full-resource-reports-both-rejects",
        "designation": "MALFORMED",
        "condition": "resource_sha256_present_for_full_resource",
        "expected_conditions": sorted(["resource_sha256_present_for_full_resource",
                                       "resource_sha256_not_lowercase_hex64"]),
        "expect": "halt, malformed; reported conditions exactly {resource_sha256_present_for_full_resource, "
                  "resource_sha256_not_lowercase_hex64}: the presence condition tests non-null presence, "
                  "independently of the digest's form",
        "basis": PRESENCE_BASIS,
        "input": {"evidence_set": evidence_set([entry(URL_A, D_ALPHA, "full_resource",
                                                      resource_sha256=MALFORMED_DIGEST)])},
    })
    # 2. invalid content_kind + WELL-FORMED resource_sha256: only the content_kind condition (isolates suppression)
    v.append({
        "id": "evi-content-kind-invalid-suppresses-full-resource-check-rejects",
        "designation": "MALFORMED",
        "condition": "content_kind_absent_or_invalid_when_pinned",
        "expected_conditions": ["content_kind_absent_or_invalid_when_pinned"],
        "expect": "halt, malformed; reported conditions exactly {content_kind_absent_or_invalid_when_pinned}; "
                  "resource_sha256 is well-formed, so the only other candidate, "
                  "resource_sha256_present_for_full_resource, is the dependent check a malformed content_kind "
                  "suppresses",
        "basis": "-03 Sections 5.3.2 (content_kind, resource_sha256) and 5.4.1(a) (a condition is not evaluated if "
                 "a member it takes as input failed its own form check); content_kind \"Full_Resource\" is outside "
                 "the three-value domain",
        "input": {"evidence_set": evidence_set([entry(URL_A, D_ALPHA, INVALID_KIND, resource_sha256=D_ALPHA)])},
    })
    # 3. invalid content_kind + malformed resource_sha256: content_kind condition + the digest's own form condition
    v.append({
        "id": "evi-content-kind-invalid-resource-sha256-malformed-rejects",
        "designation": "MALFORMED",
        "condition": "content_kind_absent_or_invalid_when_pinned",
        "expected_conditions": sorted(["content_kind_absent_or_invalid_when_pinned",
                                       "resource_sha256_not_lowercase_hex64"]),
        "expect": "halt, malformed; reported conditions exactly {content_kind_absent_or_invalid_when_pinned, "
                  "resource_sha256_not_lowercase_hex64}; resource_sha256_present_for_full_resource stays "
                  "suppressed by the malformed content_kind",
        "basis": "-03 Sections 5.3.2 and 5.4.1(a); the second half of the proposed clarification (\"A malformed "
                 "content_kind would still suppress the dependent check\")",
        "input": {"evidence_set": evidence_set([entry(URL_A, D_ALPHA, INVALID_KIND,
                                                      resource_sha256=MALFORMED_DIGEST)])},
    })
    # 4. full_resource + resource_sha256 null: no condition; (b) recomputes, (d) content_not_held, unknown
    es4 = evidence_set([entry(URL_A, D_ALPHA, "full_resource", resource_sha256=None)])
    v.append({
        "id": "evi-resource-sha256-null-with-full-resource-accepted",
        "designation": "ADDITIVE",
        "expected_conditions": [],
        "expected_token": "unknown",
        "expected_item_reasons": ["content_not_held"],
        "expect": "accepted; NOT malformed; no condition (a null resource_sha256 is not a digest); the root "
                  "recomputes under (b); no candidate content is held, so the per-item reason is content_not_held "
                  "and the step resolves unknown",
        "basis": "-03 Section 5.3.2 (\"MUST be absent or null when content_kind is full_resource\"; absent and null "
                 "are equivalent) and 5.4.1(b), (d), (i)",
        "input": {"evidence_set": es4, "verifier_holds_bytes_for": None},
        "computed": {"evidence_root": es4["evidence_root"]},
    })
    # 5. candidate bytes that hash to snippet_sha256 on every pinned item: resolved
    es5 = evidence_set([entry(URL_A, D_ALPHA, "snippet"), entry(URL_B, D_BETA, "snippet")])
    v.append({
        "id": "evi-candidate-bytes-match-resolves",
        "designation": "RESOLUTION",
        "expected_conditions": [],
        "expected_token": "resolved",
        "expected_item_reasons": ["content_matches", "content_matches"],
        "expect": "step resolves `resolved`: the runner decodes verifier_holds_bytes_hex, computes SHA-256 over "
                  "each item's bytes and finds it equal to snippet_sha256; per-item reasons content_matches, "
                  "content_matches",
        "basis": "-03 Section 5.4.1(d) and (i)",
        "input": {"evidence_set": es5,
                  "verifier_holds_bytes_for": [URL_A, URL_B],
                  "verifier_holds_bytes_hex": {URL_A: BYTES_A.hex(), URL_B: BYTES_B.hex()}},
        "computed": {"evidence_root": es5["evidence_root"],
                     "candidate_sha256": {URL_A: sha256_hex(BYTES_A), URL_B: sha256_hex(BYTES_B)}},
    })
    # 6. same set, one byte of the bytes held for item a changed: content_differs on a, unknown, no halt
    v.append({
        "id": "evi-candidate-bytes-one-byte-changed-unknown",
        "designation": "UNKNOWN",
        "expected_conditions": [],
        "expected_token": "unknown",
        "expected_item_reasons": ["content_differs", "content_matches"],
        "expect": "unknown; MUST NOT halt; per-item reasons content_differs (item a: one byte of the held bytes "
                  "differs from those of evi-candidate-bytes-match-resolves) and content_matches (item b)",
        "basis": "-03 Section 5.4.1(d) (\"A mismatch resolves unknown for that item and MUST NOT halt\") and (i) "
                 "(conjunction)",
        "input": {"evidence_set": es5,
                  "verifier_holds_bytes_for": [URL_A, URL_B],
                  "verifier_holds_bytes_hex": {URL_A: BYTES_A_CHANGED.hex(), URL_B: BYTES_B.hex()}},
        "computed": {"evidence_root": es5["evidence_root"],
                     "candidate_sha256": {URL_A: sha256_hex(BYTES_A_CHANGED), URL_B: sha256_hex(BYTES_B)},
                     "changed_byte": {"url": URL_A, "offset": 4, "from": "0x61", "to": "0x41"}},
    })
    return v


def render():
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    data = render()
    if "--check" in sys.argv[1:]:
        try:
            with open(OUT, "rb") as f:                 # bytes, so a CRLF or re-encoded copy is not "identical"
                same = f.read() == data.encode("utf-8")
        except OSError as exc:
            print(f"MISSING: {exc}")
            sys.exit(1)
        print("byte-identical" if same else "DIFFERS")
        sys.exit(0 if same else 1)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
    print(OUT, hashlib.sha256(data.encode("utf-8")).hexdigest())
