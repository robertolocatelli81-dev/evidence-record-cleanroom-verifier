#!/usr/bin/env python3
"""gen_eip712_vectors.py — deterministic generator of the independent EIP-712 vector set (x402 receipt payload signatures).

Every reject is one change to a valid input (artifact or expected_signer, named in `derived_from`), except er34, which sets
version 2 and re-signs, so that only the version rule can reject it, and er38, which adds both domain and types. er45 and
er46 are written as raw text (a non-JSON token, a duplicate key). Test key and nonces are derived from published
strings, so the bytes are reproducible:
  test key  = keccak256(b"evidence-record-conformance eip712 independent set test key v1") mod n
  nonce k   = keccak256(b"eip712 independent set nonce v1" || priv (32 bytes) || digest) mod n
The live vector is p1's served artifact (/v1/genesis), signed by 0x36f8...8b14 under the construction published on PR #11.
Usage: python3 gen_eip712_vectors.py <out dir>      (writes MANIFEST.json and vectors/)       Stdlib only.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, HERE)
import eip712 as E  # noqa: E402
import secp256k1 as S  # noqa: E402
import verify_eip712 as V  # noqa: E402

N, P = S.N, S.P
KEY_LABEL = b"evidence-record-conformance eip712 independent set test key v1"
PRIV = int.from_bytes(E.keccak256(KEY_LABEL), "big") % N
TEST_ADDR = S.public_key_to_address(S._mul(PRIV, (S.GX, S.GY)), E.keccak256)
LEDGER = "0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6"

# p1, as served by /v1/genesis (recorded in the suite's spec/vectors/p1-live-genesis-receipt.json)
P1_ARTIFACT = {
    "format": "eip712",
    "payload": {"issuedAt": 1783761710, "network": "eip155:8453",
                "payer": "0x36f82906859E5B0bd076069f8cdfAea355358b14",
                "resourceUrl": "https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo",
                "transaction": "", "version": 1},
    "signature": "0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b",
}
P1_SIGNER = "0x36f82906859e5b0bd076069f8cdfaea355358b14"
P1_PROVENANCE = {"source": "GET /v1/genesis (artifact), recorded as the suite's p1-live-genesis-receipt.json",
                 "construction": "PR #11 comment 5909238098 (2026-09-30T10:18:05Z)"}


def k_for(digest: bytes) -> int:
    return int.from_bytes(E.keccak256(b"eip712 independent set nonce v1" + PRIV.to_bytes(32, "big") + digest), "big") % N


def sig_hex(r: int, s: int, v: int) -> str:
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()


def sign_digest(d: bytes) -> str:
    r, s, rec = S.sign(d, PRIV, k_for(d))           # the library returns low-s and the matching recovery id
    return sig_hex(r, s, 27 + rec)


def parts(sig: str):
    raw = bytes.fromhex(sig[2:])
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]


def test_payload(**kw):
    p = {"version": 1, "network": "eip155:8453", "resourceUrl": "https://example.test/eip712-independent-set",
         "payer": "0x00000000000000000000000000000000000000Aa", "issuedAt": 1790000000, "transaction": ""}
    p.update(kw)
    return p


def signed(payload, domain=V.DOMAIN, types=V.TYPES, msg=None):
    m = dict(msg if msg is not None else payload)
    m.setdefault("transaction", "")
    return {"format": "eip712", "payload": payload, "signature": sign_digest(E.signing_digest(domain, "Receipt", types, m))}


def smallest_x_off_curve() -> int:
    x = 1
    while True:
        a = (pow(x, 3, P) + 7) % P
        if pow(a, (P - 1) // 2, P) != 1:
            return x
        x += 1


def build():
    V_ = []

    def add(vid, expect, reason, artifact, signer, derived_from, note, kind="contributed"):
        V_.append({"id": vid, "expect": expect, "reject_reason": reason, "kind": kind, "derived_from": derived_from,
                   "note": note, "input": {"artifact": artifact, "expected_signer": signer}})

    live = P1_ARTIFACT
    t_ok = signed(test_payload())
    t_tx = signed(test_payload(transaction="0x" + "ab" * 32))
    no_tx = dict(t_ok, payload={k: v for k, v in t_ok["payload"].items() if k != "transaction"})
    r1, s1, v1 = parts(live["signature"])
    rt, st, vt = parts(t_ok["signature"])

    # accept
    add("ea1-live-p1-payload-signature", "valid", None, live, P1_SIGNER, None,
        "p1 as served, construction published on PR #11", kind="live-ledger")
    add("ea2-test-key-receipt", "valid", None, t_ok, TEST_ADDR, None, "test key over a well-formed receipt")
    add("ea3-transaction-absent-equals-empty", "valid", None, no_tx, TEST_ADDR, "ea2",
        "x402 5.3: verifiers MUST treat empty-string optional fields as equivalent to absence; same signature as ea2")
    add("ea4-transaction-present", "valid", None, t_tx, TEST_ADDR, None, "non-empty transaction is signed as written")
    add("ea5-expected-signer-checksum-case", "valid", None, live, live["payload"]["payer"], "ea1",
        "expected_signer compared as an address, case-insensitive")

    # domain / type drift (signed by the test key over the wrong digest; the verifier uses the spec's domain)
    add("er01-domain-chainid-8453", "reject", "signer_mismatch", signed(test_payload(), dict(V.DOMAIN, chainId=8453)), TEST_ADDR, "ea2",
        "signed with chainId 8453; x402 fixes chainId 1")
    add("er02-domain-name-letters-transposed", "reject", "signer_mismatch", signed(test_payload(), dict(V.DOMAIN, name="x402 reciept")), TEST_ADDR, "ea2",
        "domain name with two letters transposed (\"reciept\")")
    add("er03-domain-version-2", "reject", "signer_mismatch", signed(test_payload(), dict(V.DOMAIN, version="2")), TEST_ADDR, "ea2",
        "domain version \"2\"")
    add("er04-type-fields-reordered", "reject", "signer_mismatch",
        signed(test_payload(), types={"Receipt": [V.TYPES["Receipt"][i] for i in (1, 0, 2, 3, 4, 5)]}), TEST_ADDR, "ea2",
        "Receipt type string with version and network swapped")
    add("er05-type-without-transaction", "reject", "signer_mismatch",
        {"format": "eip712", "payload": test_payload(), "signature": sign_digest(E.signing_digest(
            V.DOMAIN, "Receipt", {"Receipt": V.TYPES["Receipt"][:5]}, {k: v for k, v in test_payload().items() if k != "transaction"}))},
        TEST_ADDR, "ea2", "signed over a five-field type that drops transaction")
    add("er06-personal-sign-over-typed-digest", "reject", "signer_mismatch",
        {"format": "eip712", "payload": test_payload(), "signature": sign_digest(
            E.keccak256(b"\x19Ethereum Signed Message:\n32" + E.signing_digest(V.DOMAIN, "Receipt", V.TYPES, test_payload())))},
        TEST_ADDR, "ea2", "EIP-191 personal_sign over the EIP-712 digest")

    # value drift on the live artifact (one field each)
    for i, (field, val) in enumerate([("issuedAt", 1783761711), ("network", "eip155:1"),
                                      ("resourceUrl", live["payload"]["resourceUrl"] + "/"), ("version", 1)], 7):
        if field == "version":
            continue
        add(f"er{i:02d}-live-value-drift-{field}", "reject", "signer_mismatch",
            dict(live, payload=dict(live["payload"], **{field: val})), P1_SIGNER, "ea1", f"{field} changed after signing")
    add("er10-live-payer-recased", "reject", "signer_mismatch",
        dict(live, payload=dict(live["payload"], payer=live["payload"]["payer"].lower())), P1_SIGNER, "ea1",
        "payer is a string, hashed as written: lower-casing it changes the message")
    add("er11-transaction-drift", "reject", "signer_mismatch",
        dict(t_tx, payload=dict(t_tx["payload"], transaction="0x" + "ab" * 31 + "ac")), TEST_ADDR, "ea4", "transaction changed after signing")
    add("er12-ledger-key-as-payload-signer", "reject", "signer_mismatch", live, LEDGER, "ea1",
        "the ledger's counter-signing key declared as the payload signer")

    # signature encoding
    add("er13-live-high-s", "reject", "non_canonical_s", dict(live, signature=sig_hex(r1, N - s1, 55 - v1)), P1_SIGNER, "ea1",
        "s' = n - s, v flipped: recovers the same signer, refused before recovery (EIP-2)")
    half = N // 2
    add("er14-s-at-half-n", "reject", "signer_mismatch", dict(t_ok, signature=sig_hex(rt, half, vt)), TEST_ADDR, "ea2",
        "s = floor(n/2) passes low-s and fails at the signer")
    add("er15-s-at-half-n-plus-one", "reject", "non_canonical_s", dict(t_ok, signature=sig_hex(rt, half + 1, vt)), TEST_ADDR, "ea2",
        "s = floor(n/2) + 1")
    for vid, v in (("er16-v-zero", 0), ("er17-v-one", 1), ("er18-v-29", 29)):
        add(vid, "reject", "malformed_signature", dict(t_ok, signature=sig_hex(rt, st, v)), TEST_ADDR, "ea2", f"v = {v}")
    add("er19-signature-64-bytes", "reject", "malformed_signature", dict(t_ok, signature=t_ok["signature"][:-2]), TEST_ADDR, "ea2", "v byte dropped")
    add("er20-signature-66-bytes", "reject", "malformed_signature", dict(t_ok, signature=t_ok["signature"] + "00"), TEST_ADDR, "ea2", "one byte appended")
    add("er21-signature-0X-prefix", "reject", "malformed_signature", dict(t_ok, signature="0X" + t_ok["signature"][2:]), TEST_ADDR, "ea2", "0X prefix")
    add("er22-signature-trailing-newline", "reject", "malformed_signature", dict(t_ok, signature=t_ok["signature"] + "\n"), TEST_ADDR, "ea2",
        "signature taken whole, never stripped")
    add("er23-r-zero", "reject", "unrecoverable", dict(t_ok, signature=sig_hex(0, st, vt)), TEST_ADDR, "ea2", "r = 0")
    add("er24-s-zero", "reject", "unrecoverable", dict(t_ok, signature=sig_hex(rt, 0, vt)), TEST_ADDR, "ea2", "s = 0")
    add("er25-r-x-not-on-curve", "reject", "unrecoverable", dict(t_ok, signature=sig_hex(smallest_x_off_curve(), st, vt)), TEST_ADDR, "ea2",
        "r = 5, the smallest x >= 1 with no curve point (x = 0 has none either)")

    # payload shape, version, format, input
    add("er26-payload-extra-field", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], memo="not signed")), P1_SIGNER, "ea1",
        "a key outside the Receipt type (declared reading: an unsigned field is refused)")
    add("er27-payload-payer-missing", "reject", "malformed_payload",
        dict(live, payload={k: v for k, v in live["payload"].items() if k != "payer"}), P1_SIGNER, "ea1", "required field missing")
    add("er28-issuedat-as-string", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], issuedAt=str(live["payload"]["issuedAt"]))), P1_SIGNER, "ea1", "uint256 as a JSON string")
    add("er29-issuedat-as-float", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], issuedAt=float(live["payload"]["issuedAt"]))), P1_SIGNER, "ea1", "uint256 as a JSON float")
    add("er30-issuedat-negative", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], issuedAt=-1)), P1_SIGNER, "ea1", "negative uint256")
    add("er31-issuedat-2-256", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], issuedAt=2 ** 256)), P1_SIGNER, "ea1", "2^256 is out of uint256")
    add("er32-version-bool-true", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], version=True)), P1_SIGNER, "ea1", "true is not the integer 1")
    add("er33-payer-not-a-string", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], payer=0)), P1_SIGNER, "ea1", "a string field given as a number")
    add("er34-version-2", "reject", "unsupported_version", signed(test_payload(version=2)), TEST_ADDR, "ea2",
        "x402 5.5 step 2: only version 1 is defined (signed by the test key, still refused)")
    add("er35-format-jws", "reject", "unsupported_format", dict(live, format="jws"), P1_SIGNER, "ea1", "format other than eip712")
    add("er36-expected-signer-malformed", "reject", "malformed_input", live, P1_SIGNER[:-1], "ea1", "expected_signer 0x + 39 hex")
    add("er37-payer-lone-surrogate", "reject", "malformed_payload",
        dict(live, payload=dict(live["payload"], payer="\ud800")), P1_SIGNER, "ea1",
        "a string with a lone surrogate has no UTF-8 bytes for EIP-712 to hash (added after the fuzz, 2026-09-30)")
    # added after verification A (2026-10-01): shapes that had no vector
    add("ea6-signature-uppercase-hex-digits", "valid", None, dict(t_ok, signature="0x" + t_ok["signature"][2:].upper()), TEST_ADDR, "ea2",
        "the same 65 bytes with upper-case hex digits (the 0x prefix stays lower-case)")
    add("er38-artifact-carries-domain-and-types", "reject", "malformed_input",
        dict(t_ok, domain=dict(V.DOMAIN, chainId=8453), types={"Receipt": V.TYPES["Receipt"]}), TEST_ADDR, "ea2",
        "x402: domain and types MUST NOT be transmitted on the wire; a carried domain is refused, never used")
    add("er39-signature-absent", "reject", "malformed_signature", {k: v for k, v in t_ok.items() if k != "signature"}, TEST_ADDR, "ea2",
        "no signature key")
    add("er40-payload-absent", "reject", "malformed_payload", {k: v for k, v in t_ok.items() if k != "payload"}, TEST_ADDR, "ea2",
        "no payload key")
    add("er41-format-absent", "reject", "unsupported_format", {k: v for k, v in t_ok.items() if k != "format"}, TEST_ADDR, "ea2",
        "no format key")
    add("er42-s-equals-n", "reject", "non_canonical_s", dict(t_ok, signature=sig_hex(rt, N, vt)), TEST_ADDR, "ea2",
        "s = n is above n/2: refused by the low-s step, which precedes recovery")
    add("er43-r-equals-n", "reject", "unrecoverable", dict(t_ok, signature=sig_hex(N, st, vt)), TEST_ADDR, "ea2", "r = n")
    add("er44-signature-leading-space", "reject", "malformed_signature", dict(t_ok, signature=" " + t_ok["signature"]), TEST_ADDR, "ea2",
        "signature taken whole, never stripped")
    add("er45-issuedat-nan-token", "reject", "malformed_input", dict(live, payload=dict(live["payload"], issuedAt="@@NAN@@")), P1_SIGNER, "ea1",
        "issuedAt is the token NaN, which is not JSON (RFC 8259)")
    add("er46-duplicate-payer-key", "reject", "malformed_input", dict(live, payload=dict(live["payload"], payer="@@DUP@@")), P1_SIGNER, "ea1",
        "payer appears twice; the first value is not the signed one (a duplicate key could show one value and verify another)")
    return V_


RAW = {"er45-issuedat-nan-token": ('"@@NAN@@"', 'NaN'),
       "er46-duplicate-payer-key": ('"payer": "@@DUP@@"', '"payer": "0x0000000000000000000000000000000000000bad", "payer": "0x36f82906859E5B0bd076069f8cdfAea355358b14"')}


def main(argv):
    out = argv[0] if argv else os.path.join(HERE, "out")
    os.makedirs(os.path.join(out, "vectors"), exist_ok=True)
    vecs = build()
    ids = [v["id"] for v in vecs]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for v in vecs:
        text = json.dumps(v, indent=1, sort_keys=True) + "\n"
        if v["id"] in RAW:
            old, new = RAW[v["id"]]
            assert text.count(old) == 1, v["id"]
            text = text.replace(old, new)
        with open(os.path.join(out, "vectors", v["id"] + ".json"), "w", encoding="utf-8") as fh:
            fh.write(text)
    manifest = {
        "profile": "x402 receipt payload signature (format eip712), independent set",
        "domain": V.DOMAIN, "primaryType": "Receipt",
        "type_string": E.encode_type("Receipt", V.TYPES).decode(),
        "reasons": V.REASONS,
        "test_key": {"derivation": "keccak256(%r) mod n" % KEY_LABEL.decode(), "address": TEST_ADDR,
                     "nonce": "keccak256(b'eip712 independent set nonce v1' || priv32 || digest) mod n"},
        "vectors": [{"file": v["id"] + ".json", "expect": v["expect"], "reject_reason": v["reject_reason"], "kind": v["kind"]} for v in vecs],
        "counts": {"accept": sum(v["expect"] == "valid" for v in vecs), "reject": sum(v["expect"] == "reject" for v in vecs)},
    }
    with open(os.path.join(out, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"{len(vecs)} vectors ({manifest['counts']}) -> {out}")


if __name__ == "__main__":
    main(sys.argv[1:])
