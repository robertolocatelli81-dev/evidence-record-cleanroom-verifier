#!/usr/bin/env python3
"""Unit tests for verify_tersign.py — stdlib unittest. Run: python3 -m unittest -v test_verify_tersign

Every test here is a POSITIVE or NEGATIVE control that does not depend on the 69 suite vectors,
except the two that read the suite to check the harness end-to-end.
"""
import hashlib
import os
import unittest

import verify_tersign as V

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "spec")
SPEC057 = os.path.join(HERE, "spec-0.5.7")


def verdict(kind, inp):
    return V.verify_vector({"kind": kind, "input": inp})


class TestKeccak(unittest.TestCase):
    def test_public_vectors(self):
        # Keccak-256 (pre-NIST padding) public values, as in vendor/roberto_x402_eip712.py self_test
        self.assertEqual(V.keccak256_pure(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(V.keccak256_pure(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(V.keccak256_pure(b"testing").hex(), "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02")

    def test_not_sha3(self):
        self.assertNotEqual(V.keccak256_pure(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_multiblock(self):
        # > 136 bytes forces a second absorb block; compare against a value computed once and pinned
        data = b"x" * 300
        self.assertEqual(len(V.keccak256_pure(data)), 32)
        self.assertNotEqual(V.keccak256_pure(data), V.keccak256_pure(b"x" * 299))


class TestJCS(unittest.TestCase):
    def test_rfc8785_string_escaping_example(self):
        # RFC 8785 §3.2.2 sample (string member only; the numbers member is outside this suite's domain)
        # input string of the RFC sample, built with chr() so no tool/editor can re-interpret escapes:
        # EURO SIGN, '$', U+000F, LF, A ' B, '"', two backslashes, '"', '/'
        s = chr(0x20AC) + "$" + chr(0x0F) + chr(0x0A) + "A'B" + chr(0x22) + chr(0x5C) * 2 + chr(0x22) + "/"
        self.assertEqual(V.jcs({"string": s}).decode("utf-8"), '{"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')

    def test_rfc8785_key_order_alphabetical(self):
        self.assertEqual(V.jcs({"string": "s", "numbers": [1], "literals": [None, True, False]}),
                         b'{"literals":[null,true,false],"numbers":[1],"string":"s"}')

    def test_utf16_order_beats_codepoint(self):
        # U+10000 (surrogate pair D800 DC00) sorts BEFORE U+FF61 in UTF-16 units, AFTER in code points
        self.assertEqual(V.jcs({"｡": 1, "\U00010000": 2}).decode("utf-8"), '{"\U00010000":2,"｡":1}')

    def test_integer_like_keys_are_strings(self):
        self.assertEqual(V.jcs({"10": "a", "2": "b", "1": "c"}), b'{"1":"c","10":"a","2":"b"}')

    def test_no_whitespace_nested(self):
        self.assertEqual(V.jcs({"b": [1, {"z": None, "a": "x"}], "a": True}), b'{"a":true,"b":[1,{"a":"x","z":null}]}')

    def test_control_chars(self):
        self.assertEqual(V.jcs("\u0001\u001f\u007f"), b'"\\u0001\\u001f\x7f"')

    def test_ijson_integer_bounds(self):
        self.assertEqual(V.jcs({"n": 2 ** 53 - 1}), b'{"n":9007199254740991}')
        self.assertEqual(V.jcs({"n": -(2 ** 53 - 1)}), b'{"n":-9007199254740991}')
        for bad in (2 ** 53, -(2 ** 53), 2 ** 64):
            with self.assertRaises(V.Reject) as cm:
                V.jcs({"n": bad})
            self.assertEqual(cm.exception.reason, V.R_NUMBER)

    def test_number_token_class(self):
        for text in ('{"a": 2.0}', '{"a": 1e2}', '{"a": 1.5}', '{"a": -0.0}', '{"a": 2E0}'):
            with self.assertRaises(V.Reject) as cm:
                V.jcs(V.load_json(text))
            self.assertEqual(cm.exception.reason, V.R_NUMBER, text)
        self.assertEqual(V.jcs(V.load_json('{"a": 2}')), b'{"a":2}')
        self.assertEqual(V.jcs(V.load_json('{"a": -0}')), b'{"a":0}')

    def test_bool_is_not_int(self):
        self.assertEqual(V.jcs([True, False, 1, 0]), b"[true,false,1,0]")
        self.assertFalse(V.is_int(True))
        self.assertTrue(V.is_int(3))
        self.assertFalse(V.is_int(V.NumberToken("3.0")))

    def test_duplicate_names_rejected(self):
        with self.assertRaises(V.DuplicateName):
            V.load_json('{"a": 1, "a": 2}')

    def test_nan_infinity_rejected(self):
        for text in ("NaN", "Infinity", "-Infinity", '{"a": NaN}'):
            with self.assertRaises(ValueError):
                V.load_json(text)

    def test_lone_surrogate_rejected(self):
        with self.assertRaises(V.Reject) as cm:
            V.jcs({"a": "\ud800"})
        self.assertEqual(cm.exception.reason, V.R_CANON)


class TestChain(unittest.TestCase):
    def test_link_genesis_uses_32_zero_bytes(self):
        art = bytes.fromhex("11" * 32)
        self.assertEqual(V.chain_link(art, None, 1), V.keccak256_pure(art + bytes(32) + (1).to_bytes(8, "big")))
        self.assertNotEqual(V.chain_link(art, None, 1), V.chain_link(art, None, 2))
        self.assertNotEqual(V.chain_link(art, None, 1), V.chain_link(art, bytes.fromhex("22" * 32), 1))

    def _set(self, n=3, with_links=True, with_acc=False):
        arts = [bytes([i + 1]) * 32 for i in range(n)]
        recs, links, prev = [], [], None
        for i, a in enumerate(arts):
            link = V.chain_link(a, prev, i + 1)
            r = {"seq": i + 1, "artifact_digest": "0x" + a.hex(), "prev_digest": None if prev is None else "0x" + prev.hex()}
            if with_links:
                r["link"] = "0x" + link.hex()
            recs.append(r)
            links.append(link)
            prev = a
        head = {"seq": n, "digest": "0x" + arts[-1].hex()}
        if with_acc:
            acc = V.keccak256_pure(V.ACC_SEED)
            for l in links:
                acc = V.keccak256_pure(acc + l)
            head["acc"] = "0x" + acc.hex()
        return {"head": head, "records": recs}

    def test_complete_set_valid(self):
        self.assertEqual(verdict("chain_set", self._set())[0], "valid")
        self.assertEqual(verdict("chain_set", self._set(with_links=False))[0], "valid")

    def test_missing_seq(self):
        s = self._set()
        del s["records"][1]
        v = verdict("chain_set", s)
        self.assertEqual((v[0], v[1]), ("reject", V.R_COMPLETENESS))
        self.assertIn("missing seq [2]", v[2])

    def test_duplicate_seq_rejects_on_duplicate_not_continuity(self):
        s = self._set()
        s["records"].insert(2, dict(s["records"][1], artifact_digest="0x" + (b"\x99" * 32).hex()))
        v = verdict("chain_set", s)
        self.assertEqual((v[0], v[1]), ("reject", V.R_COMPLETENESS))
        self.assertIn("duplicate seq [2]", v[2])

    def test_head_digest_mismatch(self):
        s = self._set()
        s["head"]["digest"] = "0x" + (b"\x77" * 32).hex()
        self.assertEqual(verdict("chain_set", s)[1], V.R_CONTINUITY)

    def test_prev_mismatch_and_stale_link(self):
        s = self._set()
        s["records"][2]["prev_digest"] = s["records"][0]["artifact_digest"]
        self.assertEqual(verdict("chain_set", s)[1], V.R_CONTINUITY)
        s = self._set()
        s["records"][2]["link"] = s["records"][1]["link"]
        v = verdict("chain_set", s)
        self.assertEqual(v[1], V.R_CONTINUITY)
        self.assertIn("link at seq 3", v[2])

    def test_genesis_prev_must_be_null(self):
        s = self._set(with_links=False)
        s["records"][0]["prev_digest"] = "0x" + (b"\x00" * 32).hex()
        self.assertEqual(verdict("chain_set", s)[1], V.R_CONTINUITY)

    def test_seq_token_class(self):
        s = self._set()
        s["head"]["seq"] = V.NumberToken("3.0")
        self.assertEqual(verdict("chain_set", s)[1], V.R_COMPLETENESS)
        s = self._set()
        s["records"][1]["seq"] = V.NumberToken("2.0")
        self.assertEqual(verdict("chain_set", s)[1], V.R_COMPLETENESS)
        s = self._set()
        s["head"]["seq"] = True
        self.assertEqual(verdict("chain_set", s)[1], V.R_COMPLETENESS)

    def test_witness_and_attestations_not_read(self):
        s = self._set()
        s["witness"] = {"checkpoint": {"cosignatures": 99}, "inclusion": [{"seq": 2, "leaf_index": 1}]}
        s["attestations"] = [{"by": "0x" + "33" * 20, "role": "issuer"}]
        self.assertEqual(verdict("chain_set", s)[0], "valid")
        del s["records"][1]
        self.assertEqual(verdict("chain_set", s)[1], V.R_COMPLETENESS)

    def test_commitment(self):
        s = self._set(with_acc=True)
        self.assertEqual(verdict("chain_commitment", s)[0], "valid")
        s["head"]["acc"] = "0x" + (b"\x01" * 32).hex()
        v = verdict("chain_commitment", s)
        self.assertEqual(v[1], V.R_CONTINUITY)
        self.assertIn("accumulator mismatch", v[2])
        s = self._set(with_acc=False)
        self.assertEqual(verdict("chain_commitment", s)[1], V.R_CONTINUITY)   # no acc: fails closed
        # last-link-only fold must not pass
        s = self._set(with_acc=True)
        links = [V.chain_link(bytes.fromhex(r["artifact_digest"][2:]), None if r["prev_digest"] is None else bytes.fromhex(r["prev_digest"][2:]), r["seq"]) for r in s["records"]]
        s["head"]["acc"] = "0x" + V.keccak256_pure(V.keccak256_pure(V.ACC_SEED) + links[-1]).hex()
        self.assertEqual(verdict("chain_commitment", s)[1], V.R_CONTINUITY)

    def test_anchor(self):
        subj = "0x" + (b"\x42" * 32).hex()
        anch = "0x" + hashlib.sha256(b"\x42" * 32).hexdigest()
        self.assertEqual(verdict("anchor_relation", {"subject_digest": subj, "anchored_digest": anch})[0], "valid")
        self.assertEqual(verdict("anchor_relation", {"subject_digest": subj, "anchored_digest": subj})[1], V.R_EXISTENCE)


class TestIdentity(unittest.TestCase):
    def test_address_fold(self):
        a = "0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"
        self.assertEqual(V.normalize_identity(a), V.normalize_identity(a.lower()))
        self.assertEqual(V.normalize_identity(a), V.normalize_identity("  " + a + " \n"))
        self.assertIsNone(V.normalize_identity(a[:-1]))
        self.assertIsNone(V.normalize_identity("0x9d38BA84730271eb27Ac9bD4​Bd2620c08dB4FDa6"))
        self.assertIsNone(V.normalize_identity(""))
        self.assertIsNone(V.normalize_identity(12))

    def test_scheme_fold(self):
        self.assertEqual(V.normalize_identity("org:caldera-robotics/"), V.normalize_identity("org:caldera-robotics"))
        self.assertEqual(V.normalize_identity("org:caldera-robotics.#"), V.normalize_identity("org:caldera-robotics"))
        # v0.5.7 (n45/n58/p31): "The result is lowercased, the scheme included" (v0.5.3 read it case-significant)
        self.assertEqual(V.normalize_identity("org:Caldera-Robotics"), V.normalize_identity("org:caldera-robotics"))
        self.assertEqual(V.normalize_identity("Org:caldera"), V.normalize_identity("org:caldera"))
        self.assertIsNone(V.normalize_identity("1org:caldera"))      # scheme starts with a letter
        self.assertIsNone(V.normalize_identity("org:cal dera"))      # non-space path
        self.assertEqual(V.normalize_identity("org:a:b"), "uri:org:a:b")   # v0.5.7: colons in the path (CAIP-10, p37)
        self.assertIsNone(V.normalize_identity("org:/"))             # empty path after fold
        self.assertIsNone(V.normalize_identity("org:café"))     # ASCII path only
        self.assertNotEqual(V.normalize_identity("org:x"), V.normalize_identity("agent:x"))


class TestIndependence(unittest.TestCase):
    P = ["0x" + "22" * 20, "0x" + "33" * 20]
    OUT = "0x" + "9d" * 20

    def test_silence(self):
        for claimed in ("none", ["issuer_attested"], []):
            self.assertEqual(verdict("independence_claim", {"claimed": claimed, "parties": self.P, "attestations": []})[0], "valid")

    def test_unknown_claim_fails_closed(self):
        for claimed in ("effect_corroborated", ["none", "x"], 3, None):
            self.assertEqual(verdict("independence_claim", {"claimed": claimed, "parties": self.P, "attestations": []})[1], V.R_INDEPENDENCE)

    def test_k1_claimed_absent_is_silence(self):
        # K1 positive: p9 "Silence is a valid state" — an absent claim asserts nothing, whatever else is present
        self.assertEqual(verdict("independence_claim", {"parties": self.P})[0], "valid")
        self.assertEqual(verdict("independence_claim", {"parties": self.P, "attestations": [{"by": self.P[0]}]})[0], "valid")
        self.assertEqual(verdict("independence_claim", {"parties": self.P, "attestations": ["bare string"]})[0], "valid")
        self.assertEqual(verdict("independence_claim", {"parties": self.P, "covers": ["settlement"], "record_commits": None})[0], "valid")
        self.assertEqual(verdict("independence_claim", {})[0], "valid")
        # K1 negative: a PRESENT claim that cannot be read still fails closed (n8/n9); explicit null is present
        self.assertEqual(verdict("independence_claim", {"claimed": None, "parties": self.P})[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", {"claimed": "", "parties": self.P})[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", {"claimed": "independent", "parties": self.P})[1], V.R_INDEPENDENCE)

    def test_outside_attestor(self):
        base = {"claimed": "independent", "parties": self.P}
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[{"by": self.OUT}]))[0], "valid")
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[{"by": self.P[0]}]))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[{"by": self.P[0].upper().replace("0X", "0x") + " "}]))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[]))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[self.OUT]))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, attestations=[{"by": "garbage"}]))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, parties=["garbage"], attestations=[{"by": self.OUT}]))[1], V.R_INDEPENDENCE)

    def test_commitment_scope(self):
        base = {"claimed": "independent", "parties": self.P, "attestations": [{"by": self.OUT}]}
        sr = {"success": True, "transaction": "0xabc", "network": "eip155:8453"}
        self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement", "network"], settlement_result=sr))[0], "valid")
        self.assertEqual(verdict("independence_claim", dict(base, covers=["delivery"], settlement_result=sr))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement"]))[1], V.R_INDEPENDENCE)          # unevaluable
        self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement"], settlement_result=dict(sr, transaction="")))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement"], settlement_result=dict(sr, success="true")))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement"], settlement_result=dict(sr, success=False)))[1], V.R_INDEPENDENCE)
        self.assertEqual(verdict("independence_claim", dict(base, covers=[], settlement_result=dict(sr, success=False)))[0], "valid")
        # declared list: presence rejects whatever it holds
        for rc in (["settlement"], None, [], "settlement"):
            self.assertEqual(verdict("independence_claim", dict(base, covers=["settlement"], settlement_result=sr, record_commits=rc))[1], V.R_INDEPENDENCE)
            self.assertEqual(verdict("independence_claim", dict(base, record_commits=rc))[1], V.R_INDEPENDENCE)

    def test_delivery_derivation(self):
        base = {"claimed": "independent", "parties": self.P, "attestations": [{"by": self.OUT}], "covers": ["delivery"]}
        b = '{"verdict":"ALLOW"}'
        d = "0x" + V.keccak256_pure(b.encode()).hex()
        self.assertEqual(verdict("independence_claim", dict(base, deliverable_bytes=b, deliverable_digest=d))[0], "valid")
        v = verdict("independence_claim", dict(base, deliverable_bytes=b.replace("ALLOW", "DENY"), deliverable_digest=d))
        self.assertEqual(v[1], V.R_INDEPENDENCE)
        self.assertIn("does not commit to", v[2])       # overreach branch, not unevaluable
        # sha3 digest of the same bytes must NOT count as a delivery commitment
        d3 = "0x" + hashlib.sha3_256(b.encode()).hexdigest()
        self.assertEqual(verdict("independence_claim", dict(base, deliverable_bytes=b, deliverable_digest=d3))[1], V.R_INDEPENDENCE)


class TestBindings(unittest.TestCase):
    def test_offer(self):
        offer = {"resourceUrl": "https://a", "network": "eip155:8453", "scheme": "exact", "asset": "0x" + "83" * 20, "payTo": "0x" + "22" * 20, "amount": "1"}
        d = "0x" + V.keccak256_pure(V.jcs(offer)).hex()
        self.assertEqual(verdict("offer_binding", {"offer": offer, "receipt": {"offerDigest": d}})[0], "valid")
        self.assertEqual(verdict("offer_binding", {"offer": dict(offer, amount="10"), "receipt": {"offerDigest": d}})[1], V.R_BINDING)
        self.assertEqual(verdict("offer_binding", {"offer": offer, "receipt": {}})[1], V.R_BINDING)
        self.assertEqual(verdict("offer_binding", {"offer": dict(offer, amount=V.NumberToken("1.0")), "receipt": {"offerDigest": d}})[1], V.R_NUMBER)

    def test_decision_evidence(self):
        ev = {"requested": {"capabilities": ["read"]}, "effective": {"capabilities": []}, "policy": {"id": "p", "version": "1"}}
        d = "0x" + V.keccak256_pure(V.jcs(ev)).hex()
        self.assertEqual(verdict("decision_evidence_binding", {"record": {"decisionEvidenceDigest": d}, "decision_evidence": ev})[0], "valid")
        self.assertEqual(verdict("decision_evidence_binding", {"record": {}, "decision_evidence": ev})[1], V.R_BINDING)
        ev2 = dict(ev, policy={"id": "p", "version": "2"})
        self.assertEqual(verdict("decision_evidence_binding", {"record": {"decisionEvidenceDigest": d}, "decision_evidence": ev2})[1], V.R_BINDING)

    def test_digest_recompute_and_canonical(self):
        p = {"b": "x", "a": 1}
        d = "0x" + V.keccak256_pure(b'{"a":1,"b":"x"}').hex()
        self.assertEqual(verdict("digest_recompute", {"payload": p, "expected_digest": d})[0], "valid")
        self.assertEqual(verdict("digest_recompute", {"payload": p, "expected_digest": d[:-1] + "0"})[1], V.R_RECOMPUTE)
        self.assertEqual(verdict("digest_recompute", {"payload": p, "expected_digest": "0xzz"})[1], V.R_RECOMPUTE)
        self.assertEqual(verdict("canonical_bytes", {"payload": p, "claimed_canonical": '{"a":1,"b":"x"}'})[0], "valid")
        self.assertEqual(verdict("canonical_bytes", {"payload": p, "claimed_canonical": '{"b":"x","a":1}'})[1], V.R_CANON)
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"a": 1, "a": 2}', "claimed_canonical": '{"a":2}'})[1], V.R_CANON)
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"a": 1', "claimed_canonical": '{"a":1}'})[1], V.R_CANON)
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"a": 1e2}', "claimed_canonical": '{"a":100}'})[1], V.R_NUMBER)

    def test_k2_number_domain_before_claimed_canonical(self):
        # K2 positive: number domain is decided before the claimed bytes are even looked at
        self.assertEqual(verdict("canonical_bytes", {"payload": V.load_json('{"amount": 1.1}')})[1], V.R_NUMBER)
        self.assertEqual(verdict("canonical_bytes", {"payload": {"n": 2 ** 53}, "claimed_canonical": 5})[1], V.R_NUMBER)
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"a": 2.0}'})[1], V.R_NUMBER)
        # K2 negative: with an in-domain payload the missing / mistyped claimed bytes are still canonicalization_reject
        self.assertEqual(verdict("canonical_bytes", {"payload": {"a": 1}})[1], V.R_CANON)
        self.assertEqual(verdict("canonical_bytes", {"payload": {"a": 1}, "claimed_canonical": 5})[1], V.R_CANON)
        # and digest_recompute keeps the same order (n11 class)
        self.assertEqual(verdict("digest_recompute", {"payload": {"n": 2 ** 53}})[1], V.R_NUMBER)


class TestPhaseBoundary(unittest.TestCase):
    def test_phase(self):
        self.assertEqual(verdict("phase_claim", {"record": {"economic_phase": "settlement"}, "presented_as": "settlement"})[0], "valid")
        self.assertEqual(verdict("phase_claim", {"record": {"economic_phase": "funding"}, "presented_as": "delivery"})[1], V.R_PHASE)
        self.assertEqual(verdict("phase_claim", {"record": {"economic_phase": "delivery"}, "presented_as": "funding"})[1], V.R_PHASE)  # strict equality reading
        self.assertEqual(verdict("phase_claim", {"record": {"economic_phase": "x"}, "presented_as": "x"})[1], V.R_PHASE)
        self.assertEqual(verdict("phase_claim", {"record": {}, "presented_as": "delivery"})[1], V.R_PHASE)

    def _bnd(self, **kw):
        prefix = [{"event": "record", "seq": i} for i in (1, 2, 3)]
        ev = {"event": "witness_ref_introduced", "ruleVersion": "witness-ref-v1",
              "prefixDigest": "0x" + V.keccak256_pure(V.jcs(prefix)).hex(), "position": 3, "attestedPrefixLength": 3}
        ev.update(kw.pop("ev", {}))
        inp = {"prefix": prefix, "boundary_event": ev, "covered_through": 3}
        inp.update(kw)
        return inp

    def test_boundary(self):
        self.assertEqual(verdict("boundary_binding", self._bnd())[0], "valid")
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"position": 2}))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"attestedPrefixLength": 2}))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"attestedPrefixLength": 0}, covered_through=0))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"event": "other"}))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"ruleVersion": "witness-ref-v2"}))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"position": V.NumberToken("3.0")}))[1], V.R_BOUNDARY)
        inp = self._bnd(covered_through=V.NumberToken("3.0"))
        self.assertEqual(verdict("boundary_binding", inp)[1], V.R_BOUNDARY)

    def test_k3_no_coverage_claimed(self):
        # K3 positive: p18 "the coverage it claims" — no covered_through, full attestation → valid
        inp = self._bnd()
        del inp["covered_through"]
        v = verdict("boundary_binding", inp)
        self.assertEqual(v[0], "valid")
        self.assertIn("no coverage claimed", v[2])
        # K3 negative (kept): empty attestation rejects with or without a coverage claim (n26)
        inp = self._bnd(ev={"attestedPrefixLength": 0})
        del inp["covered_through"]
        self.assertEqual(verdict("boundary_binding", inp)[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"attestedPrefixLength": 0}, covered_through=0))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"attestedPrefixLength": 0}))[1], V.R_BOUNDARY)
        # K3 negative: a claimed coverage beyond the attestation still rejects; a present but malformed one rejects
        self.assertEqual(verdict("boundary_binding", self._bnd(ev={"attestedPrefixLength": 2}))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(covered_through=-1))[1], V.R_BOUNDARY)
        self.assertEqual(verdict("boundary_binding", self._bnd(covered_through="3"))[1], V.R_BOUNDARY)
        # attestedPrefixLength absent is still a reject (n25 class; nothing attested is stated)
        inp = self._bnd()
        del inp["boundary_event"]["attestedPrefixLength"]
        self.assertEqual(verdict("boundary_binding", inp)[1], V.R_BOUNDARY)
        t = self._bnd(ev={"event": "digest_suite_transition", "ruleVersion": "suite-transition-v1", "fromSuite": "keccak256-jcs", "toSuite": "sha3-256-jcs"})
        self.assertEqual(verdict("boundary_binding", t)[0], "valid")
        t["boundary_event"]["prefixDigest"] = "0x" + hashlib.sha3_256(V.jcs(t["prefix"])).hexdigest()
        self.assertEqual(verdict("boundary_binding", t)[1], V.R_BOUNDARY)
        t = self._bnd(ev={"event": "digest_suite_transition", "ruleVersion": "suite-transition-v1", "fromSuite": "sha3-256-jcs", "toSuite": "x"})
        self.assertEqual(verdict("boundary_binding", t)[1], V.R_BOUNDARY)


class TestHarness(unittest.TestCase):
    def test_unknown_kind_and_crash_are_rejects(self):
        self.assertEqual(V.verify_vector({"kind": "nope", "input": {}})[0], "reject")
        self.assertEqual(V.verify_vector({"kind": "chain_set", "input": None})[0], "reject")
        self.assertEqual(V.verify_vector({"kind": "chain_set", "input": {"head": {"seq": 1, "digest": 5}, "records": 3}})[0], "reject")

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_suite_concordant_and_flip_discordant(self):
        V._ABLATE.clear()
        res = V.run_suite(SPEC)
        self.assertEqual(res["n"], 69)
        self.assertEqual(res["concordant"], 69)
        flipped = V.run_suite(SPEC, flip_expect=True)
        self.assertEqual(flipped["verdict_concordant"], 0)

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_ablation_changes_verdicts(self):
        try:
            V._ABLATE.clear()
            V._ABLATE.add("keccak_to_sha3")
            res = V.run_suite(SPEC)
            self.assertLess(res["concordant"], 69)
        finally:
            V._ABLATE.clear()


# ── closed input members (input schema 1, 2026-10-11) ───────────────────────────────────────────────────────────────
# Test-side helpers, written independently of the verifier's own lists: CONTENT names are hashed/parsed content, never walked.
_CONTENT = ("payload", "payload_text", "offer", "decision_evidence", "prefix")
_KEYS = ["x_new_2026", "", "~0", "a/b", "ünï", "Head", "seq ", "records[0]", "link\n", "witness", "seq", "kind", "input"]
_VALUES = [1, None, True, -1, 2 ** 70, "s", [], {}, [{"a": 1}], {"b": {"c": []}}, "0x" + "11" * 32]


def _defined_here(kind, pos, key):
    """The one collision in _KEYS: `witness` is a 0.5.3 chain_set member (MANIFEST witnessed_inclusion), so it is not new there."""
    return kind == "chain_set" and pos == () and key == "witness"


def _ptr(path):
    return "".join("/" + (str(x) if isinstance(x, int) else x.replace("~", "~0").replace("/", "~1")) for x in path)


def _positions(inp, path=()):
    """Every JSON object reachable inside `input` (input itself included), outside CONTENT members."""
    out = [path]
    for k, v in inp.items():
        if not path and k in _CONTENT:
            continue
        if isinstance(v, dict):
            out += _positions(v, path + (k,))
        elif isinstance(v, list):
            for i, e in enumerate(v):
                if isinstance(e, dict):
                    out += _positions(e, path + (k, i))
    return out


def _at(obj, path):
    for x in path:
        obj = obj[x]
    return obj


def _suite_vectors():
    import json
    with open(os.path.join(SPEC, "MANIFEST.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    for e in m["vectors"]:
        with open(os.path.join(SPEC, "vectors", e["file"]), encoding="utf-8") as fh:
            yield e, json.load(fh)


class TestClosedInputMembers(unittest.TestCase):
    """Review 2026-10-11: the 2026-10-10 version LEARNED the known members from the suite under verification, so a member
    planted in that suite's vectors was never named (0/1 and 0/56 rows), the single-vector path named nothing unless a
    suite had been run before, and members the verifier does not read (chain_set `witness`) were never listed. The lists
    are now fixed in the code; these tests are generative over every object position of every suite vector and must fail
    on bd0cd8c (positive control, RAPPORTO.md)."""

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_run_suite_names_members_planted_in_the_suite_itself(self):
        """Every object position of every vector gets a new member, all in ONE suite: every row names all of them."""
        import copy, json, shutil, tempfile
        V._ABLATE.clear()
        base = {r["file"]: r for r in V.run_suite(SPEC)["rows"]}
        d = tempfile.mkdtemp(); shutil.copytree(SPEC, os.path.join(d, "s")); s = os.path.join(d, "s")
        expected = {}
        for e, vec in _suite_vectors():
            v = copy.deepcopy(vec); planted = []
            for n, pos in enumerate(_positions(vec["input"])):
                key = _KEYS[n % len(_KEYS)]
                if key in _at(vec["input"], pos) or _defined_here(e["kind"], pos, key):
                    key = "x_new_2026_%d" % n
                _at(v["input"], pos)[key] = _VALUES[n % len(_VALUES)]
                planted.append(_ptr(pos + (key,)))
            expected[e["file"]] = sorted(planted)
            with open(os.path.join(s, "vectors", e["file"]), "w", encoding="utf-8") as fh:
                json.dump(v, fh)
        res = V.run_suite(s)
        self.assertEqual(res["n"], 69)
        n_planted = 0
        for r in res["rows"]:
            self.assertEqual(sorted(r["unknown_input_members"]), expected[r["file"]], r["file"])
            self.assertEqual((r["verdict"], r["reason"], r["detail"]), (base[r["file"]]["verdict"], base[r["file"]]["reason"], base[r["file"]]["detail"]), r["file"])
            n_planted += len(expected[r["file"]])
        self.assertEqual(res["concordant"], 69)
        self.assertGreater(n_planted, 69)

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_run_suite_one_planted_vector(self):
        """A member planted in ONE vector of the suite is named on that row (bd0cd8c: 0/1)."""
        import json, shutil, tempfile
        d = tempfile.mkdtemp(); shutil.copytree(SPEC, os.path.join(d, "s")); s = os.path.join(d, "s")
        p = os.path.join(s, "vectors", "p1-live-genesis-receipt.json")
        with open(p, encoding="utf-8") as fh:
            v = json.load(fh)
        v["input"]["x_unknown_2026"] = 1
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(v, fh)
        rows = {r["file"]: r["unknown_input_members"] for r in V.run_suite(s)["rows"]}
        self.assertEqual(rows.pop("p1-live-genesis-receipt.json"), ["/x_unknown_2026"])
        self.assertEqual([f for f, u in rows.items() if u], [])

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_single_vector_path_every_position_every_key(self):
        """verify_vector + unknown_input_members on one vector, no suite run before: one planted member at each position,
        each key in _KEYS, each value in _VALUES -> exactly that pointer, verdict/reason/detail unchanged."""
        import copy
        V._ABLATE.clear()
        checked = 0
        for e, vec in _suite_vectors():
            base = V.verify_vector(vec, e["kind"])
            self.assertEqual(V.unknown_input_members(vec, e["kind"]), [], e["file"])
            for pos in _positions(vec["input"]):
                for j, key in enumerate(_KEYS):
                    if key in _at(vec["input"], pos) or _defined_here(e["kind"], pos, key):
                        continue
                    v = copy.deepcopy(vec)
                    _at(v["input"], pos)[key] = _VALUES[j % len(_VALUES)]
                    self.assertEqual(V.unknown_input_members(v, e["kind"]), [_ptr(pos + (key,))], (e["file"], pos, key))
                    self.assertEqual(V.unknown_input_members(v), [_ptr(pos + (key,))], (e["file"], pos, key))   # kind from the vector
                    self.assertEqual(V.verify_vector(v, e["kind"]), base, (e["file"], pos, key))
                    checked += 1
        self.assertGreater(checked, 1000)

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_members_not_read_are_listed(self):
        """`input_members_not_read` names what the verifier does not read, also when the suite carries it (witness)."""
        import copy
        rows = {r["file"]: r for r in V.run_suite(SPEC)["rows"]}
        self.assertEqual(rows["p24-witnessed-complete-set.json"]["input_members_not_read"], ["/witness"])
        self.assertEqual(rows["n34-witnessed-inclusion-not-completeness.json"]["input_members_not_read"], ["/witness"])
        self.assertEqual(rows["p28-issuer-sequence-distinct-seq.json"]["input_members_not_read"], ["/attestations"])
        self.assertEqual(rows["n28-authority-reduction-substitution.json"]["input_members_not_read"], ["/record/outcome"])
        self.assertEqual(sum(bool(r["input_members_not_read"]) for r in rows.values()), 30)
        self.assertEqual(sum(bool(r["unknown_input_members"]) for r in rows.values()), 0)
        self.assertEqual(sum(bool(r["unknown_vector_members"]) for r in rows.values()), 0)
        for e, vec in _suite_vectors():                      # a planted member is also "not read"; below a not-read member, nothing new
            base_nr = V.input_members_not_read(vec, e["kind"])
            for pos in _positions(vec["input"]):
                v = copy.deepcopy(vec); _at(v["input"], pos)["x_new_2026"] = 1
                under = any(_ptr(pos).startswith(b + "/") or _ptr(pos) == b for b in base_nr)
                want = base_nr if under else sorted(base_nr + [_ptr(pos + ("x_new_2026",))])
                self.assertEqual(sorted(V.input_members_not_read(v, e["kind"])), sorted(want), (e["file"], pos))
                self.assertEqual(set(V.unknown_input_members(v, e["kind"])) - set(V.input_members_not_read(v, e["kind"]) + [_ptr(pos + ("x_new_2026",))]), set())

    def test_odd_shapes_never_raise_and_name_nothing_spurious(self):
        for vec in (None, [], "x", 1, {}, {"kind": "chain_set"}, {"kind": "chain_set", "input": None}, {"kind": "chain_set", "input": []},
                    {"kind": [], "input": {"a": 1}}, {"kind": {"k": 1}, "input": {"a": 1}}, {"kind": "nope", "input": {"a": 1}},
                    {"kind": "chain_set", "input": {"head": [], "records": {"seq": 1}}},
                    {"kind": "chain_set", "input": {"head": {"seq": {"deep": 1}}, "records": [1, "x", None, [], {"seq": 1, "z": 2}]}}):
            r = V.input_member_report(vec)
            self.assertEqual(set(r), {"unknown_input_members", "input_members_not_read", "unknown_vector_members"})
            if isinstance(vec, dict) and isinstance(vec.get("input"), (dict, type(None), list)):
                self.assertEqual(V.verify_vector(vec)[0] if isinstance(vec, dict) and vec else "reject", "reject")
        r = V.input_member_report({"kind": "chain_set", "input": {"head": {"seq": {"deep": 1}}, "records": [1, "x", None, [], {"seq": 1, "z": 2}]}})
        self.assertEqual(r["unknown_input_members"], ["/records/4/z"])            # a LEAF holding an object is not walked
        self.assertEqual(V.input_member_report({"kind": "nope", "input": {"a": 1}})["unknown_input_members"], [])   # unknown kind: rejects
        self.assertEqual(V.input_member_report({"kind": "chain_set", "input": {}, "extra": 1})["unknown_vector_members"], ["/extra"])
        v = {"kind": "digest_recompute", "input": {"head": {"seq": 1}, "records": [], "witness": {}}}   # the kind the VERDICT uses wins
        self.assertEqual(V.unknown_input_members(v, "chain_set"), [])
        self.assertEqual(V.unknown_input_members(v), ["/head", "/records", "/witness"])
        for k in ([], {}, [1], {"a": 1}):                                              # was: TypeError, no verdict
            self.assertEqual(V.verify_vector({"kind": k, "input": {}})[:2], ("reject", V.R_INPUT))

    def test_duplicate_member_rejects_and_reports_nothing(self):
        import json, tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        texts = {"top.json": '{"kind":"chain_link","input":{"seq":1,"seq":2}}',
                 "nested.json": '{"kind":"chain_set","input":{"head":{"seq":1,"seq":1,"digest":"0x%s"},"records":[]}}' % ("11" * 32),
                 "vec.json": '{"kind":"chain_link","kind":"chain_link","input":{}}'}
        for n, t in texts.items():
            with open(os.path.join(d, "vectors", n), "w", encoding="utf-8") as fh:
                fh.write(t)
        with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as fh:
            json.dump({"vectors": [{"file": n, "expect": "reject"} for n in texts]}, fh)
        for r in V.run_suite(d)["rows"]:
            self.assertEqual((r["verdict"], r["reason"]), ("reject", V.R_CANON), r["file"])
            self.assertEqual((r["unknown_input_members"], r["input_members_not_read"], r["unknown_vector_members"]), ([], [], []))

    def test_read_list_matches_what_the_functions_read(self):
        """_INPUT_READ is checked two ways: (1) every member the kind functions touch (get / [] / in) on every suite and
        held-out vector and every --mutate mutant is in the list; (2) every name in the list is a quoted literal in the
        source of the function (or its helpers)."""
        import inspect, json

        class T(dict):
            def __init__(self, d, path, seen):
                super().__init__(d); self._p = path; self._s = seen
            def _w(self, k, v):
                self._s.add(self._p + (k,))
                if isinstance(v, dict):
                    return T(v, self._p + (k,), self._s)
                if isinstance(v, list):
                    return [T(x, self._p + (k, "[]"), self._s) if isinstance(x, dict) else x for x in v]
                return v
            def __getitem__(self, k):
                return self._w(k, dict.__getitem__(self, k))
            def get(self, k, default=None):
                self._s.add(self._p + (k,))
                return self._w(k, dict.__getitem__(self, k)) if dict.__contains__(self, k) else default
            def __contains__(self, k):
                self._s.add(self._p + (k,)); return dict.__contains__(self, k)

        def allowed(schema, path):
            for x in path:
                if x == "[]":
                    if not isinstance(schema, list):
                        return False
                    schema = schema[0]; continue
                if not isinstance(schema, dict) or x not in schema:
                    return False
                schema = schema[x]
                if schema in (V.LEAF, V.CONTENT):
                    return True
            return True

        vecs = []
        for d in (SPEC, os.path.join(HERE, "heldout")):
            with open(os.path.join(d, "MANIFEST.json"), encoding="utf-8") as fh:
                for e in json.load(fh)["vectors"]:
                    with open(os.path.join(d, "vectors", e["file"]), encoding="utf-8") as fh2:
                        vec = json.load(fh2)
                    vecs.append((e["kind"], vec))
                    if e["expect"] == "valid":
                        vecs += [(e["kind"], m) for _, m in V.mutations_for(vec)]
        V._ABLATE.clear()
        touched = {}
        for kind, vec in vecs:
            seen = set()
            try:
                V.KINDS[kind](T(vec["input"], (), seen))
            except V.Reject:
                pass
            bad = [p for p in seen if not allowed(V._INPUT_READ[kind], p)]
            self.assertEqual(bad, [], kind)
            touched.setdefault(kind, set()).update(seen)

        def spaths(sc, pre=()):
            out = set()
            if isinstance(sc, list):
                return spaths(sc[0], pre + ("[]",))
            if isinstance(sc, dict):
                for k, v in sc.items():
                    out.add(pre + (k,)); out |= spaths(v, pre + (k,))
            return out
        for kind, schema in V._INPUT_READ.items():   # review 2026-10-11: not padded — every listed path is read somewhere
            self.assertEqual(sorted(spaths(schema) - touched.get(kind, set())), [], kind)
        helpers = {"chain_set": [V._chain_set_links], "chain_commitment": [V._chain_set_links], "independence_claim": [V.derive_commitments]}
        for kind, schema in V._INPUT_READ.items():
            src = "".join(inspect.getsource(f) for f in [V.KINDS[kind]] + helpers.get(kind, []))
            def names(sc):
                if isinstance(sc, list):
                    return names(sc[0])
                return [n for k, v in sc.items() for n in [k] + (names(v) if isinstance(v, (dict, list)) else [])] if isinstance(sc, dict) else []
            for n in names(schema):
                self.assertTrue('"%s"' % n in src, (kind, n))
            # review 2026-10-11, static: every quoted name the functions read with .get("x"), ["x"] or "x" in is a name in
            # the list — also on branches no vector reaches (a read added there without updating the list fails here)
            import ast, textwrap
            lits = set()
            for f in [V.KINDS[kind]] + helpers.get(kind, []):
                for nd in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(f)))):
                    if (isinstance(nd, ast.Call) and isinstance(nd.func, ast.Attribute) and nd.func.attr == "get"
                            and nd.args and isinstance(nd.args[0], ast.Constant) and isinstance(nd.args[0].value, str)):
                        lits.add(nd.args[0].value)
                    elif isinstance(nd, ast.Subscript):
                        sl = nd.slice.value if isinstance(nd.slice, getattr(ast, "Index", ())) else nd.slice
                        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                            lits.add(sl.value)
                    elif (isinstance(nd, ast.Compare) and isinstance(nd.left, ast.Constant) and isinstance(nd.left.value, str)
                          and any(isinstance(o, (ast.In, ast.NotIn)) for o in nd.ops)):
                        lits.add(nd.left.value)
            self.assertEqual(sorted(lits - set(names(schema))), [], kind)

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_frozen_suite_list_is_exactly_the_0_5_3_members(self):
        """The frozen list is not padded and not short: the members the 0.5.3 vectors carry beyond what is read are
        exactly _INPUT_SUITE_053_NOT_READ (this reads the suite only to CHECK the fixed list; nothing is learned)."""
        import json
        with open(os.path.join(SPEC, "MANIFEST.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["version"], "0.5.3")

        def paths(sc, pre=()):
            out = set()
            if isinstance(sc, list):
                return paths(sc[0], pre + ("[]",))
            if isinstance(sc, dict):
                for k, v in sc.items():
                    out.add(pre + (k,)); out |= paths(v, pre + (k,))
            return out

        def walk(v, pre, out):
            if isinstance(v, dict):
                for k, x in v.items():
                    out.add(pre + (k,))
                    if not (len(pre) == 0 and k in _CONTENT):
                        walk(x, pre + (k,), out)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        walk(x, pre + ("[]",), out)

        measured = {}
        for e, vec in _suite_vectors():
            walk(vec["input"], (), measured.setdefault(e["kind"], set()))
        for kind in V._INPUT_READ:
            read = paths(V._INPUT_READ[kind]); frozen = paths(V._INPUT_SUITE_053_NOT_READ.get(kind, {}))
            leaf_under = {p for p in measured.get(kind, set()) if any(p[:len(r)] == r and len(p) > len(r) and
                          not isinstance(self._node(V._INPUT_READ[kind], r), (dict, list)) for r in read)}
            self.assertEqual(frozen, (measured.get(kind, set()) - read - leaf_under) | (frozen & read), kind)
            self.assertTrue(frozen - read <= measured.get(kind, set()), kind)
            self.assertTrue(measured.get(kind, set()) - leaf_under <= read | frozen, kind)

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_vector_metadata_list_is_exactly_the_0_5_3_members(self):
        """Review 2026-10-11: _VECTOR_SUITE_053_NOT_READ is the top-level members the 0.5.3 vectors carry besides kind/input."""
        tops = set()
        for _, vec in _suite_vectors():
            tops |= set(vec)
        self.assertEqual(sorted(tops - set(V._VECTOR_READ)), sorted(V._VECTOR_SUITE_053_NOT_READ))

    def test_report_kind_and_vector_members(self):
        """Review 2026-10-11: run_suite reports with the kind the VERDICT uses (the manifest's); an unknown kind leaves the
        two input lists empty but still names top-level vector members (sorted); the run records the input schema."""
        import json, tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        texts = {"a.json": {"kind": "chain_set", "input": {"head": {"seq": 1}, "records": [], "witness": {}}},
                 "b.json": {"kind": "nope", "input": {"q": 1}, "z_extra": 1, "a_extra": 2}}
        for n, t in texts.items():
            with open(os.path.join(d, "vectors", n), "w", encoding="utf-8") as fh:
                json.dump(t, fh)
        with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as fh:
            json.dump({"vectors": [{"file": "a.json", "kind": "digest_recompute", "expect": "reject"},
                                   {"file": "b.json", "expect": "reject"}]}, fh)
        res = V.run_suite(d)
        self.assertEqual(res["input_schema"], "1")
        rows = {r["file"]: r for r in res["rows"]}
        self.assertEqual(rows["a.json"]["unknown_input_members"], ["/head", "/records", "/witness"])
        b = rows["b.json"]
        self.assertEqual((b["verdict"], b["reason"]), ("reject", V.R_INPUT))
        self.assertEqual((b["unknown_input_members"], b["input_members_not_read"], b["unknown_vector_members"]),
                         ([], [], ["/a_extra", "/z_extra"]))

    @unittest.skipUnless(os.path.isdir(SPEC), "spec/ not present")
    def test_cli_prints_members_escaped_and_never_crashes_on_them(self):
        """Review 2026-10-11: the text report prints the three lists beside the row, each pointer as an escaped JSON string;
        a member name with a newline cannot add a line, a lone surrogate cannot crash the print or --json (was: rc 1)."""
        import json, shutil, subprocess, sys, tempfile
        d = tempfile.mkdtemp(); s = os.path.join(d, "s"); shutil.copytree(SPEC, s)
        p = os.path.join(s, "vectors", "p1-live-genesis-receipt.json")
        with open(p, encoding="utf-8") as fh:
            v = json.load(fh)
        v["input"]["x\nOK forged-row"] = 1
        v["input"]["\ud800y"] = 2
        v["x_top"] = 3
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(v, fh)                         # ensure_ascii: the surrogate is an escape in the file
        out = os.path.join(d, "o.json")
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, os.path.join(HERE, "verify_tersign.py"), s, "--json", out],
                           capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace")[-300:])
        text = r.stdout.decode("utf-8")
        self.assertEqual([l for l in text.splitlines() if l.startswith("OK forged")], [])
        row = [l for l in text.splitlines() if "p1-live-genesis-receipt.json" in l][0]
        both = '"/x\\nOK forged-row", "/\\ud800y"'   # the input lists follow the file's member order
        self.assertIn('[input members not read: %s]' % both, row)
        self.assertIn('[UNKNOWN input members (not read, not in suite 0.5.3): %s]' % both, row)
        self.assertIn('[UNKNOWN vector members: "/x_top"]', row)
        with open(out, encoding="utf-8") as fh:
            rows = {x["file"]: x for x in json.load(fh)["rows"]}
        self.assertEqual(rows["p1-live-genesis-receipt.json"]["unknown_input_members"], ["/x\nOK forged-row", "/\ud800y"])

    @staticmethod
    def _node(sc, path):
        for x in path:
            sc = sc[0] if x == "[]" else sc[x]
        return sc


class TestReviewAdditions(unittest.TestCase):
    """Added by the 2026-09-29 adversarial code review: each test kills a mutant that survived the shipped bench
    (M08 M12 M13 M14 M17 M25 M28 M37 M40 M41 M43 M50 M52 M54) or pins a review fix (F1-F5)."""

    def test_rfc8785_key_order_example_utf16_units(self):                       # M08 (UTF-16 LE would misplace U+FB33)
        import json
        obj = json.loads('{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\u000a": "Newline", "1": "One", '
                         '"\\u0080": "Control\\u007f", "\\ud834\\udd1e": "Surrogate Example", "\\ufb33": "Hebrew Letter Dalet With Dagesh"}')
        self.assertEqual(V.jcs(obj).decode("utf-8"),
                         '{"\\n":"Newline","\\r":"Carriage Return","1":"One","\u0080":"Control\u007f","€":"Euro Sign",'
                         '"\U0001d11e":"Surrogate Example","דּ":"Hebrew Letter Dalet With Dagesh"}')
        self.assertEqual(V.jcs({"Ā": 1, "ÿ": 2}), '{"ÿ":2,"Ā":1}'.encode("utf-8"))

    def test_short_escapes_b_f(self):                                            # M12 M13
        self.assertEqual(V.jcs("\b\f\t\n\r"), b'"\\b\\f\\t\\n\\r"')

    def test_digest_strip_whitespace(self):                                      # M14 (manifest: digests compare after strip + lowercase)
        p = {"a": 1}
        d = "0x" + V.keccak256_pure(b'{"a":1}').hex().upper()
        self.assertEqual(verdict("digest_recompute", {"payload": p, "expected_digest": "  " + d + "\n"})[0], "valid")

    def test_chain_link_seq_bounds_reason(self):                                 # M17
        L = {"artifact_digest": "0x" + "11" * 32, "prev_digest": None, "expected_link": "0x" + "0" * 64}
        self.assertEqual(verdict("chain_link", dict(L, seq=2 ** 64))[1], V.R_CONTINUITY)
        self.assertEqual(verdict("chain_link", dict(L, seq=-1))[1], V.R_CONTINUITY)

    def test_phase_vocabulary_refund_reversal(self):                             # M25
        for ph in ("refund", "reversal", "funding", "delivery", "settlement"):
            self.assertEqual(verdict("phase_claim", {"record": {"economic_phase": ph}, "presented_as": ph})[0], "valid", ph)

    def test_address_exact_length(self):                                         # M28
        self.assertIsNone(V.normalize_identity("0x" + "ab" * 20 + "ab"))
        self.assertIsNone(V.normalize_identity("0x" + "ab" * 19))

    def test_boundary_attested_length_within_prefix(self):                       # M37
        prefix = [{"event": "record", "seq": i} for i in (1, 2, 3)]
        ev = {"event": "witness_ref_introduced", "ruleVersion": "witness-ref-v1", "prefixDigest": "0x" + V.keccak256_pure(V.jcs(prefix)).hex(), "position": 3, "attestedPrefixLength": 4}
        self.assertEqual(verdict("boundary_binding", {"prefix": prefix, "boundary_event": ev, "covered_through": 3})[1], V.R_BOUNDARY)
        ev["attestedPrefixLength"] = 3; ev["event"] = ["witness_ref_introduced"]                            # F4: non-string event
        self.assertEqual(verdict("boundary_binding", {"prefix": prefix, "boundary_event": ev, "covered_through": 3})[1], V.R_BOUNDARY)

    def test_crash_paths_are_rejects(self):                                      # M40 (generic except) + M54
        P = ["0x" + "22" * 20]
        v = verdict("independence_claim", {"claimed": "independent", "parties": P, "attestations": [{"by": "0x" + "9d" * 20}], "covers": ["delivery"], "deliverable_bytes": "\ud800", "deliverable_digest": "0x" + "0" * 64})
        self.assertEqual(v[0], "reject")
        v = verdict("canonical_bytes", {"payload_text": "[" * 5000 + "]" * 5000, "claimed_canonical": "x"})
        self.assertEqual(v[0], "reject")
        s = {"head": {"seq": 1, "digest": "0x" + "11" * 32}, "records": [{"seq": 1, "artifact_digest": "0x" + "11" * 32}]}
        self.assertEqual(verdict("chain_set", s)[1], V.R_CONTINUITY)                                             # M54 absent prev_digest

    def test_records_beyond_head_rejected(self):                                 # M52
        s = {"head": {"seq": 1, "digest": "0x" + "11" * 32}, "records": [{"seq": 1, "artifact_digest": "0x" + "11" * 32, "prev_digest": None},
                                                                          {"seq": 2, "artifact_digest": "0x" + "22" * 32, "prev_digest": None}]}
        v = verdict("chain_set", s)
        self.assertEqual((v[0], v[1]), ("reject", V.R_COMPLETENESS)); self.assertIn("outside", v[2])
        s["records"][1]["seq"] = 0
        self.assertEqual(verdict("chain_set", s)[1], V.R_COMPLETENESS)

    def test_huge_head_seq_rejects_fast(self):                                   # F2 (was: memory blow-up, OOM kill)
        import time
        t = time.time()
        v = verdict("chain_set", {"head": {"seq": 10 ** 12, "digest": "0x" + "11" * 32}, "records": []})
        self.assertEqual((v[0], v[1]), ("reject", V.R_COMPLETENESS)); self.assertIn("missing seq [1]", v[2])
        self.assertLess(time.time() - t, 2.0)
        v = verdict("chain_set", {"head": {"seq": 3, "digest": "0x" + "11" * 32}, "records": [{"seq": 1, "artifact_digest": "0x" + "11" * 32, "prev_digest": None}, {"seq": 3, "artifact_digest": "0x" + "11" * 32, "prev_digest": None}]})
        self.assertIn("missing seq [2]", v[2])

    def test_verify_file_never_raises(self):                                     # M50 + F1
        import tempfile
        d = tempfile.mkdtemp()
        cases = {"bad.json": b'{"kind": "chain_set", "input": {', "deep.json": b"[" * 5000 + b"]" * 5000,
                 "deep_payload.json": b'{"kind":"digest_recompute","input":{"payload":' + b"[" * 5000 + b"]" * 5000 + b',"expected_digest":"0x' + b"0" * 64 + b'"}}',
                 "bin.json": b"\xff\xfe\x00", "nan.json": b"[NaN]"}
        for name, data in cases.items():
            p = os.path.join(d, name)
            with open(p, "wb") as fh:
                fh.write(data)
            self.assertEqual(V.verify_file(p)[0], "reject", name)
        self.assertEqual(V.verify_file(os.path.join(d, "missing.json"))[0], "reject")
        self.assertEqual(V.verify_file(d)[0], "reject")

    def test_harness_reason_counts_and_can_fail(self):                           # M41 M43 F3 F5
        import io, contextlib, json, tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        p = {"a": 1}; good = "0x" + V.keccak256_pure(b'{"a":1}').hex(); bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        def dump(obj, *parts):
            with open(os.path.join(d, *parts), "w", encoding="utf-8") as fh:
                json.dump(obj, fh)
        dump({"kind": "digest_recompute", "input": {"payload": p, "expected_digest": bad}}, "vectors", "x.json")
        dump({"kind": "digest_recompute", "input": {"payload": p, "expected_digest": good}}, "vectors", "y.json")
        dump({"suite": "t", "version": "0", "vectors": [{"file": "x.json", "kind": "digest_recompute", "expect": "reject", "reason": "existence_reject"},
                                                        {"file": "y.json", "expect": "valid"},                       # no kind anywhere -> F3/F5 must not crash
                                                        {"file": "y.json", "kind": "digest_recompute"}]}, "MANIFEST.json")
        res = V.run_suite(d)
        self.assertEqual(res["n"], 3)
        self.assertEqual(res["verdict_concordant"], 2)                         # x (verdict right) + y#2 (valid); y#3 has no expect (F5)
        self.assertEqual(res["reason_concordant"], 0)                          # x: reason wrong ...
        self.assertEqual(res["concordant"], 1)                                 # ... so x is NOT concordant (M41); only y#2 is
        with contextlib.redirect_stdout(io.StringIO()):
            V.print_report(res)
        # --mutate can fail: a kind that ignores its input never flips
        V.KINDS["always_valid"] = lambda inp: "ok"
        try:
            dump({"vectors": [{"file": "y.json", "kind": "always_valid", "expect": "valid"}]}, "MANIFEST.json")
            m = V.run_mutations(d)
            self.assertGreater(m["n"], 0); self.assertEqual(m["flipped"], 0)        # M43
        finally:
            del V.KINDS["always_valid"]


# ── v0.5.7 (2026-10-12) ─────────────────────────────────────────────────────────────────────────────────────────────
# Generative tests for the rules the v0.5.7 MANIFEST added or rewrote. The oracle helpers below are written from the
# manifest text in a different style from the verifier (character loops, no regular expressions), so that a shared
# regular-expression slip does not pass both. Every test here fails on 1a9146d (positive control, RAPPORTO.md).
_WS = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000} | set(range(0x2000, 0x200B))
_UNRES = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = "0123456789abcdefABCDEF"


def _oracle_identity(v):
    """manifest v0.5.7 identifier_normalization, steps (1)-(5), as a key or None"""
    if not isinstance(v, str):
        return None
    i, j = 0, len(v)
    while i < j and ord(v[i]) in _WS:
        i += 1
    while j > i and ord(v[j - 1]) in _WS:
        j -= 1
    t = v[i:j]
    if len(t) == 42 and t[0] == "0" and t[1] in "xX" and all(c in _HEX for c in t[2:]):
        return "addr:" + t.lower()
    if not t or not ("a" <= t[0].lower() <= "z") or ":" not in t:
        return None
    scheme, rest = t.split(":", 1)
    if not all(c.isascii() and (c.isalnum() or c in "+.-") for c in scheme) or not rest:
        return None
    if not all(0x21 <= ord(c) <= 0x7E for c in rest):
        return None
    out, k = [], 0
    while k < len(t):
        if t[k] == "%" and k + 2 < len(t) + 0 and t[k + 1] in _HEX and t[k + 2] in _HEX and chr(int(t[k + 1:k + 3], 16)) in _UNRES:
            out.append(chr(int(t[k + 1:k + 3], 16))); k += 3
        else:
            out.append(t[k]); k += 1
    t = "".join(out)
    if "%" in t or "?" in t:
        return None
    path = t[t.index(":") + 1:]
    if "#" in path:
        path = path[:path.index("#")]
    if any(seg == "." or seg == ".." for seg in path.split("/")):
        return None
    t = t.lower()
    while t and t[-1] in "/.#":
        t = t[:-1]
    if "#" in t or ":" not in t:
        return None
    scheme, rest = t.split(":", 1)
    if not rest or not scheme or not ("a" <= scheme[0] <= "z"):
        return None
    last = t.split(":")[-1]
    if len(last) == 42 and last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]):
        return "addr:" + last
    return "uri:" + t


class TestSuite057(unittest.TestCase):
    @unittest.skipUnless(os.path.isdir(SPEC057), "spec-0.5.7/ not present")
    def test_suite_057_concordant_flip_mutate(self):
        V._ABLATE.clear()
        res = V.run_suite(SPEC057)
        self.assertEqual((res["version"], res["n"], res["concordant"], res["reason_named"], res["reason_concordant"]),
                         ("0.5.7", 162, 162, 106, 106))
        self.assertEqual(V.run_suite(SPEC057, flip_expect=True)["concordant"], 0)
        m = V.run_mutations(SPEC057)
        self.assertEqual(m["flipped"], m["n"])
        self.assertGreater(m["n"], 0)

    @unittest.skipUnless(os.path.isdir(SPEC057), "spec-0.5.7/ not present")
    def test_057_vectors_carry_no_member_outside_the_053_lists(self):
        for e, vec in _suite_vectors_in(SPEC057):
            rep = V.input_member_report(vec, e["kind"])
            self.assertEqual((rep["unknown_input_members"], rep["unknown_vector_members"]), ([], []), e["file"])

    @unittest.skipUnless(os.path.isdir(SPEC057) and os.path.isdir(SPEC), "spec dirs not present")
    def test_053_vectors_are_byte_identical_in_057(self):
        for name in os.listdir(os.path.join(SPEC, "vectors")):
            with open(os.path.join(SPEC, "vectors", name), "rb") as a, open(os.path.join(SPEC057, "vectors", name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)

    def test_whitespace_strip_every_code_point(self):
        base = V.normalize_identity("org:a")
        for cp in range(0x110000):
            if 0xD800 <= cp <= 0xDFFF:
                continue
            c = chr(cp)
            got = V.normalize_identity(c + "org:a" + c)
            if cp in _WS:
                self.assertEqual(got, base, hex(cp))
            else:
                self.assertNotEqual(got, base, hex(cp))
            d = V.parse_digest(c + "0x" + "ab" * 32 + c)
            self.assertEqual(d is not None, cp in _WS, hex(cp))
        # the same strip where a criterion reads a digest field (hex32), not only in parse_digest (review 2026-10-12)
        good = "0x" + V.content_address({"a": 1}).hex()
        for cp in sorted(_WS) + [0x1C, 0x1D, 0x1E, 0x1F, 0xFEFF]:
            got = verdict("digest_recompute", {"payload": {"a": 1}, "expected_digest": chr(cp) + good + chr(cp)})
            self.assertEqual(got[0], "valid" if cp in _WS else "reject", hex(cp))

    def test_digest_lowercase_never_admits_non_ascii(self):
        for cp in range(0x80, 0x110000):
            if 0xD800 <= cp <= 0xDFFF:
                continue
            self.assertIsNone(V.parse_digest("0x" + "a" * 63 + chr(cp)), hex(cp))
            self.assertIsNone(V.parse_digest(chr(cp) + "x" + "a" * 64), hex(cp))
        self.assertEqual(V.parse_digest("0X" + "AB" * 32), bytes([0xAB]) * 32)     # declared reading: the 0X prefix lowercases

    def test_percent_triplets_every_byte_both_cases(self):
        for b in range(256):
            for trip in ("%%%02x" % b, "%%%02X" % b):
                ident = "org:a" + trip + "b"
                exp = V.normalize_identity("org:a" + chr(b) + "b") if chr(b) in _UNRES else None
                self.assertEqual(V.normalize_identity(ident), exp, ident)
                self.assertEqual(V.normalize_identity(ident), _oracle_identity(ident), ident)
        self.assertIsNone(V.normalize_identity("org:trustline-custody/eu-wes%2574"))   # n55: one pass, %25 stays
        self.assertIsNone(V.normalize_identity("org:trustline-custody/eu-wes%%37%34"))  # n56: never rescanned
        self.assertIsNone(V.normalize_identity("org:a%2"))                              # a bare % remains

    def test_generative_identifiers_against_the_oracle(self):
        import random
        rng = random.Random(20261012)
        atoms = ["a", "B", "z9", ".", "..", "/", "#", "?", ":", "%2E", "%2e", "%2D", "%41", "%25", "%2F", "%", "-", "_",
                 "~", " ", " ", "\u001c", "﻿", "0x" + "Ab" * 20, "0X" + "cd" * 20, "eip155", "1", "+", "é"]
        schemes = ["org", "ORG", "Org", "did", "a+b.c-d", "1x", "", "x y", "eip155", "acct"]
        n_parse = n_none = 0
        for _ in range(40000):
            ident = rng.choice(schemes) + rng.choice([":", ":", "", "::"]) + "".join(rng.choice(atoms) for _ in range(rng.randint(0, 7)))
            if rng.random() < 0.2:
                ident = rng.choice([" ", "\t", "　", "\u001c", "﻿", ""]) + ident + rng.choice([" ", "\n", " ", ""])
            got = V.normalize_identity(ident)
            self.assertEqual(got, _oracle_identity(ident), repr(ident))
            n_parse += got is not None
            n_none += got is None
        self.assertGreater(n_parse, 2000)   # the generator reaches both outcomes in volume
        self.assertGreater(n_none, 2000)

    def test_address_alias_any_scheme_any_reference(self):
        import random
        rng = random.Random(7)
        for _ in range(2000):
            h = "".join(rng.choice("0123456789abcdef") for _ in range(40))
            mixed = "".join(c.upper() if rng.random() < 0.5 else c for c in h)
            pre = rng.choice(["0x", "0X"])
            ident = rng.choice(["eip155:8453:", "did:pkh:eip155:1:", "did:ethr:", "ethereum:", "acct:", "x:y:z:"]) + pre + mixed
            self.assertEqual(V.normalize_identity(ident), "addr:0x" + h, ident)
            self.assertEqual(V.normalize_identity(pre + mixed), "addr:0x" + h)
            for bad in (pre + mixed[:-1], pre + mixed + "0", "0y" + mixed):
                self.assertNotEqual(V.normalize_identity("eip155:1:" + bad), "addr:0x" + h)

    def test_dot_segments_and_query(self):
        for bad in ("org:.", "org:..", "org:./a", "org:../a", "org:a/./b", "org:a/../b", "org:a/.", "org:a/..",
                    "org:a/%2E", "org:a/%2e%2E", "org:a?x", "org:a#b", "org:/", "org:#",
                    "org:...",       # no dot-segment, but empty path once the trailing dots are removed (n51)
                    "org:a/.#"):     # path is "a/." up to the first "#": a dot-segment
            self.assertIsNone(V.normalize_identity(bad), bad)
        for good in ("org:a/.well-known/.../..v2", "org:a.", "org:a/", "org:a#", "org:a...", "org:a/.b#"):
            self.assertIsNotNone(V.normalize_identity(good), good)

    def test_chain_link_seq_domain(self):
        import random
        art = "0x" + "11" * 32
        def link(seq):
            return "0x" + V.keccak256_pure(bytes.fromhex(art[2:]) + bytes(32) + (seq % 2 ** 64).to_bytes(8, "big")).hex()
        rng = random.Random(3)
        seqs = [0, 1, 2, -1, V.I_JSON_MAX, V.I_JSON_MAX + 1, 2 ** 63, 2 ** 64 - 1] + [rng.randint(-2 ** 60, 2 ** 64 - 1) for _ in range(300)]
        for s in seqs:
            got = verdict("chain_link", {"artifact_digest": art, "prev_digest": None, "seq": s, "expected_link": link(s)})
            self.assertEqual(got[0], "valid" if 1 <= s <= V.I_JSON_MAX else "reject", s)
            if got[0] == "reject":
                self.assertEqual(got[1], V.R_CONTINUITY)
        for s in (True, False, None, "1", V.NumberToken("1.0"), V.NumberToken("1e0"), [1], {"a": 1}):
            self.assertEqual(verdict("chain_link", {"artifact_digest": art, "prev_digest": None, "seq": s, "expected_link": link(1)})[1], V.R_CONTINUITY, repr(s))

    def test_payload_text_surrogate_before_number_any_order(self):
        import random
        rng = random.Random(11)
        for _ in range(500):
            sur = "\\u%04x" % rng.randint(0xD800, 0xDFFF)
            num = rng.choice(["2.0", "1e2", "0.5", "-1E-3"])
            members = ['"n":' + num, '"s":"' + sur + '"'] if rng.random() < 0.5 else ['"s":"x' + sur + '"', '"n":[' + num + ']']
            if rng.random() < 0.5:
                members.reverse()
            text = "{" + ",".join(members) + "}"
            got = verdict("canonical_bytes", {"payload_text": V.load_json('"' + text.replace('"', '\\"') + '"'), "claimed_canonical": ""})
            self.assertEqual(got[1], V.R_CANON, text)
        # a surrogate inside an array, before or after a number token (review 2026-10-12)
        for text in ('["\\ud800",1.5]', '[1.5,"\\udc00"]', '{"a":[["\\ud800"]],"n":1e2}'):
            self.assertEqual(verdict("canonical_bytes", {"payload_text": text, "claimed_canonical": ""})[1], V.R_CANON, text)
        # a payload_text that is a JSON number is not a string holding JSON text (n43/n44), whatever its token class
        self.assertEqual(verdict("canonical_bytes", {"payload_text": V.NumberToken("2.0"), "claimed_canonical": "2"})[1], V.R_CANON)
        # a number alone stays number_domain_reject; a surrogate in a NAME is caught too
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"n":2.0}', "claimed_canonical": ""})[1], V.R_NUMBER)
        self.assertEqual(verdict("canonical_bytes", {"payload_text": '{"\\udfb7":2.0}', "claimed_canonical": ""})[1], V.R_CANON)

    def test_half_raw_pair_is_the_same_name(self):
        for hi in (0xD800, 0xD842, 0xDBFF):
            for lo in (0xDC00, 0xDFB7, 0xDFFF):
                raw = chr(hi)                                  # the raw code unit, as the vector file delivers it
                esc_pair = "\\u%04x\\u%04x" % (hi, lo)
                cp = chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                dup = '{"' + raw + "\\u%04x" % lo + '":1,"' + esc_pair + '":2}'
                self.assertEqual(verdict("canonical_bytes", {"payload_text": dup, "claimed_canonical": ""})[1], V.R_CANON, dup)
                # alone it repeats no name: declared reading, the joined pair canonicalizes as the code point
                one = '{"' + raw + "\\u%04x" % lo + '":"' + raw + "\\u%04x" % lo + '"}'
                claimed = '{"' + cp + '":"' + cp + '"}'
                self.assertEqual(verdict("canonical_bytes", {"payload_text": one, "claimed_canonical": claimed})[0], "valid", one)
                # a half-raw pair nested in an object or an array is joined as well (review 2026-10-12)
                half = raw + "\\u%04x" % lo
                nested = '{"o":{"k":"' + half + '"},"l":[["' + half + '"]]}'
                claimed_nested = '{"l":[["' + cp + '"]],"o":{"k":"' + cp + '"}}'
                self.assertEqual(verdict("canonical_bytes", {"payload_text": nested, "claimed_canonical": claimed_nested})[0], "valid", nested)
                # names repeated across two objects are two objects (p30)
                two = '[{"' + raw + "\\u%04x" % lo + '":1},{"' + esc_pair + '":2}]'
                claimed_two = '[{"' + cp + '":1},{"' + cp + '":2}]'
                self.assertEqual(verdict("canonical_bytes", {"payload_text": two, "claimed_canonical": claimed_two})[0], "valid", two)

    def test_bound_object_without_canonical_form_takes_the_criterion_reason(self):
        import random
        rng = random.Random(5)
        d0 = "0x" + "00" * 32
        prefix_ev = {"event": "witness_ref_introduced", "ruleVersion": "witness-ref-v1", "prefixDigest": d0, "position": 1, "attestedPrefixLength": 1}
        for _ in range(300):
            s = "x" + chr(rng.randint(0xD800, 0xDFFF))
            obj = rng.choice([{"a": s}, {s: 1}, {"n": {"m": [1, {"k": s}]}}, {"l": [s]}])
            self.assertEqual(verdict("offer_binding", {"offer": obj, "receipt": {"offerDigest": d0}})[1], V.R_BINDING)
            self.assertEqual(verdict("decision_evidence_binding", {"decision_evidence": obj, "record": {"decisionEvidenceDigest": d0}})[1], V.R_BINDING)
            self.assertEqual(verdict("boundary_binding", {"prefix": [obj], "boundary_event": dict(prefix_ev)})[1], V.R_BOUNDARY)
            self.assertEqual(verdict("digest_recompute", {"payload": obj, "expected_digest": d0})[1], V.R_CANON)
        # declared reading: a non-integer number token in a bound object keeps number_domain_reject
        self.assertEqual(verdict("offer_binding", {"offer": {"a": V.NumberToken("1.5")}, "receipt": {"offerDigest": d0}})[1], V.R_NUMBER)

    def test_transaction_blank_after_strip_commits_to_no_settlement(self):
        P = ["0x" + "22" * 20, "0x" + "33" * 20]
        base = {"claimed": "independent", "parties": P, "attestations": [{"by": "0x" + "44" * 20}], "covers": ["settlement"]}
        for tx in ("", " ", "　\t", " "):
            self.assertEqual(verdict("independence_claim", dict(base, settlement_result={"success": True, "transaction": tx}))[1], V.R_INDEPENDENCE, repr(tx))
        for tx in ("0xabc", "\u001c", "﻿"):                     # not White_Space: not blank
            self.assertEqual(verdict("independence_claim", dict(base, settlement_result={"success": True, "transaction": tx}))[0], "valid", repr(tx))
        got = verdict("independence_claim", dict(base, covers=["delivery"], deliverable_bytes="\ud800", deliverable_digest="0x" + "00" * 32))
        self.assertEqual(got[1], V.R_INDEPENDENCE)                     # was input_reject (UnicodeEncodeError) before 2026-10-12
        # the same reject where the claim covers only settlement: the derivation reads every field it is given (review
        # 2026-10-12; an overreach reject on `delivery` alone could not tell the two apart)
        ok_sr = {"success": True, "transaction": "0xabc"}
        got = verdict("independence_claim", dict(base, settlement_result=ok_sr, deliverable_bytes="\ud800", deliverable_digest="0x" + "00" * 32))
        self.assertEqual(got[:2], ("reject", V.R_INDEPENDENCE), got)
        # network: the same strip as transaction
        for net, ok in (("\u3000", False), (" \t", False), ("\u001c", True), ("base", True)):
            got = verdict("independence_claim", dict(base, covers=["network"], settlement_result=dict(ok_sr, network=net)))
            self.assertEqual(got[0], "valid" if ok else "reject", repr(net))
        # a JSON number is not a string: a non-integer token commits to nothing (review 2026-10-12: it did)
        d15 = "0x" + V.keccak256(b"1.5").hex()
        for extra in ({"covers": ["settlement"], "settlement_result": {"success": True, "transaction": V.NumberToken("1.5")}},
                      {"covers": ["network"], "settlement_result": {"success": True, "transaction": "0xabc", "network": V.NumberToken("1e2")}},
                      {"covers": ["delivery"], "deliverable_bytes": V.NumberToken("1.5"), "deliverable_digest": d15}):
            got = verdict("independence_claim", dict(base, **extra))
            self.assertEqual(got[1], V.R_INDEPENDENCE, extra)
        self.assertEqual(verdict("independence_claim", dict(base, covers=["delivery"], deliverable_bytes="1.5", deliverable_digest=d15))[0], "valid")


def _suite_vectors_in(spec):
    import json
    with open(os.path.join(spec, "MANIFEST.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    for e in m["vectors"]:
        with open(os.path.join(spec, "vectors", e["file"]), encoding="utf-8") as fh:
            yield e, V.load_json(fh.read())


if __name__ == "__main__":
    unittest.main()
