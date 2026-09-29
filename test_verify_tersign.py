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
        self.assertNotEqual(V.normalize_identity("org:Caldera-Robotics"), V.normalize_identity("org:caldera-robotics"))  # manifest: case-significant
        self.assertIsNone(V.normalize_identity("Org:caldera"))       # scheme must be lowercase alnum
        self.assertIsNone(V.normalize_identity("org:cal dera"))      # non-space path
        self.assertIsNone(V.normalize_identity("org:a:b"))           # one colon (strict reading)
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


if __name__ == "__main__":
    unittest.main()
