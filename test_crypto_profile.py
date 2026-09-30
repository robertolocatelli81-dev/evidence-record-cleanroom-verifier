#!/usr/bin/env python3
"""Unit tests for crypto_profile/verify_countersig.py, built ONLY from data already in this repository
(spec/vectors p1 + p4, the live genesis counter-signature). Each twin is derived here; no file of
tersignhq/evidence-record-conformance PR #11 is copied."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "crypto_profile"))
import verify_countersig as C  # noqa: E402


def _live():
    p1 = json.load(open(os.path.join(HERE, "spec", "vectors", "p1-live-genesis-receipt.json"), encoding="utf-8"))
    return {"artifact_digest": p1["input"]["expected_digest"], "prev_digest": None, "seq": 1,
            "countersignature": p1["provenance"]["countersignature"],
            "ledger_signer": p1["provenance"]["ledger_signer"]}


def _parts(sig_hex):
    b = bytes.fromhex(sig_hex[2:])
    return int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big"), b[64]


def _hex(r, s, v):
    return "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])).hex()


class TestCountersignature(unittest.TestCase):
    def test_link_matches_p4(self):
        p4 = json.load(open(os.path.join(HERE, "spec", "vectors", "p4-chain-link-genesis.json"), encoding="utf-8"))
        self.assertEqual("0x" + C.link_of(_live()).hex(), p4["input"]["expected_link"])

    def test_live_signature_valid(self):
        self.assertEqual(C.check(_live())[:2], ("valid", None))

    def test_high_s_twin_refused_but_recovers_same_signer(self):
        inp = _live()
        r, s, v = _parts(inp["countersignature"])
        twin = dict(inp, countersignature=_hex(r, C.N - s, 55 - v))
        self.assertEqual(C.check(twin)[:2], ("reject", C.NON_CANONICAL))
        # the point of the twin: without low-s it would pass (mutant), i.e. it recovers the ledger signer
        self.assertEqual(C.check(twin, low_s=False)[:2], ("valid", None))

    def test_v_out_of_range_refused_not_normalised(self):
        inp = _live()
        r, s, _ = _parts(inp["countersignature"])
        self.assertEqual(C.check(dict(inp, countersignature=_hex(r, s, 29)))[:2], ("reject", C.MALFORMED))
        self.assertEqual(C.check(dict(inp, countersignature=_hex(r, s, 1)))[:2], ("reject", C.MALFORMED))

    def test_truncated_and_non_hex(self):
        inp = _live()
        self.assertEqual(C.check(dict(inp, countersignature=inp["countersignature"][:-2]))[1], C.MALFORMED)
        self.assertEqual(C.check(dict(inp, countersignature="0xzz"))[1], C.MALFORMED)
        self.assertEqual(C.check(dict(inp, countersignature=None))[1], C.MALFORMED)

    def test_moved_to_other_position(self):
        inp = _live()
        self.assertEqual(C.check(dict(inp, seq=2))[:2], ("reject", C.MISMATCH))
        self.assertEqual(C.check(dict(inp, prev_digest="0x" + "11" * 32))[:2], ("reject", C.MISMATCH))

    def test_wrong_declared_signer(self):
        self.assertEqual(C.check(dict(_live(), ledger_signer="0x" + "00" * 20))[:2], ("reject", C.MISMATCH))

    def test_unrecoverable(self):
        inp = _live()
        _, s, v = _parts(inp["countersignature"])
        self.assertEqual(C.check(dict(inp, countersignature=_hex(0, s, v)))[1], C.UNRECOVERABLE)
        # an x with no curve point: search deterministically for the first such r
        x = 1
        while True:
            y2 = (pow(x, 3, C.P) + 7) % C.P
            if pow(y2, (C.P - 1) // 2, C.P) != 1:
                break
            x += 1
        self.assertEqual(C.check(dict(inp, countersignature=_hex(x, s, v)))[1], C.UNRECOVERABLE)

    def test_no_eip191_prefix_mutant_breaks_live(self):
        self.assertEqual(C.check(_live(), eip191=False)[1], C.MISMATCH)

    def test_malformed_link_fields_rejected_never_crash(self):
        inp = _live()
        bad = {
            "art_bad_hex": dict(inp, artifact_digest="0xzz" + inp["artifact_digest"][4:]),
            "art_short": dict(inp, artifact_digest=inp["artifact_digest"][:-2]),
            "art_no0x": dict(inp, artifact_digest=inp["artifact_digest"][2:]),
            "prev_short": dict(inp, prev_digest="0x" + "11" * 31),
            "seq_neg": dict(inp, seq=-1), "seq_2e64": dict(inp, seq=2 ** 64),
            "seq_str": dict(inp, seq="1"), "seq_float": dict(inp, seq=1.0), "seq_bool": dict(inp, seq=True),
            "signer_missing": {k: v for k, v in inp.items() if k != "ledger_signer"},
            "signer_short": dict(inp, ledger_signer=inp["ledger_signer"][:-2]),
            "art_missing": {k: v for k, v in inp.items() if k != "artifact_digest"},
        }
        for name, case in bad.items():
            with self.subTest(name):
                self.assertEqual(C.check(case)[:2], ("reject", C.MALFORMED_INPUT))
        # seq at the uint64 edge is well-formed (it only fails to match the live signature)
        self.assertEqual(C.check(dict(inp, seq=2 ** 64 - 1))[1], C.MISMATCH)
        self.assertEqual(C.check(dict(inp, seq=0))[1], C.MISMATCH)

    def test_tolerated_forms_per_readme(self):
        inp = _live()
        # README: ledger_signer compared after strip + lowercase
        self.assertEqual(C.check(dict(inp, ledger_signer=" " + inp["ledger_signer"].upper().replace("0X", "0x") + " "))[:2], ("valid", None))
        # uppercase hex digits in the signature are still hex; a "0X" prefix or leading space is not accepted
        self.assertEqual(C.check(dict(inp, countersignature="0x" + inp["countersignature"][2:].upper()))[:2], ("valid", None))
        self.assertEqual(C.check(dict(inp, countersignature="0X" + inp["countersignature"][2:]))[1], C.MALFORMED)
        self.assertEqual(C.check(dict(inp, countersignature=" " + inp["countersignature"]))[1], C.MALFORMED)

    def test_no_internal_error_on_any_case_here(self):
        inp = _live()
        for case in (inp, dict(inp, seq=None), dict(inp, artifact_digest=5), dict(inp, prev_digest=[]), {}):
            self.assertNotEqual(C.check(case)[1], C.INTERNAL_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
