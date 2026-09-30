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


if __name__ == "__main__":
    unittest.main(verbosity=2)
