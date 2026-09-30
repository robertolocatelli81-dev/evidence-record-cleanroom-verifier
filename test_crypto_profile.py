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
        # suite at 4108697: seq in [1, 2^53 - 1]; 0, 2^53 and 2^64 - 1 are malformed, 2^53 - 1 is well formed
        self.assertEqual(C.check(dict(inp, seq=0))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, seq=2 ** 53))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, seq=2 ** 64 - 1))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, seq=2 ** 53 - 1))[1], C.MISMATCH)
        # link_version: absent = 1; the integer 1 accepted; anything else rejects on its own reason
        self.assertEqual(C.check(dict(inp, link_version=1))[:2], ("valid", None))
        for lv in (2, "1", 1.0, True, None):
            self.assertEqual(C.check(dict(inp, link_version=lv))[1], C.UNSUPPORTED_LINK_VERSION)

    def test_prev_digest_absent_equals_null(self):
        # suite vector cp3 (1e08f4e): omitted key == explicit null == genesis
        inp = _live()
        self.assertEqual(C.check({k: v for k, v in inp.items() if k != "prev_digest"})[:2], ("valid", None))

    def test_link_fields_checked_before_signature(self):
        inp = _live()
        r, s, v = _parts(inp["countersignature"])
        mixed = dict(inp, seq="1", countersignature=_hex(r, C.N - s, 55 - v))   # bad seq AND high-s
        self.assertEqual(C.check(mixed)[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(None)[1], C.MALFORMED_INPUT)

    def test_tolerated_forms_per_readme(self):
        # suite at 4108697, step 2: identifiers are stripped of Unicode White_Space and lower-cased before the shape check
        inp = _live()
        for sg in (" " + inp["ledger_signer"], inp["ledger_signer"] + "\n", "0X" + inp["ledger_signer"][2:].upper(),
                   "\u3000" + inp["ledger_signer"] + "\u2028"):
            self.assertEqual(C.check(dict(inp, ledger_signer=sg))[:2], ("valid", None))
        for ad in (inp["artifact_digest"] + "\n", "0X" + inp["artifact_digest"][2:], "\t" + inp["artifact_digest"]):
            self.assertEqual(C.check(dict(inp, artifact_digest=ad))[:2], ("valid", None))
        # U+FEFF and U+001C are NOT White_Space: not stripped (cn17); str.strip() would have stripped U+001C
        self.assertEqual(C.check(dict(inp, artifact_digest="\ufeff" + inp["artifact_digest"]))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, artifact_digest="\u001c" + inp["artifact_digest"]))[1], C.MALFORMED_INPUT)
        # the signature is matched whole and never normalized
        sig = inp["countersignature"]
        self.assertEqual(C.check(dict(inp, countersignature="0x" + sig[2:].upper()))[:2], ("valid", None))
        for bad in ("0X" + sig[2:], " " + sig, sig + "\n", sig[:10] + " " + sig[10:], sig[2:]):
            self.assertEqual(C.check(dict(inp, countersignature=bad))[1], C.MALFORMED)
        self.assertEqual(C.check({k: v for k, v in inp.items() if k != "countersignature"})[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, countersignature=None))[1], C.MALFORMED)

    def test_no_internal_error_on_any_case_here(self):
        inp = _live()
        for case in (inp, dict(inp, seq=None), dict(inp, artifact_digest=5), dict(inp, prev_digest=[]), {}, None, [], "x"):
            self.assertNotEqual(C.check(case)[1], C.INTERNAL_ERROR)

    def test_white_space_set_exact_on_every_identifier(self):
        # Test 2 (30/09): pin all 25 White_Space characters and the usual impostors, on each identifier
        inp = _live()
        # INDEPENDENT list, from Unicode PropList.txt (White_Space), NOT the runner's constant: a test that iterates over the
        # code's own set cannot notice a character missing from it (Test 2 re-run, 30/09)
        unicode_white_space = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) + \
                              [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
        self.assertEqual(len(unicode_white_space), 25)
        for ch in map(chr, unicode_white_space):
            for key in ("artifact_digest", "ledger_signer"):
                with self.subTest(key=key, ch=hex(ord(ch))):
                    self.assertEqual(C.check(dict(inp, **{key: ch + inp[key] + ch}))[:2], ("valid", None))
            with self.subTest(key="prev_digest", ch=hex(ord(ch))):
                self.assertEqual(C.check(dict(inp, prev_digest=ch + "0x" + "00" * 32 + ch))[:2], ("valid", None))
        for ch in ("\u0000", "\u001c", "\u001d", "\u001e", "\u001f", "\u180e", "\u200b", "\ufeff"):
            for key in ("artifact_digest", "ledger_signer"):
                with self.subTest(key=key, bad=hex(ord(ch))):
                    self.assertEqual(C.check(dict(inp, **{key: ch + inp[key]}))[1], C.MALFORMED_INPUT)

    def test_order_between_steps(self):
        inp = _live()
        r, s, v = _parts(inp["countersignature"])
        self.assertEqual(C.check({k: x for k, x in inp.items() if k != "seq"} | {"link_version": 2})[1], C.MALFORMED_INPUT)  # 1 before 3
        self.assertEqual(C.check(dict(inp, artifact_digest="0xzz", link_version=2))[1], C.MALFORMED_INPUT)                  # 2 before 3
        self.assertEqual(C.check(dict(inp, countersignature="0xzz", link_version=2))[1], C.UNSUPPORTED_LINK_VERSION)        # 3 before 5
        x = 1
        while pow((pow(x, 3, C.P) + 7) % C.P, (C.P - 1) // 2, C.P) == 1:
            x += 1
        self.assertEqual(C.check(dict(inp, countersignature=_hex(x, C.N - 1, 27)))[1], C.NON_CANONICAL)                      # 6 before 7

    def test_signature_and_identifier_shapes(self):
        inp = _live(); sig = inp["countersignature"]
        self.assertEqual(C.check(dict(inp, countersignature=sig + "00"))[1], C.MALFORMED)       # 66 bytes
        self.assertEqual(C.check(dict(inp, countersignature=sig + "0"))[1], C.MALFORMED)        # odd length
        self.assertEqual(C.check(dict(inp, artifact_digest=inp["artifact_digest"] + "00"))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, artifact_digest="00" + inp["artifact_digest"][2:]))[1], C.MALFORMED_INPUT)
        self.assertEqual(C.check(dict(inp, prev_digest="0x" + "\ufb00" * 32))[1], C.MALFORMED_INPUT)   # no casefold (ﬀ)
        for key in ("artifact_digest", "ledger_signer"):
            self.assertEqual(C.check(dict(inp, **{key: None}))[1], C.MALFORMED_INPUT)
            self.assertEqual(C.check(dict(inp, **{key: 5}))[1], C.MALFORMED_INPUT)

    def test_recovery_extremes(self):
        inp = _live()
        r, s, v = _parts(inp["countersignature"])
        self.assertEqual(C.check(dict(inp, countersignature=_hex(r, 0, v)))[1], C.UNRECOVERABLE)          # s = 0
        self.assertEqual(C.check(dict(inp, countersignature=_hex(C.N, s, v)))[1], C.UNRECOVERABLE)        # r = n
        e = int.from_bytes(C.personal_hash(C.link_of(inp)), "big")
        R = C._mul(e % C.N, C.G)                                                                           # s=1, R=e*G -> point at infinity
        self.assertEqual(C.check(dict(inp, countersignature=_hex(R[0], 1, 27 + (R[1] % 2))))[1], C.UNRECOVERABLE)

    def test_unloadable_vector_file_is_a_verdict_not_a_crash(self):
        # Test 3 (30/09): a 4,301-digit integer or 100,000 levels of nesting made json.load raise inside run()
        import tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        bodies = {"big.json": '{"expect":"reject","input":{"seq":' + "9" * 4301 + "}}",
                  "deep.json": '{"expect":"reject","input":' + "[" * 100000 + "]" * 100000 + "}"}
        for name, body in bodies.items():
            open(os.path.join(d, "vectors", name), "w").write(body)
        json.dump({"vectors": [{"file": n, "expect": "reject"} for n in bodies]}, open(os.path.join(d, "MANIFEST.json"), "w"))
        _, rows = C.run(d)
        self.assertEqual([(r["verdict"], r["reason"]) for r in rows], [("reject", C.MALFORMED_INPUT)] * 2)

    def _run_one(self, body_by_name):
        import tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        for name, body in body_by_name.items():
            open(os.path.join(d, "vectors", name), "w").write(body)
        json.dump({"vectors": [{"file": n} for n in body_by_name]}, open(os.path.join(d, "MANIFEST.json"), "w"))
        return d

    def test_oversized_integers_do_not_depend_on_the_int_string_limit(self):
        # Verification A (30/09): with the 4300-digit default a VALID vector with a long integer in an unread key was
        # malformed_input, and valid with PYTHONINTMAXSTRDIGITS=0; link_version/signature gave the wrong step's reason
        live = _live()
        big = "9" * 5000
        base = json.dumps({"expect": "valid", "input": live})
        cases = {"extra.json": base[:-2] + ', "zz_extra": ' + big + "}}",
                 "lv.json": json.dumps({"input": dict(live, link_version=0)}).replace('"link_version": 0', '"link_version": ' + big),
                 "sig.json": json.dumps({"input": dict(live, countersignature=0)}).replace('"countersignature": 0', '"countersignature": ' + big),
                 "seq.json": json.dumps({"input": dict(live, seq=0)}).replace('"seq": 0', '"seq": ' + big)}
        _, rows = C.run(self._run_one(cases))
        got = {r["file"]: (r["verdict"], r["reason"]) for r in rows}
        self.assertEqual(got, {"extra.json": ("valid", None), "lv.json": ("reject", C.UNSUPPORTED_LINK_VERSION),
                               "sig.json": ("reject", C.MALFORMED), "seq.json": ("reject", C.MALFORMED_INPUT)})

    def test_nesting_verdict_is_the_same_on_every_interpreter(self):
        # Verification A (30/09): 1,000 levels were malformed_input on 3.9/3.11 and valid on 3.13
        live = json.dumps({"input": _live()})
        # total depth = the two enclosing objects (vector, input) + k brackets
        cases = {f"n{k + 2}.json": live[:-2] + ', "zz": ' + "[" * k + "]" * k + "}}" for k in (897, 898, 899, 998, 4998)}
        _, rows = C.run(self._run_one(cases))
        got = {r["file"]: r["verdict"] for r in rows}
        self.assertEqual(got, {"n899.json": "valid", "n900.json": "valid", "n901.json": "reject",
                               "n1000.json": "reject", "n5000.json": "reject"})

    def test_unopenable_vector_file_stops_the_run_without_a_traceback(self):
        # Verification A (30/09): a directory, a broken link or a listed-but-missing file raised a Python traceback
        import subprocess
        d = self._run_one({"ok.json": json.dumps({"input": _live()})})
        os.makedirs(os.path.join(d, "vectors", "dir.json"))
        m = json.load(open(os.path.join(d, "MANIFEST.json")))
        for extra in ({"file": "dir.json"}, {"file": "missing.json"}):
            json.dump({"vectors": m["vectors"] + [extra]}, open(os.path.join(d, "MANIFEST.json"), "w"))
            with self.assertRaises(C.RunStopped):
                C.run(d)
            p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "crypto_profile", "verify_countersig.py"), d],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            self.assertNotIn("Traceback", p.stderr)
            self.assertIn("run stopped", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
