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

    def test_loader_edges(self):
        # Verification B (30/09): nine non-equivalent mutants of the loader survived; each case below kills one or more
        live = json.dumps(_live())[1:-1]

        def doc(extra):
            return '{"expect": "valid", "input": {' + live + ', "x_extra": ' + extra + "}}"
        cases = {"l1.json": (doc('"' + "[" * 1000 + '"'), "valid"),                       # brackets inside a string
                 "l2.json": (doc('"a\\"' + "[" * 1000 + '"'), "valid"),                  # escaped quote, string goes on
                 "l3.json": (doc("[" + ",".join(["[]"] * 1000) + "]"), "valid"),           # 1,000 siblings, depth 4
                 "l4.json": (doc("[" + "[" * 897 + "]" * 897 + ",[]]"), "valid"),          # depth exactly 900, scan active
                 "l5.json": (doc('"\xff"').encode("latin-1"), "reject"),                   # not UTF-8
                 "l6.json": (doc("1")[:-3], "reject")}                                       # truncated JSON
        import tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "vectors"))
        for name, (body, _) in cases.items():
            open(os.path.join(d, "vectors", name), "wb").write(body if isinstance(body, bytes) else body.encode())
        json.dump({"vectors": [{"file": n, "expect": exp, "reject_reason": C.MALFORMED_INPUT if exp == "reject" else None}
                               for n, (_, exp) in cases.items()]}, open(os.path.join(d, "MANIFEST.json"), "w"))
        _, rows = C.run(d)
        got = {r["file"]: (r["verdict"], r["reason"], r["concordant"]) for r in rows}
        self.assertEqual(got, {n: (exp, C.MALFORMED_INPUT if exp == "reject" else None, True) for n, (_, exp) in cases.items()})

    def test_unloadable_manifest_stops_the_run_without_a_traceback(self):
        import subprocess, tempfile
        for body in ("{not json", '{"profile": "x"}', '{"vectors": [1]}', '{"vectors": {}}', '{"vectors": [{"x": 1}]}',
                     '{"vectors": [{"file": 5}]}', '{"vectors": ' + "[" * 1000 + "]" * 1000 + "}",
                     '{"vectors": ' + "[" * 100000 + "]" * 100000 + "}", '{"vectors": [{"file": "a\\u0000b.json"}]}'):
            d = tempfile.mkdtemp()
            open(os.path.join(d, "MANIFEST.json"), "w").write(body)
            p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "crypto_profile", "verify_countersig.py"), d],
                               capture_output=True, text=True)
            self.assertEqual((p.returncode, "Traceback" in p.stderr, "run stopped" in p.stderr), (2, False, True))

    def test_depth_scan_across_escapes_and_after_the_deepest_point(self):
        # 30/09 re-check of the survivors: 950 levels load on 3.9, 3.11 and 3.13, so only the scan can refuse them
        live = json.dumps(_live())[1:-1]
        deep = "[" * 947 + "]" * 947

        def doc(extra):
            return '{"input": {' + live + ', "x_extra": ' + extra + "}}"
        cases = {"esc_n.json": doc('["a\\n", ' + deep + "]"),       # an escape must not hide what follows the string
                 "esc_q.json": doc('["a\\"b", ' + deep + "]"),
                 "shallow_after.json": doc("[" + deep + ", []]")}       # the deepest point, not the last one, counts
        d = self._run_one(cases)
        _, rows = C.run(d)
        self.assertEqual({r["file"]: (r["verdict"], r["reason"]) for r in rows},
                         {n: ("reject", C.MALFORMED_INPUT) for n in cases})

    def test_json_report_with_an_oversized_expect(self):
        # 30/09: --json raised TypeError (Oversized not serializable) when a vector's "expect" was a 5,000-digit integer
        import subprocess
        d = self._run_one({"x.json": '{"expect": ' + "9" * 5000 + ', "input": ' + json.dumps(_live()) + "}"})
        out = os.path.join(d, "report.json")
        for limit, want in ((None, "<integer of 5000 digits>"), ("0", None)):
            env = {k: v for k, v in os.environ.items() if k != "PYTHONINTMAXSTRDIGITS"}
            if limit is not None:
                env["PYTHONINTMAXSTRDIGITS"] = limit      # no limit: the integer loads as an int, no marker to report
            p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "crypto_profile", "verify_countersig.py"), d,
                                "--json", out], capture_output=True, text=True, env=env)
            self.assertNotIn("Traceback", p.stderr)
            self.assertEqual(p.stdout.split("->")[1].split()[0], "valid")
            if want:
                self.assertEqual(json.load(open(out))["rows"][0]["expect"], want)

    def _cli(self, d, *extra):
        import subprocess
        return subprocess.run([sys.executable, "-B", os.path.join(HERE, "crypto_profile", "verify_countersig.py"), d, *extra],
                              capture_output=True, text=True)

    def test_exit_codes_and_concordance(self):
        # second verification of b1987a0 (01/10): exit codes and the concordance rule were not pinned by any test.
        # The expectation is read from the vector file itself (the MANIFEST entry is the fallback for unloadable files).
        def vec(expect, reason=None, inp=None):
            return json.dumps({"expect": expect, "reject_reason": reason, "input": inp or _live()})
        bad = dict(_live(), countersignature="0x" + "00" * 65)
        got_reason = C.check(bad)[1]
        other = C.MISMATCH if got_reason != C.MISMATCH else C.MALFORMED
        for body, rc, line in ((vec("valid"), 0, "concordant 1/1"),
                               (vec("reject", C.MALFORMED), 1, "concordant 0/1"),
                               (vec("reject", got_reason, bad), 0, "concordant 1/1"),
                               (vec("reject", other, bad), 1, "concordant 0/1")):     # right verdict, wrong reason: not concordant
            d = self._run_one({"v.json": body})
            p = self._cli(d)
            self.assertEqual((p.returncode, line in p.stdout, "Traceback" in p.stderr), (rc, True, False), body[:60])
        d = self._run_one({"v.json": vec("valid")})
        for argv in (("--json",), ("--json", "--mutants"), ("--json", os.path.join(d, "no", "such", "dir", "x.json"))):
            p = self._cli(d, *argv)
            self.assertEqual((p.returncode, "Traceback" in p.stderr), (2, False), argv)

    def test_manifest_shapes_and_unsafe_names_stop_the_run(self):
        import tempfile
        live = json.dumps({"input": _live()})
        cases = ['[]', '"x"', 'null', '{"vectors": []}', '{"vectors": [{"file": "../MANIFEST.json"}]}',
                 '{"vectors": [{"file": "/etc/hostname"}]}', '{"vectors": [{"file": "sub/ok.json"}]}', '{"vectors": [{"file": ".."}]}',
                 '{"vectors": [{"file": ""}]}', '{"vectors": [{"file": "a\\\\b.json"}]}']
        for body in cases + [None, "FIFO", "DEVZERO"]:
            d = self._run_one({"ok.json": live})
            man = os.path.join(d, "MANIFEST.json")
            if body is None:
                os.remove(man)                                                       # MANIFEST missing
            elif body == "FIFO":
                os.mkfifo(os.path.join(d, "vectors", "f.json"))
                json.dump({"vectors": [{"file": "f.json"}]}, open(man, "w"))
            elif body == "DEVZERO":
                os.symlink("/dev/zero", os.path.join(d, "vectors", "z.json"))
                json.dump({"vectors": [{"file": "z.json"}]}, open(man, "w"))
            else:
                open(man, "w").write(body)
            p = self._cli(d)
            self.assertEqual((p.returncode, "Traceback" in p.stderr, "run stopped" in p.stderr), (2, False, True), (body, p.stderr[-200:]))

    def test_signature_with_every_hex_digit_in_both_cases(self):
        # 0x + 130 hex digits accepts upper- and lower-case digits; a signature using all 22 characters stays valid
        sig = _live()["countersignature"]
        mixed, seen = [], set()
        for ch in sig[2:]:
            up = ch in "abcdef" and ch not in seen
            seen.add(ch)
            mixed.append(ch.upper() if up else ch)
        mixed = "0x" + "".join(mixed)
        self.assertEqual(len(set(mixed[2:])), 22)
        self.assertEqual(C.check(dict(_live(), countersignature=mixed))[0], "valid")

    # 01/10 mutation survivors (473 mutants of ccc1bfc): each test below kills at least one non-equivalent survivor
    def test_signature_space_right_after_0x(self):
        # bytes.fromhex skips spaces: only the full-string hex check refuses "0x " + 130 digits (survivor m439)
        sig = _live()["countersignature"]
        self.assertEqual(C.check(dict(_live(), countersignature="0x " + sig[2:]))[1], C.MALFORMED)

    def test_identifier_non_hex_right_after_0x(self):
        # "0xg…" must be malformed_input, never internal_error (survivor m457)
        for bad in ("0xg" + "0" * 63, "0x " + "0" * 63):
            self.assertEqual(C.check(dict(_live(), artifact_digest=bad))[1], C.MALFORMED_INPUT, bad[:4])

    def test_r_equal_one_recovers_a_point(self):
        # x = 1 has a curve point, so r = 1 recovers some key: signer_mismatch, not unrecoverable (survivor m347)
        r, s, v = _parts(_live()["countersignature"])
        self.assertEqual(C.check(dict(_live(), countersignature=_hex(1, s, v)))[1], C.MISMATCH)

    def test_depth_scan_with_siblings_before_the_deepest_point(self):
        # closing brackets must lower the depth by exactly one (survivor m447)
        live = json.dumps(_live())[1:-1]
        deep = "[" * 947 + "]" * 947
        body = '{"input": {' + live + ', "x_extra": [' + ",".join(["[]"] * 50) + ", " + deep + "]}}"
        _, rows = C.run(self._run_one({"sib.json": body}))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("reject", C.MALFORMED_INPUT))

    def test_cli_usage_and_mutants_mode(self):
        # usage exits 2 (survivors m098, m201, m202, m283, m284); --mutants reports each mutant and exits 0 only when all die
        # (survivors m102, m103, m206, m407, m416, m459, m460)
        import subprocess
        tool = os.path.join(HERE, "crypto_profile", "verify_countersig.py")
        for argv in ([], ["--help"], ["-x"]):
            p = subprocess.run([sys.executable, "-B", tool, *argv], capture_output=True, text=True)
            self.assertEqual((p.returncode, "Traceback" in p.stderr), (2, False), argv)
        r, s, v = _parts(_live()["countersignature"])
        vecs = {"cp.json": json.dumps({"expect": "valid", "input": _live()}),
                "hs.json": json.dumps({"expect": "reject", "reject_reason": C.NON_CANONICAL,
                                       "input": dict(_live(), countersignature=_hex(r, C.N - s, 55 - v))})}
        d = self._run_one(vecs)
        p = subprocess.run([sys.executable, "-B", tool, d, "--mutants"], capture_output=True, text=True)
        lines = [l for l in p.stdout.splitlines() if l.startswith("mutant ")]
        got = {l.split()[1]: l.split(None, 2)[2] for l in lines}
        self.assertEqual(got, {"no_low_s": "KILLED by hs.json", "no_eip191_prefix": "KILLED by cp.json",
                               "v_normalised_not_refused": "SURVIVES", "hardcoded_ledger_signer": "SURVIVES",
                               "link_ignores_seq": "SURVIVES"})     # the exact killer map pins each built-in mutant's definition
        p0 = subprocess.run([sys.executable, "-B", tool, d], capture_output=True, text=True)
        self.assertFalse(any(l.startswith("mutant ") for l in p0.stdout.splitlines()))   # no --mutants, no mutant lines
        self.assertEqual((p.returncode, "concordant 2/2" in p.stdout), (0, True))    # exit code follows the vectors, not the mutants

    def test_unexpected_exception_is_internal_error(self):
        # the last-resort branch (survivors m167, m258): a runner bug is reported, never disguised as a verdict reason
        def boom(inp):
            raise KeyError("simulated runner bug")
        for fn in (boom, lambda inp: 1 // 0):
            self.assertEqual(C.check(_live(), link_fn=fn)[:2], ("reject", C.INTERNAL_ERROR))

    def test_manifest_with_a_long_integer_elsewhere_still_runs(self):
        # MANIFEST.json is parsed without the int-string limit too: a 5,000-digit integer in an unread key does not stop
        # the run, on any interpreter or PYTHONINTMAXSTRDIGITS (survivor m336)
        d = self._run_one({"v.json": json.dumps({"expect": "valid", "input": _live()})})
        open(os.path.join(d, "MANIFEST.json"), "w").write('{"note": ' + "9" * 5000 + ', "vectors": [{"file": "v.json"}]}')
        _, rows = C.run(d)
        self.assertEqual([(r["verdict"], r["concordant"]) for r in rows], [("valid", True)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
