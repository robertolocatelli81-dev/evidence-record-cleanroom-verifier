"""Tests for verify_eip712.py (the corrected runner). The committed vectors live in ../commitment-3b766320/out and are
never modified; every case here is built in a temporary directory. Stdlib only: python3 -m unittest -v test_verify_eip712"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SET = os.path.join(HERE, "..", "commitment-3b766320", "out")
ERRATA = os.path.join(HERE, "..", "ERRATA_EXPECT.json")
COMMITTED_TOOL = os.path.join(HERE, "..", "commitment-3b766320", "verify_eip712.py")
sys.path.insert(0, HERE)
import verify_eip712 as V  # noqa: E402

TOOL = os.path.join(HERE, "verify_eip712.py")


def vec(name):
    with open(os.path.join(SET, "vectors", name), encoding="utf-8") as fh:
        return json.load(fh)


def manifest_entry(name):
    with open(os.path.join(SET, "MANIFEST.json"), encoding="utf-8") as fh:
        return next(e for e in json.load(fh)["vectors"] if e["file"] == name)


EA1 = "ea1-live-p1-payload-signature.json"
EA3 = "ea3-transaction-absent-equals-empty.json"


def tmpset(files, manifest=None):
    """files: {name: str|bytes}; manifest: dict or raw str (default: every file, expect valid)."""
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "vectors"))
    for n, body in files.items():
        with open(os.path.join(d, "vectors", n), "wb") as fh:
            fh.write(body if isinstance(body, bytes) else body.encode("utf-8"))
    if manifest is None:
        manifest = {"vectors": [{"file": n, "expect": "valid"} for n in files]}
    with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        fh.write(manifest if isinstance(manifest, str) else json.dumps(manifest))
    return d


def cli(*argv, env=None):
    return subprocess.run([sys.executable, "-B", TOOL, *argv], capture_output=True, text=True, timeout=120, env=env)


class TestCommittedSet(unittest.TestCase):
    def test_committed_vectors_all_concordant_and_mutants_killed(self):
        p = cli(SET, "--errata", ERRATA, "--mutants")
        self.assertEqual((p.returncode, "concordant 52/52" in p.stdout, "SURVIVES" in p.stdout, "Traceback" in p.stderr),
                         (0, True, False, False))
        self.assertEqual(sum(l.startswith("mutant ") for l in p.stdout.splitlines()), len(V.MUTANTS))

    def test_live_p1_recovers_the_payer(self):
        self.assertEqual(V.check(vec(EA1)["input"])[:2], ("valid", None))

    def test_e5_only_ea3_differs_from_the_committed_expectations(self):
        p = cli(SET)
        diff = [l for l in p.stdout.splitlines() if l.startswith("[DIFF]")]
        self.assertEqual((p.returncode, "concordant 51/52" in p.stdout, len(diff), EA3 in diff[0]), (1, True, 1, True))
        self.assertIn("[OK E5] " + EA3, cli(SET, "--errata", ERRATA).stdout)


class TestErrataE5(unittest.TestCase):
    """x402 5.5 step 3: the payload is used exactly as transmitted; an omitted transaction is not filled in with ""."""

    def test_omitted_transaction_rejects_and_present_empty_string_verifies(self):
        inp = vec(EA3)["input"]
        self.assertEqual(V.check(inp)[:2], ("reject", "malformed_payload"))
        filled = json.loads(json.dumps(inp))
        filled["artifact"]["payload"]["transaction"] = ""
        self.assertEqual(V.check(filled)[:2], ("valid", None))

    def test_errata_file_listed_twice_in_manifest_stops(self):
        d = tempfile.mkdtemp()
        shutil.copytree(os.path.join(SET, "vectors"), os.path.join(d, "vectors"))
        with open(os.path.join(SET, "MANIFEST.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        man["vectors"].append(dict(manifest_entry(EA3)))
        with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as fh:
            json.dump(man, fh)
        p = cli(d, "--errata", ERRATA)
        self.assertEqual((p.returncode, "Traceback" in p.stderr, "not listed exactly once" in p.stderr), (2, False, True))

    def test_e5_mutant_is_the_committed_reading(self):
        # killed by ea3 is not enough: the mutant must agree with the committed MANIFEST on all 52, ea3 included
        rows = V.run(SET, None, **V.MUTANTS["transaction_filled_when_absent"])
        self.assertEqual([r["file"] for r in rows if not r["concordant"]], [])

    def test_committed_runner_accepts_it(self):
        # the erratum as measured: the committed runner fills the omitted key with "" and verifies ea3
        p = subprocess.run([sys.executable, "-B", COMMITTED_TOOL, SET], capture_output=True, text=True, timeout=120)
        line = next(l for l in p.stdout.splitlines() if EA3 in l)
        self.assertIn("-> valid", line)

    def test_unusable_errata_files_stop_the_run(self):
        ok = {"file": EA3, "expect": "reject", "reject_reason": "malformed_payload", "erratum": "E5"}
        for body in ('{"vectors": []}', "not json", '{"vectors": [{"file": "nope.json", "expect": "reject", "erratum": "E5"}]}',
                     json.dumps({"vectors": [dict(ok, expect="maybe")]}), json.dumps({"vectors": [ok, ok]}),
                     json.dumps({"vectors": [{k: v for k, v in ok.items() if k != "erratum"}]}),
                     '{"vectors": [{"file": "x", "file": "y"}]}', '{"vectors": ["x"]}', "[1]",
                     json.dumps({"vectors": [dict(ok, erratum="")]}), json.dumps({"vectors": [dict(ok, erratum="E5]\n[OK] x")]})):
            d = tempfile.mkdtemp()
            path = os.path.join(d, "e.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            p = cli(SET, "--errata", path)
            self.assertEqual((p.returncode, "Traceback" in p.stderr, "run stopped" in p.stderr), (2, False, True), body)
        for argv in ([SET, "--errata"], [SET, "--errata", "--mutants"], [SET, "--errata", "/nonexistent/e.json"], [SET, "--errata", ""],
                     [SET, "--errata", ERRATA, "--errata", ERRATA], [SET, "--json", "a.json", "--json", "b.json"]):
            p = cli(*argv)
            self.assertEqual((p.returncode, "Traceback" in p.stderr), (2, False), argv)


class TestExitCodesAndConcordance(unittest.TestCase):
    def test_exit_codes(self):
        body = json.dumps(vec(EA1))
        self.assertEqual(cli(tmpset({"a.json": body})).returncode, 0)
        p = cli(tmpset({"a.json": body}, {"vectors": [{"file": "a.json", "expect": "reject", "reject_reason": "signer_mismatch"}]}))
        self.assertEqual((p.returncode, "concordant 0/1" in p.stdout), (1, True))
        for argv in ([], ["--help"], ["-x"], [tmpset({"a.json": body}), "--json"], [tmpset({"a.json": body}), "--json", "--mutants"],
                     [tmpset({"a.json": body}), "--json", "/nonexistent/dir/x.json"]):
            p = cli(*argv)
            self.assertEqual((p.returncode, "Traceback" in p.stderr), (2, False), argv)

    def test_wrong_reason_is_not_concordant(self):
        name = "er13-live-high-s.json"
        right = manifest_entry(name)["reject_reason"]
        for reason, want in ((right, True), ("signer_mismatch", False)):
            d = tmpset({name: json.dumps(vec(name))}, {"vectors": [{"file": name, "expect": "reject", "reject_reason": reason}]})
            self.assertEqual(V.run(d)[0]["concordant"], want)

    def test_mutants_flag_exit_follows_mutants_too(self):
        # with --mutants, exit 0 requires every built-in mutant killed: one valid vector cannot kill them all
        p = cli(tmpset({"a.json": json.dumps(vec(EA1))}), "--mutants")
        self.assertEqual((p.returncode, "SURVIVES" in p.stdout), (1, True))

    def test_unknown_option_is_ignored(self):
        self.assertEqual(cli(tmpset({"a.json": json.dumps(vec(EA1))}), "--mutant").returncode, 0)


class TestManifestAndNames(unittest.TestCase):
    def stops(self, d):
        p = cli(d)
        return (p.returncode, "Traceback" in p.stderr, "run stopped" in p.stderr)

    def test_unloadable_manifest_shapes(self):
        body = json.dumps(vec(EA1))
        for raw in ("", "{not json", "[]", '"x"', "null", '{"x": 1}', '{"vectors": {}}', '{"vectors": 5}', '{"vectors": []}',
                    '{"vectors": [1]}', '{"vectors": [{"x": 1}]}', '{"vectors": [{"file": 5}]}', '{"vectors": NaN}',
                    '{"vectors": [], "vectors": [{"file": "a.json"}]}', '{"vectors": ' + "[" * 1000 + "]" * 1000 + "}",
                    '{"vectors": ' + "[" * 100000 + "]" * 100000 + "}"):
            self.assertEqual(self.stops(tmpset({"a.json": body}, raw)), (2, False, True), raw[:40])
        d = tmpset({"a.json": body}); os.remove(os.path.join(d, "MANIFEST.json"))
        self.assertEqual(self.stops(d), (2, False, True))
        d = tmpset({"a.json": body}); os.remove(os.path.join(d, "MANIFEST.json")); os.mkdir(os.path.join(d, "MANIFEST.json"))
        self.assertEqual(self.stops(d), (2, False, True))
        with open(os.path.join(d, "MANIFEST.json", "x"), "w"):
            pass
        d = tmpset({"a.json": body}, b"\xff\xfe".decode("latin-1"))
        self.assertEqual(self.stops(d), (2, False, True))

    def test_manifest_nan_and_depth_boundary_in_an_unread_key(self):
        # proposed by an independent review (01/10): NaN/-Infinity in an unread MANIFEST key, and depth 901 vs 900
        body = json.dumps(vec(EA1))
        tail = ', "vectors": [{"file": "a.json", "expect": "valid"}]}'
        for raw in ('{"note": NaN' + tail, '{"note": -Infinity' + tail, '{"note": ' + "[" * 900 + "]" * 900 + tail):
            self.assertEqual(self.stops(tmpset({"a.json": body}, raw)), (2, False, True), raw[:20])
        self.assertEqual(cli(tmpset({"a.json": body}, '{"note": ' + "[" * 899 + "]" * 899 + tail)).returncode, 0)   # depth 900 runs

    def test_long_integer_in_an_unread_manifest_key_still_runs(self):
        d = tmpset({"a.json": json.dumps(vec(EA1))}, '{"note": ' + "9" * 5000 + ', "vectors": [{"file": "a.json", "expect": "valid"}]}')
        self.assertEqual(cli(d).returncode, 0)

    def test_unsafe_names(self):
        body = json.dumps(vec(EA1))
        for name in ("../MANIFEST.json", "/etc/hostname", "sub/a.json", "a\\b.json", "..", ".", "", "a\u0000b.json"):
            d = tmpset({"a\\b.json": body} if name == "a\\b.json" else {"a.json": body},
                       {"vectors": [{"file": name, "expect": "valid"}]})
            self.assertEqual(self.stops(d), (2, False, True), repr(name))

    def test_non_regular_or_missing_vector_files(self):
        body = json.dumps(vec(EA1))
        d = tmpset({"a.json": body}, {"vectors": [{"file": "missing.json"}]})
        self.assertEqual(self.stops(d), (2, False, True))
        d = tmpset({}, {"vectors": [{"file": "dir.json"}]}); os.mkdir(os.path.join(d, "vectors", "dir.json"))
        self.assertEqual(self.stops(d), (2, False, True))
        d = tmpset({}, {"vectors": [{"file": "f.json"}]}); os.mkfifo(os.path.join(d, "vectors", "f.json"))
        self.assertEqual(self.stops(d), (2, False, True))
        d = tmpset({}, {"vectors": [{"file": "z.json"}]}); os.symlink("/dev/zero", os.path.join(d, "vectors", "z.json"))
        self.assertEqual(self.stops(d), (2, False, True))
        d = tmpset({}, {"vectors": [{"file": "b.json"}]}); os.symlink("/nonexistent", os.path.join(d, "vectors", "b.json"))
        self.assertEqual(self.stops(d), (2, False, True))

    def test_symlink_inside_vectors_is_followed(self):
        target = tempfile.mkdtemp()
        with open(os.path.join(target, "real.json"), "w") as fh:
            fh.write(json.dumps(vec(EA1)))
        d = tmpset({}, {"vectors": [{"file": "l.json", "expect": "valid"}]})
        os.symlink(os.path.join(target, "real.json"), os.path.join(d, "vectors", "l.json"))
        self.assertEqual(cli(d).returncode, 0)

    def test_unprintable_file_name_is_escaped(self):
        d = tmpset({"café.json": json.dumps(vec(EA1))})
        out = os.path.join(d, "r.json")
        p = cli(d, "--json", out, env=dict(os.environ, PYTHONIOENCODING="ascii"))
        self.assertEqual((p.returncode, "Traceback" in p.stderr, os.path.exists(out)), (0, False, True))


class TestVectorFileContents(unittest.TestCase):
    def verdict(self, raw):
        d = tmpset({"v.json": raw}, {"vectors": [{"file": "v.json", "expect": "reject", "reject_reason": "malformed_input"}]})
        r = V.run(d)[0]
        return r["verdict"], r["reason"]

    def test_unloadable_vector_files_are_malformed_input(self):
        good = json.dumps(vec(EA1))
        live = json.dumps(vec(EA1)["input"])
        for raw in (b"\xff\xfe", b"\xef\xbb\xbf" + good.encode(), good[:-5], "", "[]" * 0 + "{", '{"input": NaN}',
                    '{"input": Infinity}', '{"input": {}, "input": ' + live + "}",
                    '{"input": ' + "[" * 899 + "]" * 899 + "}", '{"input": ' + "[" * 100000 + "]" * 100000 + "}"):
            self.assertEqual(self.verdict(raw), ("reject", "malformed_input"), repr(raw)[:50])

    def test_depth_900_loads_and_901_does_not(self):
        live = json.dumps(vec(EA1)["input"])[:-1]
        # depth = the vector object (1) + input (2) + k brackets; an extra key directly inside input is ignored (declared)
        ok = '{"input": ' + live + ', "x": ' + "[" * 898 + "]" * 898 + "}}"       # total depth 900
        bad = '{"input": ' + live + ', "x": ' + "[" * 899 + "]" * 899 + "}}"      # total depth 901
        d = tmpset({"ok.json": ok, "bad.json": bad})
        got = {r["file"]: (r["verdict"], r["reason"]) for r in V.run(d)}
        self.assertEqual(got, {"ok.json": ("valid", None), "bad.json": ("reject", "malformed_input")})

    def test_verdicts_do_not_depend_on_the_int_string_limit(self):
        live = vec(EA1)["input"]
        big = "9" * 5000
        art = json.dumps(live)
        cases = {"issued.json": art.replace('"issuedAt": 1783761710', '"issuedAt": ' + big),
                 "version.json": art.replace('"version": 1', '"version": ' + big)}
        d = tmpset({n: '{"input": ' + b + "}" for n, b in cases.items()})
        outs = []
        for limit in (None, "0", "640"):
            env = {k: v for k, v in os.environ.items() if k != "PYTHONINTMAXSTRDIGITS"}
            if limit:
                env["PYTHONINTMAXSTRDIGITS"] = limit
            outs.append(cli(d, env=env).stdout)
        self.assertEqual(len(set(outs)), 1)
        self.assertIn("malformed_payload", outs[0])


# Killer map of the 12 built-in mutants on the 52 committed vectors with ERRATA_EXPECT.json (measured 2026-10-03; pins
# each mutant's definition)
KILLERS = {
 "no_low_s": [
  "er13-live-high-s.json",
  "er15-s-at-half-n-plus-one.json",
  "er42-s-equals-n.json"
 ],
 "v_any": [
  "er16-v-zero.json",
  "er17-v-one.json",
  "er18-v-29.json"
 ],
 "extra_keys_ignored": [
  "er26-payload-extra-field.json"
 ],
 "signer_case_sensitive": [
  "ea5-expected-signer-checksum-case.json"
 ],
 "chain_id_8453": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "er01-domain-chainid-8453.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "domain_name_typo": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "er02-domain-name-letters-transposed.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "payer_lowercased": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "type_reordered": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "er04-type-fields-reordered.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "personal_sign_over_digest": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "er06-personal-sign-over-typed-digest.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "artifact_extra_keys_ignored": [
  "er38-artifact-carries-domain-and-types.json"
 ],
 "transaction_dropped_from_type": [
  "ea1-live-p1-payload-signature.json",
  "ea2-test-key-receipt.json",
  "ea4-transaction-present.json",
  "ea5-expected-signer-checksum-case.json",
  "er05-type-without-transaction.json",
  "ea6-signature-uppercase-hex-digits.json"
 ],
 "transaction_filled_when_absent": [
  "ea3-transaction-absent-equals-empty.json"
 ]
}


def sig_parts(sig):
    raw = bytes.fromhex(sig[2:])
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]


def sig_hex(r, s, v):
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()


def with_sig(r, s, v, base=EA1):
    inp = json.loads(json.dumps(vec(base)["input"]))
    inp["artifact"]["signature"] = sig_hex(r, s, v)
    return inp


class TestMutationSurvivors(unittest.TestCase):
    """Each test kills at least one non-equivalent survivor of the 2026-10-01 mutation run (343 mutants)."""

    def test_killer_map_is_exact(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, "r.json")
        p = cli(SET, "--errata", ERRATA, "--mutants", "--json", out)
        self.assertEqual(p.returncode, 0)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["mutants"], KILLERS)
        p0 = cli(SET)
        self.assertFalse(any(l.startswith("mutant ") for l in p0.stdout.splitlines()))   # no --mutants, no mutant lines

    def test_r_and_s_range_are_checked_before_low_s(self):
        r, s, v = sig_parts(vec(EA1)["input"]["artifact"]["signature"])
        for rr in (0, V.N):
            self.assertEqual(V.check(with_sig(rr, V.N - 1, v))[1], V.UNRECOVERABLE, rr)
        self.assertEqual(V.check(with_sig(r, 0, v))[1], V.UNRECOVERABLE)

    def test_v_is_checked_before_the_r_and_s_range(self):
        r, s, v = sig_parts(vec(EA1)["input"]["artifact"]["signature"])
        self.assertEqual(V.check(with_sig(0, s, 29))[1], V.MALFORMED_SIGNATURE)     # survivor m014

    def test_r_one_and_s_one_recover_a_point(self):
        r, s, v = sig_parts(vec(EA1)["input"]["artifact"]["signature"])
        self.assertEqual(V.check(with_sig(1, s, v))[1], V.SIGNER_MISMATCH)
        self.assertEqual(V.check(with_sig(r, 1, v))[1], V.SIGNER_MISMATCH)

    def test_artifact_check_precedes_format(self):
        inp = json.loads(json.dumps(vec(EA1)["input"]))
        inp["artifact"]["format"] = "jws"
        inp["artifact"]["domain"] = {}
        self.assertEqual(V.check(inp)[1], V.MALFORMED_INPUT)

    def test_zero_is_a_uint256(self):
        inp = json.loads(json.dumps(vec(EA1)["input"]))
        inp["artifact"]["payload"]["version"] = 0
        self.assertEqual(V.check(inp)[1], V.UNSUPPORTED_VERSION)
        inp = json.loads(json.dumps(vec(EA1)["input"]))
        inp["artifact"]["payload"]["issuedAt"] = 0
        self.assertEqual(V.check(inp)[1], V.SIGNER_MISMATCH)

    def test_depth_scan_strings_escapes_siblings(self):
        live = json.dumps(vec(EA1)["input"])[:-1]
        deep = "[" * 947 + "]" * 947
        cases = {"str.json": ('{"input": ' + live + ', "x": "' + "[" * 1500 + '"}}', ("valid", None)),
                 "esc.json": ('{"input": ' + live + ', "x": ["a\\"b", ' + deep + "]}}", ("reject", "malformed_input")),
                 "bs.json": ('{"input": ' + live + ', "x": ["a\\\\", ' + deep + "]}}", ("reject", "malformed_input")),
                 "sib.json": ('{"input": ' + live + ', "x": [' + ",".join(["[]"] * 60) + ", " + deep + "]}}", ("reject", "malformed_input")),
                 "after.json": ('{"input": ' + live + ', "x": [' + deep + ", []]}}", ("reject", "malformed_input"))}
        d = tmpset({n: b for n, (b, _) in cases.items()})
        got = {r["file"]: (r["verdict"], r["reason"]) for r in V.run(d)}
        self.assertEqual(got, {n: want for n, (_, want) in cases.items()})

    def test_unexpected_exception_is_internal_error(self):
        def boom(msg):
            raise KeyError("simulated runner bug")
        for fn in (boom, lambda msg: 1 // 0):
            self.assertEqual(V.check(vec(EA1)["input"], digest_fn=fn)[:2], ("reject", V.INTERNAL_ERROR))

    def test_json_report_with_an_oversized_expectation(self):
        d = tmpset({"a.json": json.dumps(vec(EA1))}, '{"vectors": [{"file": "a.json", "expect": ' + "9" * 5000 + "}]}")
        out = os.path.join(d, "r.json")
        p = cli(d, "--json", out)
        self.assertEqual((p.returncode, "Traceback" in p.stderr), (1, False))
        with open(out, encoding="utf-8") as fh:
            got = json.load(fh)["rows"][0]["expect"]   # the marker under the int-string limit, the integer itself without it
        self.assertTrue(got == "<integer of 5000 digits>" or (type(got) is int and got > 10 ** 4999), str(got)[:40])


if __name__ == "__main__":
    unittest.main(verbosity=2)
