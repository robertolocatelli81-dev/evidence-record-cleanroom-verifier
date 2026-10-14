#!/usr/bin/env python3
"""Mutants of the lines changed for v0.5.9 (verifier 0.3.0). Each mutant: a temp copy of the repo with ONE textual
replacement in verify_tersign.py (the old text must occur exactly once), then the full unittest run and the three suites.
A mutant is KILLED when the unit tests fail; the suite result is recorded beside it. The unmutated copy runs first and must pass. Usage: python3 results/v0.3.0/mutants_059.py . <out.json> (from the repository root; about 40 s per mutant)"""
import json, os, shutil, subprocess, sys, tempfile

ABL = ["no_defined_members", "head_read_late", "no_head_seq_bound", "absent_prev_rejects", "zero_prev_as_bytes",
       "apl_required", "coverage_without_apl", "claim_null_unknown", "empty_claim_lists_ok", "int_digit_limit"]
ON = '    return name not in _ABLATE\n'
MUT = [("abl:" + a, ON, '    return name not in _ABLATE and name != %r\n' % a) for a in ABL] + [
 ("M01 names case-insensitive", "            if k not in names:\n", "            if k.lower() not in [n.lower() for n in names]:\n"),
 ("M02 names stripped", "            if k not in names:\n", "            if k.strip() not in names:\n"),
 ("M03 names NFKC", "            if k not in names:\n", "            if __import__('unicodedata').normalize('NFKC', k) not in names:\n"),
 ("M04 only first array entry", "for i, e in enumerate(arr) if isinstance(e, dict))", "for i, e in enumerate(arr[:1]) if isinstance(e, dict))"),
 ("M05 stop at first non-object entry", "for i, e in enumerate(arr) if isinstance(e, dict))", "for i, e in enumerate(__import__('itertools').takewhile(lambda x: isinstance(x, dict), arr)))"),
 ("M06 nested closed object skipped", "                out.append(([member], obj, names))\n", "                pass\n"),
 ("M07 member check after criterion", "            check_defined_members(kind, inp)\n        return \"valid\", None, fn(inp)", "            d = fn(inp); check_defined_members(kind, inp); return \"valid\", None, d\n        return \"valid\", None, fn(inp)"),
 ("M08 lists compare skipped", '"match" if listed == _pinned_sorted() else "DIFFERS"', '"match"'),
 ("M09 exit ignores DIFFERS", 'res["concordant"] == res["n"] and res.get("defined_members") != "DIFFERS" else 1', 'res["concordant"] == res["n"] else 1'),
 ("M10 role dropped from pinned list", '"input.attestations[]": ("by", "role")}', '"input.attestations[]": ("by",)}'),
 ("M11 acc allowed in chain_set head", '                  "input.head": ("digest", "seq"),', '                  "input.head": ("acc", "digest", "seq"),'),
 ("M12 bound > to >=", "if hseq > CHAIN_SET_HEAD_SEQ_MAX and", "if hseq >= CHAIN_SET_HEAD_SEQ_MAX and"),
 ("M13 head.seq >= 0", "    if not is_int(hseq) or hseq < 1:\n        raise Reject(R_COMPLETENESS, f\"head.seq", "    if not is_int(hseq) or hseq < 0:\n        raise Reject(R_COMPLETENESS, f\"head.seq"),
 ("M14 head digest reason continuity", 'hdig = hex32(head.get("digest"), R_COMPLETENESS, "head.digest")', 'hdig = hex32(head.get("digest"), R_CONTINUITY, "head.digest")'),
 ("M15 zero is null only at genesis", "        if pd == zero and _on(\"zero_prev_as_bytes\"):", "        if pd == zero and s == present[0] and _on(\"zero_prev_as_bytes\"):"),
 ("M16 final head compare off", "    if present[-1] == hseq and prev_art != hdig:", "    if False and prev_art != hdig:"),
 ("M17 empty prefix accepted", "    if not prefix:\n        raise Reject(R_BOUNDARY", "    if False:\n        raise Reject(R_BOUNDARY"),
 ("M18 apl upper +1", "if not is_int(apl) or apl < 0 or apl > len(prefix):", "if not is_int(apl) or apl < 0 or apl > len(prefix) + 1:"),
 ("M19 apl lower -1", "if not is_int(apl) or apl < 0 or apl > len(prefix):", "if not is_int(apl) or apl < -1 or apl > len(prefix):"),
 ("M20 apl null as absent", '    if "attestedPrefixLength" in ev:\n', '    if ev.get("attestedPrefixLength") is not None:\n'),
 ("M21 ct null as absent", '    if "covered_through" in inp:\n        ct = inp["covered_through"]', '    if inp.get("covered_through") is not None:\n        ct = inp["covered_through"]'),
 ("M22 ct >= apl", "if apl is not None and ct > apl and", "if apl is not None and ct >= apl and"),
 ("M23 ct >= -1", "        if not is_int(ct) or ct < 0:\n", "        if not is_int(ct) or ct < -1:\n"),
 ("M24 position only upper", "        if pos != len(prefix):\n", "        if pos > len(prefix):\n"),
 ("M25 issuer_attested not silent", 'CLAIM_SILENT = ("", "none", "issuer_attested")', 'CLAIM_SILENT = ("", "none")'),
 ("M26 silence tokens not dropped", "    remaining = [t for t in tokens if t not in silent]\n", "    remaining = list(tokens)\n"),
 ("M27 case-folded vocabulary", "    unknown = [t for t in remaining if t not in CLAIM_ASSERTING]\n", "    unknown = [t for t in remaining if t.lower() not in CLAIM_ASSERTING]\n"),
 ("M28 array of any strings", "    elif isinstance(claimed, list) and all(is_text(t) for t in claimed):\n", "    elif isinstance(claimed, list) and any(is_text(t) for t in claimed):\n"),
 ("M29 any independent suffices", "    if not any(t in CLAIM_ASSERTING for t in remaining):\n", "    if not all(t in CLAIM_ASSERTING for t in remaining) or not remaining:\n"),
 ("M30 chunk factor fixed", "        v = v * 10 ** len(c) + int(c)\n", "        v = v * 10 ** _INT_CHUNK + int(c)\n"),
 ("M31 sign dropped", "    out = BigInt(-v if neg else v)\n", "    out = BigInt(v)\n"),
 ("M32 _r catches TypeError", "    except ValueError:\n        return f\"<{type(v).__name__} holding", "    except TypeError:\n        return f\"<{type(v).__name__} holding"),
 ("M33 member mutants dropped", '    mut("member:undefined-top", lambda i: i.__setitem__("x_mutant_undefined", 1))\n', ''),
 ("M34 records entries not object -> skipped by criterion", '        r = need_dict(r, R_COMPLETENESS, "record")\n', '        if not isinstance(r, dict):\n            continue\n'),
 ("M35 n148 entries after non-object", "out.extend(([member, i], e, names) for i, e in enumerate(arr) if isinstance(e, dict))", "out.extend(([member, i], e, names) for i, e in enumerate(arr) if isinstance(e, dict) and i == 0)"),
]


def main():
    repo, out = os.path.abspath(sys.argv[1]), sys.argv[2]   # absolute: the suites are symlinked from a temp dir
    src = open(os.path.join(repo, "verify_tersign.py"), encoding="utf-8").read()
    res = []
    # review 2026-10-14: the unmutated copy must pass first; with a relative path the symlinks pointed at themselves
    # and every mutant counted as killed
    MUT.insert(0, ("BASELINE (no mutation)", src, src))
    for name, old, new in MUT:
        n = src.count(old)
        if n != 1:
            res.append({"mutant": name, "status": "NOT-APPLIED", "count": n}); print(name, "NOT-APPLIED", n, flush=True); continue
        d = tempfile.mkdtemp(prefix="m059_")
        for f in ("test_verify_tersign.py", "verify_tersign.py"):
            shutil.copy(os.path.join(repo, f), d)
        for f in ("spec", "spec-0.5.7", "spec-0.5.9", "heldout"):
            os.symlink(os.path.join(repo, f), os.path.join(d, f))
        with open(os.path.join(d, "verify_tersign.py"), "w", encoding="utf-8") as fh:
            fh.write(src.replace(old, new))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        u = subprocess.run([sys.executable, "-m", "unittest", "test_verify_tersign"], cwd=d, capture_output=True, text=True, env=env)
        failed = [l.split(" ")[1] for l in u.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
        suites = {}
        for sd in ("spec-0.5.9", "spec-0.5.7", "spec"):
            r = subprocess.run([sys.executable, "verify_tersign.py", sd + "/", "--quiet"], cwd=d, capture_output=True, text=True, env=env)
            suites[sd] = (r.returncode, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:])
        st = "KILLED" if u.returncode != 0 else "SURVIVED"
        if name.startswith("BASELINE"):
            if u.returncode != 0 or any(v[0] != 0 for v in suites.values()):
                print("BASELINE FAILS: the bench cannot tell a mutant from the code; nothing measured", failed[:3], suites, flush=True)
                sys.exit(2)
            print(name, "passes", suites["spec-0.5.9"], flush=True)
            shutil.rmtree(d)
            continue
        res.append({"mutant": name, "status": st, "unittest_rc": u.returncode, "failed_tests": failed, "suites": suites})
        print(name, st, len(failed), suites["spec-0.5.9"], flush=True)
        shutil.rmtree(d)
    json.dump(res, open(out, "w"), indent=1, ensure_ascii=False)
    print("killed", sum(r["status"] == "KILLED" for r in res), "of", len(res), "; not applied", sum(r["status"] == "NOT-APPLIED" for r in res))


main()
