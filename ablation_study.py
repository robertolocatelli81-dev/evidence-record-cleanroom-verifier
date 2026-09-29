#!/usr/bin/env python3
"""ablation_study.py — disable ONE rule at a time in verify_tersign and measure which vectors
become discordant with the manifest. A rule that, once removed, leaves every vector concordant
is a rule the suite does not pin (or that this implementation does not really exercise).

Usage: python3 ablation_study.py spec/ [--json results/ablations.json]
"""
import argparse
import json
import sys

import verify_tersign as V


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("spec_dir")
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    V._ABLATE.clear()
    base = V.run_suite(args.spec_dir)
    assert base["concordant"] == base["n"], "baseline must be fully concordant before ablating"
    out = {"baseline": {"concordant": base["concordant"], "n": base["n"]}, "ablations": {}}
    print(f"baseline: {base['concordant']}/{base['n']} concordant")
    for name, desc in V.ABLATIONS.items():
        V._ABLATE.clear()
        V._ABLATE.add(name)
        res = V.run_suite(args.spec_dir)
        disc = [(r["file"], f"{r['expect']}/{r['expect_reason']}", f"{r['verdict']}/{r['reason']}")
                for r in res["rows"] if not r["concordant"]]
        verdict_disc = [r["file"] for r in res["rows"] if not r["verdict_ok"]]
        out["ablations"][name] = {"description": desc, "concordant": res["concordant"], "n": res["n"],
                                  "verdict_discordant": verdict_disc,
                                  "discordant": [{"file": f, "expect": e, "got": g} for f, e, g in disc]}
        print(f"\n== ablate {name}: {desc}")
        print(f"   concordant {res['concordant']}/{res['n']}  (verdict flips: {len(verdict_disc)}, reason-only: {len(disc) - len(verdict_disc)})")
        for f, e, g in disc:
            print(f"   DISC {f:<56} expect={e:<34} got={g}")
    V._ABLATE.clear()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
    weak = [n for n, a in out["ablations"].items() if not a["discordant"]]
    print(f"\nablations with NO discordant vector (unpinned rules): {weak if weak else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
