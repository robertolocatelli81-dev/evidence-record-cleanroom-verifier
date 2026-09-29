# Out-of-suite differential: 524 deterministic variants of the 69 vectors

The 69-vector suite pins what its authors chose to pin. To see where two implementations of the same
manifest diverge on inputs the suite does NOT pin, this folder derives 524 variants from the 69 vectors
with a seeded generator and compares, per variant, the verdict of this repository's verifier with the
verdict the upstream verifier printed on the very same bytes.

## Files

- `generate_variants.py` — the deterministic generator (seed 20260928; `random.Random` consumed in
  manifest order). Regeneration on Python 3.9.25, 3.11.2 and 3.13.15 produced 524/524 byte-identical
  variant files and an identical mutated MANIFEST (sha256 `b738f040a7ecf3dd199011c33611c7b81aa2c56c96054e39f552e0681dff51ea`).
- `upstream_stdout_0eda3038.txt` — the recorded stdout of the upstream verifier on those 524 variants
  (sha256 `323713bbfacd8682254f5f914b402ed1f6d2d0a71cec46645b35ee43de31656b`, 526 lines: 524 verdict lines,
  one blank, one summary line). It is the OUTPUT of an Apache-2.0 tool on inputs generated here, not code;
  it was run by the author of this repository, exactly as described in "How the upstream side was obtained".
- `compare_recorded.py` — runs ONLY this repository's verifier on the variants and compares with that
  recording (line format `[PASS|FAIL] <file> -> valid|reject|malformed[/reason] (detail)`). The upstream
  code is never read by anything in this repository; only its recorded output is.
- `results/compare_py311.json` (and `_py39`, `_py313`) — every per-variant pair (our verdict/reason/detail,
  upstream verdict/reason/detail), the class of each disagreement, the SHA-256 of every input, and the counts
  below; `results/compare_py*.log` are the headed logs.

## How the upstream side was obtained (exact procedure)

1. Clone `tersignhq/evidence-record-conformance` at commit `0eda303875168f3399f91306853f337a284729e0`.
2. Copy it without `.git`.
3. Replace its `MANIFEST.json` with the generated variant manifest (`<out_dir>/MANIFEST.json`, sha256 `b738f040…dff51ea`).
4. Remove every file in `vectors/` and put the 524 generated variant files there.
5. From that directory run `python3 -I -B verify.py` (Python 3.11.2, on 2026-09-28).
6. Its stdout is the recorded output (`upstream_stdout_0eda3038.txt`); lines read as
   `[PASS|FAIL] <file> -> <valid|reject|malformed>[/<reason>]`. Exit status 1 is expected, because every
   variant carries a dummy `expect: valid` in the variant manifest, so the upstream harness prints a
   "NON-CONFORMANT" summary line (ignored by the comparison).

The step was run by the author of this repository in a session separate from the clean-room session that
wrote the verifier; the clean-room session and this repository's code never opened `verify.py`.

## Measured (identical on Python 3.9.25 / 3.11.2 / 3.13.15; logs `results/compare_py*.log`)

| set | n | accept / non-accept agree | verdict + reason agree (non-malformed) |
|---|---|---|---|
| all variants | 524 | **512/524** | 488/492 |
| variants that change `input` | 430 | **428/430** | 416/420 |
| variants that change only metadata (`description`, `id`, `expect`, `kind`, …) | 94 | 84/94 | 72/72 |

Upstream verdicts on the 524: valid 113, reject 379, "malformed" 32 (the upstream harness reports an
exception instead of a verdict). Ours: valid 121, reject 403. Cases where upstream rejects and we accept: **0**.

The 12 residual disagreements, all read against the clauses:

- **10 harness differences (metadata only).** The variant's file-level `kind` is upper-cased while the
  manifest's stays lower-case. Upstream reports `malformed (kind mismatch)`; we read the kind from the
  manifest and never open the file's `kind`. No clause either way; a cross-check of the two would be an
  optional hardening, not a conformance point.
- **2 boundary readings the manifest leaves open** (see the main README, "Readings where the manifest is
  silent"): `mut0359` — empty attestation (`attestedPrefixLength` 0) with no coverage claimed: upstream valid,
  we reject on n26's "unattested must be its own outcome rather than a pass" (pinned by our held-out vector
  h5); `mut0375` — `attestedPrefixLength` 4 on a 3-event prefix: upstream valid, we reject as a sanity bound
  that no clause states in either direction.
- 2 reason-only differences (`mut0038`, `mut0492`: unparseable `head.digest` → upstream
  `completeness_reject`, ours `continuity_reject`); the manifest assigns no reason to that case.

## What this does and does not show

It shows that on 430 input-changing variants the two implementations disagree on 2, both in a kind the
manifest has no rule for, and that no variant is rejected upstream and accepted here. It does not show
conformance to any specification beyond the manifest: the variants are perturbations of the suite's own
inputs, and `expect` is not an oracle for them.

## Reproduce

```
python3 docs/differential/generate_variants.py spec/ /tmp/variants          # sha256 of /tmp/variants/MANIFEST.json = b738f040…dff51ea
python3 docs/differential/compare_recorded.py /tmp/variants spec/ /tmp/compare.json   # uses upstream_stdout_0eda3038.txt from this folder
```
To re-produce the upstream side yourself, follow "How the upstream side was obtained" and pass the resulting
stdout as the second argument: `compare_recorded.py /tmp/variants <your_stdout.txt> spec/ /tmp/compare.json`.
