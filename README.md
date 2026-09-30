# evidence-record-cleanroom-verifier

An **independent, clean-room verifier for the Tersign `evidence-record-conformance` suite** (v0.5.3, 69 vectors,
upstream commit 0eda3038). Not affiliated with, endorsed by, or maintained by Tersign; "Tersign" here only names
the suite this verifier targets.

Python 3.9+ standard library only. One command:

```
python3 verify_tersign.py spec/
```

prints a verdict (`valid` / `reject`) and a reason code for each of the 69 vectors and exits 0 only if every
verdict, and every reason the manifest names, matches the manifest's `expect`.

## What it is for

The suite's own criterion of a "complete reproduction" asks for an implementation **not written by the suite's
authors** that executes the whole vector set. This repository is such an implementation, written under a
clean-room rule, with the measurements that show the verifier can fail (flipped expectations, mutated vectors,
ablations), a vector-by-vector audit of the suite itself, an out-of-suite differential against the upstream
verifier's recorded output, and every reading declared where the manifest is silent.

A complete independent reproduction was published earlier by @stillmarcus24
(tersignhq/evidence-record-conformance#8). This repository makes no claim about priority.

## Clean room: what was read, what was not

Written on 2026-09-28 in a separate, isolated session given ONLY:

- `spec/MANIFEST.json` and the 69 files in `spec/vectors/` (including their `description` fields, which are
  Tersign's prose and were used as clauses where the manifest is silent — declared case by case below);
- `vendor/` — two Apache-2.0 files by Roberto Locatelli (the Keccak-256 core is copied verbatim, with the wrapper
  renamed `keccak256_pure`; the JCS in `verify_tersign.py` is a fresh implementation written from RFC 8785);
- public specifications read online: RFC 8785, RFC 7493, the x402 `compliance_fields.md` extension text
  (x402-foundation/x402 PR #2853 at commit b8a81c0 — an **open, unmerged draft** authored by the suite's author),
  MCP issue #3004 comments.

NOT read: Tersign's `verify.py`, `keccak.py`, `tools/`, README, TypeScript engine, or their GitHub repository.
Tersign's behaviour was compared only through recorded **output** of their verifier (see the differential below).

Limit of this claim: the session transcript proves which tools and files were used; it cannot prove what a
language model already knew. Take "clean room" as "no Tersign code was opened", not as a statement about
prior knowledge. The manifest's rule texts and the vectors' descriptions are Tersign's prose: where a rule exists
only there, the verifier follows that prose and says so.

## Measured results

All numbers below were produced on Python 3.9.25, 3.11.2 and 3.13.15 with identical outcomes; the headed logs
(command, interpreter, clock time, exit code) and JSON files are in `results/`.

| measure | value | reproduce |
|---|---|---|
| suite: verdicts / named reasons | **69/69**, **40/40** | `python3 verify_tersign.py spec/` |
| held-out separator vectors (ours, 5) | 5/5 | `python3 verify_tersign.py heldout/` |
| unit tests | 56/56 | `python3 -m unittest -v test_verify_tersign` |
| positive control: every `expect` flipped | 0/69 concordant, exit 1 | `python3 verify_tersign.py spec/ --flip-expect` |
| positive control: mutations of the 29 valid vectors | 66/66 become reject | `python3 verify_tersign.py spec/ --mutate` |
| positive controls on live-ledger values, independent of `expect` | 11/11 | `python3 positive_controls.py spec/` |
| ablations, one rule off at a time | 13/14 produce discordant vectors | `python3 ablation_study.py spec/` |
| vector audit of the suite (Q1–Q4, 50 ablations, live data, OTS proofs) | 58 CORRECT / 11 DOUBTFUL / 0 WRONG; live checks 34/34, OTS 13/13 | `docs/vector-audit/` |
| out-of-suite differential vs the upstream verifier's recorded output, 524 variants | 512/524 accept/non-accept; 428/430 on the 430 variants that change `input`; 488/492 verdict+reason on non-malformed; 0 cases upstream-reject / ours-valid | `docs/differential/` (the recording `upstream_stdout_0eda3038.txt` is redistributed there with the exact procedure that produced it: upstream `verify.py` @ 0eda3038 run on the regenerated variants) |

The ablation that produces no discordant vector is "do not require `position`": under our reading the vector
meant to pin it (n25) is over-determined (it also lacks the attestation fields), so the suite does not pin that
rule separately. Four reasons (n4, n34, n11, n35) are pinned only through the order of checks. Both facts are
measured in `docs/vector-audit/AUDIT_69.md`, which also states where the suite is solid.

## Crypto profile: counter-signature recovery (tersignhq/evidence-record-conformance PR #11)

`crypto_profile/verify_countersig.py` is a second, separate runner for the crypto profile of
tersignhq/evidence-record-conformance PR #11 (EIP-191 `personal_sign` counter-signatures over chain links). It was
written from that PR's `crypto/README.md`, `MANIFEST.json` and vectors, without reading the PR's `verify_crypto.py`,
which every comparison ran as a black box; after the first version, a separate local patching experiment of ours
read `verify_crypto.py` (it is not used by this runner, and the docstring says so). Hashing and `chain_link` come from `verify_tersign.py`. It follows the eight steps of the PR README at
`4108697` (identifiers stripped of Unicode White_Space and lower-cased before the shape check, `seq` in [1, 2^53 − 1],
`link_version`, signature matched whole); where an earlier reading of ours differed, the vectors decided, and the
docstring records it.

| measure (Python 3.9.25 / 3.11.2 / 3.13.15, identical) | value | reproduce |
|---|---|---|
| PR #11 vectors at `4108697` | 37/37 verdicts and reasons | `python3 crypto_profile/verify_countersig.py <dir with the PR's crypto/MANIFEST.json and crypto/vectors>` |
| mutants of this runner, each killed by a named vector | 5/5 | same, with `--mutants` |
| unit tests (built from this repository's own p1/p4 data) | 14/14 | `python3 -m unittest -v test_crypto_profile` |

The PR's vectors are not redistributed here; fetch them from the PR branch at the commit you want to test. The live
audit (`docs/vector-audit/live_check.py`) rejects non-canonical ECDSA signatures (65 bytes, `v` in {27, 28},
EIP-2 low-s) before recovery; its check refuses the high-s twin of the published p1 counter-signature, and all
15 published signatures it checks are canonical.

## Readings where the manifest is silent (all declared, none chosen from a vector's outcome)

- economic phase vocabulary: funding, delivery, settlement, refund, reversal — consistent with the draft Tersign
  itself proposes to x402 (PR #2853, open) — with strict equality between the record's phase and the presented phase
  (the draft forbids only a "later phase"; equality is the stricter reading);
- independence claim tokens: `independent` asserts; `none` / `issuer_attested` are silence (from p9/p11's text);
  unknown tokens fail closed (n8/n9); an ABSENT `claimed` field is silence (K1, p9 "Silence is a valid state");
- scheme-qualified identifiers compare case-significant (manifest) while the vector text and the draft say
  case folds: a conflict the suite does not pin; trailing `/` `.` `#` fold toward "same party" (n31); a `0X`
  prefix does not parse (the lowercase fold is applied to the hex digits, not to the prefix); a 0x-address must be
  exactly 40 hex digits;
- `chain_link`: an ABSENT `prev_digest` is read as the genesis predecessor (null), whereas `chain_set` requires the
  key to be present ("wire form of a genesis predecessor is null" — the manifest speaks of the wire form, not of an
  absent key; the two kinds read it differently and no vector separates them);
- boundary events: the manifest has no rule; prefix digest = keccak256(JCS(prefix array)) under the prior suite
  (calibrated on p18 and independently confirmed by n29's sha3 value), `position` must equal the prefix length,
  `attestedPrefixLength` must lie in 0..len(prefix) (a sanity bound no clause states), `attestedPrefixLength == 0`
  rejects with or without a coverage claim (n26), a coverage claim beyond the attestation rejects, a missing coverage
  claim is nothing to compare (K3, p18 "the coverage it claims");
- number domain is evaluated before anything else about the bytes (K2, manifest `canonicalization`; draft "MUST
  reject it before computing");
- inputs the manifest's reason vocabulary does not cover (unreadable file, JSON nesting deeper than the parser
  allows, lone surrogates in a string field, an unknown `kind`) reject with the extra reason `input_reject`: a
  reject, never a crash.

K1–K3 were applied on 2026-09-29 after the out-of-suite differential exposed them; each is motivated by the
clause quoted in the code, has positive and negative unit tests, and a held-out vector in `heldout/`. Two
robustness fixes from an adversarial code review of the same day (a `RecursionError` on deep nesting escaped as a
crash; a huge `head.seq` materialised a range and exhausted memory) are covered by tests too. The 69-vector result
did not change.

## Scope (honest, the same as the suite's structural profile)

Digests, canonical bytes, chain arithmetic, sequence closure, declared-claim evaluation. **Not** verified by the
verifier: secp256k1 counter-signatures over the links, the real-world identity behind an attestor address,
OpenTimestamps proofs or Bitcoin blocks (the anchor relation is checked as a SHA-256 relation only). A structurally
complete set recomputed wholesale by one forging party passes the structural predicate, here as upstream.
Percent-encoded identifiers are not decoded (n31 leaves that open). The vector audit in `docs/vector-audit/` does
go further for the three live vectors (counter-signature recovery, OTS proof replay against two public block
explorers), as a check of the suite's data, not as part of the verifier.

## Layout

- `verify_tersign.py` — the verifier; each rule cites the manifest / specification sentence it derives from.
- `test_verify_tersign.py` — unit tests (`unittest`).
- `crypto_profile/verify_countersig.py`, `test_crypto_profile.py` — the crypto-profile runner (PR #11) and its tests.
- `positive_controls.py`, `ablation_study.py`, `run_logged.py` — the bench that can fail, and headed logs.
- `spec/` — the upstream manifest and vectors, unmodified, Apache-2.0, hash-pinned (`SPEC_SHA256SUMS`, `spec/NOTICE.tersign.md`).
- `heldout/` — 5 separator vectors written here (not part of the upstream suite).
- `vendor/` — Roberto Locatelli's primitives with provenance (`vendor/PROVENANCE.md`).
- `results/` — measured artefacts (JSON + headed logs) on the three interpreters.
- `docs/vector-audit/` — the vector-by-vector audit (`AUDIT_69.md`, `audit_69.json`), its scripts, captured live
  bytes and measurement files. Re-running the audit scripts rewrites their measurement files in place; only the
  timestamps and the interpreter line change.
- `docs/differential/` — the deterministic variant generator, the comparison script, the recorded upstream
  output with the exact procedure that produced it, and the results.
- `DELIVERABLES_SHA256SUMS` — SHA-256 of every tracked file except itself (the upstream vectors are also
  covered by `SPEC_SHA256SUMS`, the vendored primitives by `vendor/PROVENANCE.md`).

CI (`.github/workflows/ci.yml`): Python 3.9 / 3.11 / 3.13 run the hash check, unit tests (verifier and crypto profile), suite, held-out, the
positive controls, the ablations, the offline audit checks and the deterministic regeneration of the 524 variants,
with no network; a separate job runs gitleaks (pinned release, default rules).

## License and attribution

Apache-2.0 (`LICENSE`, `NOTICE`). The upstream vectors are redistributed unmodified under their Apache-2.0 license
with attribution to their authors (Tersign (@wowlegend), @Rul1an, @0rkz, @mohammedmessaoudene-cmd, @navigatorbuilds).

## Authorship

Noûs, AI agent operating under a revocable mandate from Roberto Locatelli, who reviews and is accountable.
