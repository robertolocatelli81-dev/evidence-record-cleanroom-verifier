# evidence-record-cleanroom-verifier

An **independent, clean-room verifier for the Tersign `evidence-record-conformance` suite** (v0.5.7, 162 vectors,
upstream tag `v0.5.7` = commit 112b3ed6; written first against v0.5.3, 69 vectors, upstream commit 0eda3038, which
it still runs). Not affiliated with, endorsed by, or maintained by Tersign; "Tersign" here only names the suite this
verifier targets.

Python 3.9+ standard library only. One command:

```
python3 verify_tersign.py spec-0.5.7/      # v0.5.7, 162 vectors
python3 verify_tersign.py spec/            # v0.5.3, 69 vectors (byte-identical to the same 69 files in v0.5.7)
```

prints a verdict (`valid` / `reject`) and a reason code for each vector and exits 0 only if every verdict, and every
reason the manifest names, matches the manifest's `expect`.

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

Alignment to v0.5.7 (2026-10-12, verifier 0.2.0), in a separate session given ONLY: the v0.5.7 `MANIFEST.json`, its
`LICENSE` and the 162 files in `vectors/` (with their `description` fields), fetched with a sparse checkout of those
three paths at 9be9eec9 (identical on those paths to the tag `v0.5.7`, commit 112b3ed6), and this repository; the
upstream file list (names and sizes from the GitHub `git/trees` API) was read to choose those paths. NOT
read in that session: `verify.py`, `keccak.py`, `tools/`, `crypto/`, `.github/`, README, CONTRIBUTORS, CONTRIBUTING
or SECURITY of the upstream repository. Every rule changed for v0.5.7 cites the manifest sentence it implements.

Limit of this claim: the session transcript proves which tools and files were used; it cannot prove what a
language model already knew. Take "clean room" as "no Tersign code was opened", not as a statement about
prior knowledge. The manifest's rule texts and the vectors' descriptions are Tersign's prose: where a rule exists
only there, the verifier follows that prose and says so.

## Measured results

Verifier 0.2.0 (2026-10-12), Python 3.9.25, 3.11.2 and 3.13.15 with identical rows; headed logs and JSON in
`results/v0.2.0/`:

| measure | value | reproduce |
|---|---|---|
| suite v0.5.7: verdicts / named reasons | **162/162**, **106/106** | `python3 verify_tersign.py spec-0.5.7/` |
| suite v0.5.3: verdicts / named reasons | **69/69**, **40/40** | `python3 verify_tersign.py spec/` |
| held-out separator vectors (ours, 5) | 5/5 | `python3 verify_tersign.py heldout/` |
| unit tests | 81/81 | `python3 -m unittest -v test_verify_tersign` |
| positive control: every `expect` flipped | 0/162 and 0/69 concordant, exit 1 | `python3 verify_tersign.py spec-0.5.7/ --flip-expect` |
| positive control: mutations of the valid vectors | 114/114 (v0.5.7, 56 valid vectors), 66/66 (v0.5.3) become reject | `python3 verify_tersign.py spec-0.5.7/ --mutate` |
| positive controls on live-ledger values, independent of `expect` | 11/11 on either directory | `python3 positive_controls.py spec-0.5.7/` |
| ablations, one rule off at a time (22 rules) | 20/22 produce discordant vectors on v0.5.7; 13/22 on v0.5.3 | `python3 ablation_study.py spec-0.5.7/` |
| out-of-suite differential vs the upstream v0.5.3 verifier's recorded output, 524 variants | 511/524 accept/non-accept; 427/430 on the 430 variants that change `input`; 487/492 verdict+reason on non-malformed; 1 case upstream-reject / ours-valid (see below) | `docs/differential/` with `results/v0.2.0/differential_compare_py*.json` |

The two ablations that produce no discordant vector on v0.5.7: "do not require `position`" (under our reading the
vector meant to pin it, n25, is over-determined: it also lacks the attestation fields) and "do not join a surrogate
pair written half raw" (n93, the only vector with such a pair, rejects with the same reason whether or not the pair is
joined: unjoined, its raw half is an unpaired surrogate; the manifest says "no vector pins whether a pair written half
raw accepts where it repeats no name"). Each of the eight rules added for v0.5.7, `no_pair_join` included, is killed
by the unit tests when it is turned off (1 to 4 of the 14 `TestSuite057` tests fail per rule, with the rule off for the
whole run; the 14 v0.5.3 ablations were not measured against the unit tests). On v0.5.3 none of the eight rules added
for v0.5.7, turned off, makes a vector discordant, so 13/22.

The differential compares with output recorded from the upstream **v0.5.3** verifier (commit 0eda3038). Verifier
0.1.0 measured 512/524, 428/430, 488/492 and 0 upstream-reject / ours-valid (re-measured on 2026-10-12 with the same
recording and the 1a9146d verifier: the same four numbers). The one difference with 0.2.0 is `mut0391`, p21 with
its first party upper-cased to `ORG:CALDERA-ROBOTICS`: the v0.5.3 rule (lower-case scheme) made it unparseable and
upstream v0.5.3 rejected; the v0.5.7 rule ("a letter, then letters, digits ... letters in either case"; "The result
is lowercased, the scheme included") parses it, the attestor stays outside the parties, and 0.2.0 accepts. No output
of an upstream v0.5.7 verifier was recorded or compared.

Verifier 0.1.0 (2026-09-29, v0.5.3 only; `results/*.log`, `results/*.json`): the vector audit of the suite
(`docs/vector-audit/`: 58 CORRECT / 11 DOUBTFUL / 0 WRONG on the 69 vectors, live checks 34/34, OTS 13/13) was
measured with that version and is not repeated for the 93 vectors v0.5.7 added. Four v0.5.3 reasons (n4, n34, n11,
n35) are pinned only through the order of checks (`docs/vector-audit/AUDIT_69.md`).

## Changes

**0.2.0 (2026-10-12) — aligned to suite v0.5.7.** On the 162 v0.5.7 vectors the 0.1.0 code (1a9146d) gave 137/162
fully concordant (141/162 verdicts, 85/106 named reasons); 0.2.0 gives 162/162 (162/162, 106/106). The 25 discordant
vectors, by the v0.5.7 manifest clause that decides them:

- `identifier_normalization`, 19 verdicts: p31, p37, p38, p56 (valid, were rejected as unparseable) and n45, n48,
  n49, n50, n53, n54, n55, n56, n59, n60, n61, n62, n67, n69, n70 (reject, were accepted);
- `chain_link` seq domain [1, 2^53-1], 2 verdicts: n75 (seq 0), n76 (seq 2^53);
- `canonicalization`, payload_text shape before number tokens, 1 reason: n92 (was `number_domain_reject`);
- `canonicalization`, "a criterion that digests an object rejects it with its own reason", 3 reasons: n94, n95 (were
  `canonicalization_reject`, now `binding_reject`), n96 (now `boundary_reject`).

n93 (a duplicate name written once as a half-raw pair) was concordant under 0.1.0 for a different cause: the raw half
was read as an unpaired surrogate; 0.2.0 joins the pair and rejects on the duplicate name. Also changed: the exact
White_Space strip (Python's `str.strip()` also strips U+001C-U+001F) for identifiers, digests and the derived
`transaction` / `network`; a blank `transaction` after that strip commits to no settlement; `deliverable_bytes` with
an unpaired surrogate is an `independence_reject` instead of an internal error wherever the claim's scope is
evaluated; a non-integer number token (`1.5`) is no longer read as a string in `transaction`, `network`,
`deliverable_bytes` and `payload_text` (`transaction: 1.5` committed a settlement); the `--mutate` control's phase mutant
was a no-op on a funding record (p47, new in v0.5.7: 113/114 flipped) and now picks a different phase (114/114).
Eight new ablation switches, one per rule above; 14 new unit tests (81 in all), generative over every code point for
the strip, every byte in both hex cases for percent triplets, 40,000 seeded identifiers against an oracle written
separately from the manifest text, and seeded inputs for the other rules; 12 of the 14 fail on 1a9146d (the two that
pass are checks on the vector files: the 69 v0.5.3 files are byte-identical in v0.5.7, and v0.5.7 carries no member
outside the 0.5.3 lists). The 69/69 result on v0.5.3 did not change.

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
| unit tests (built from this repository's own p1/p4 data) | 38/38 | `python3 -m unittest -v test_crypto_profile` |

The PR's vectors are not redistributed here; fetch them from the PR branch at the commit you want to test. The live
audit (`docs/vector-audit/live_check.py`) rejects non-canonical ECDSA signatures (65 bytes, `v` in {27, 28},
EIP-2 low-s) before recovery; its check refuses the high-s twin of the published p1 counter-signature, and all
14 published signatures it checks (13 ledger counter-signatures and one anchor signature) are canonical.

## evidence-pinning rev 9 (x402-foundation/tsc#4)

`evidence-pinning-rev9/` holds a second implementation of the evidence-set step of
`draft-krausz-verification-state-03` (5.3, 5.4.1), run on the 47 vectors of TKCollective/tanilo-receipt-spec rev 9
(corpus at `0dffb77`): 47/47 outcomes, 47/47 under the runner notes' rule, 44/47 when the reported set must equal the
named condition, and the same output as babyblueviper1's transcript on all 47 lines. What was read before the run,
the readings, the frozen hashes and the controls are in that folder's README; the CI job reruns it on every push.

## Readings where the manifest is silent (all declared, none chosen from a vector's outcome)

Since v0.5.7 the manifest itself states several rules that were readings here under v0.5.3: the closed phase
vocabulary with strict equality (`phase_claim`), the identifier normalization (case folded, scheme included; percent
triplets of unreserved characters decoded; `?`, dot-segments and a fragment with content do not parse; the
White_Space strip; an identifier ending in a 0x-address names that address), and the chain_link `seq` domain
[1, 2^53-1]. They are implemented as written and are no longer readings. What remains:

- independence claim tokens: `independent` asserts; `none` / `issuer_attested` are silence (from p9/p11's text);
  unknown tokens fail closed (n8/n9); an ABSENT `claimed` field is silence (K1, p9 "Silence is a valid state");
- digests: "Digests compare after the same whitespace strip, lowercased" is applied to the whole string, so a
  digest written `0X…` reads as `0x…` (no vector has one);
- `chain_link`: an ABSENT `prev_digest` is read as the genesis predecessor (null), whereas `chain_set` requires the
  key to be present ("wire form of a genesis predecessor is null" — the manifest speaks of the wire form, not of an
  absent key; the two kinds read it differently and no vector separates them); `chain_set` `head.seq` and record
  `seq` are not bounded by 2^53-1 (the manifest states that bound for `chain_link`);
- boundary events: the manifest has no rule; prefix digest = keccak256(JCS(prefix array)) under the prior suite
  (calibrated on p18 and independently confirmed by n29's sha3 value), `position` must equal the prefix length,
  `attestedPrefixLength` must lie in 0..len(prefix) (a sanity bound no clause states), `attestedPrefixLength == 0`
  rejects with or without a coverage claim (n26), a coverage claim beyond the attestation rejects, a missing coverage
  claim is nothing to compare (K3, p18 "the coverage it claims");
- number domain first (K2, manifest `canonicalization`; draft "MUST reject it before computing") for a `payload`
  given as an object; for `payload_text` v0.5.7 orders the two faults the other way ("its shape, an unpaired
  surrogate included, is decided before its number tokens (n92)") and the verifier follows it;
- a surrogate pair written half raw and half escaped is joined into its code point (names compare "as UTF-16 code
  units"), so where it repeats no name it canonicalizes and accepts (the manifest: "no vector pins" this);
- an object a criterion binds (offer, decision evidence, boundary prefix) that has no canonical form rejects with
  that criterion's reason (n94-n96 for an unpaired surrogate; read the same for nesting deeper than 512); a non-integer
  number token in it keeps `number_domain_reject` (no clause or vector moves it);
- `deliverable_bytes` holding an unpaired surrogate has no UTF-8 bytes to digest: wherever the claim's scope is
  evaluated (an asserted `independent` claim with `covers`, whatever `covers` names) the claim rejects with
  `independence_reject` (until 0.2.0 that case surfaced as `input_reject`, an internal UnicodeEncodeError); without
  `covers` the field is not read, and a `deliverable_bytes` that is not a JSON string commits to no delivery;
- a JSON number is not a string: where the manifest reads a string (`transaction`, `network`, `deliverable_bytes`,
  `payload_text`) a non-integer number token such as `1.5` is not one, as an integer is not (until the 2026-10-12
  review it was read as its text); a `payload_text` given as `2.0` therefore rejects as "not a string holding JSON
  text" (`canonicalization_reject`, n43/n44), not as `number_domain_reject` (no vector pins this case);
- inputs the manifest's reason vocabulary does not cover (unreadable file, JSON nesting deeper than the parser
  allows, an unknown `kind`) reject with the extra reason `input_reject`: a reject, never a crash (until 2026-10-11 a
  `kind` that was a JSON array or object raised `TypeError` with no verdict; fixed, with a test).

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
Identifier equivalences the v0.5.7 manifest does not fold (a default port, an ENS name, a did:web) compare as
distinct, as the manifest says. The vector audit in `docs/vector-audit/` does
go further for the three live vectors (counter-signature recovery, OTS proof replay against two public block
explorers), as a check of the suite's data, not as part of the verifier.

## Layout

- `verify_tersign.py` — the verifier; each rule cites the manifest / specification sentence it derives from.
- `test_verify_tersign.py` — unit tests (`unittest`).
- `crypto_profile/verify_countersig.py`, `test_crypto_profile.py` — the crypto-profile runner (PR #11) and its tests.
- `positive_controls.py`, `ablation_study.py`, `run_logged.py` — the bench that can fail, and headed logs.
- `spec-0.5.7/` — the upstream v0.5.7 manifest and 162 vectors, unmodified, Apache-2.0, hash-pinned
  (`SPEC_0.5.7_SHA256SUMS`, `spec-0.5.7/NOTICE.tersign.md`).
- `spec/` — the upstream v0.5.3 manifest and 69 vectors, unmodified, Apache-2.0, hash-pinned (`SPEC_SHA256SUMS`, `spec/NOTICE.tersign.md`).
- `heldout/` — 5 separator vectors written here (not part of the upstream suite).
- `vendor/` — Roberto Locatelli's primitives with provenance (`vendor/PROVENANCE.md`).
- `results/v0.2.0/` — measured artefacts of verifier 0.2.0 (JSON + headed logs) on the three interpreters;
  `results/` (top level) — those of verifier 0.1.0.
- `docs/vector-audit/` — the vector-by-vector audit (`AUDIT_69.md`, `audit_69.json`), its scripts, captured live
  bytes and measurement files. The committed measurement files document verifier 0.1.0. Re-running the audit
  scripts rewrites them in place; with verifier 0.2.0 the timestamps, the interpreter line and the verifier line
  (sha256, version) change, and `audit_driver` adds the eight ablations of v0.5.7, none of which flips a v0.5.3 vector.
- `docs/differential/` — the deterministic variant generator, the comparison script, the recorded upstream
  output with the exact procedure that produced it, and the results.
- `DELIVERABLES_SHA256SUMS` — SHA-256 of every tracked file except itself (the upstream vectors are also
  covered by `SPEC_SHA256SUMS`, the vendored primitives by `vendor/PROVENANCE.md`).

CI (`.github/workflows/ci.yml`): Python 3.9 / 3.11 / 3.13 run the hash checks, unit tests (verifier and crypto profile), both suites, held-out, the
positive controls, the ablations, the offline audit checks and the deterministic regeneration of the 524 variants,
with no network; a separate job runs gitleaks (pinned release, default rules).

## License and attribution

Apache-2.0 (`LICENSE`, `NOTICE`). The upstream vectors are redistributed unmodified under their Apache-2.0 license
with attribution to their authors (Tersign (@wowlegend), @Rul1an, @0rkz, @mohammedmessaoudene-cmd, @navigatorbuilds).
One folder is not under Apache-2.0: `evidence-pinning-rev10-proposed/` is dedicated to the public domain under CC0 1.0
(its `NOTICE.md`), so that the proposed vectors can be copied into another corpus without a licence condition.

## Authorship

Noûs, AI agent operating under a revocable mandate from Roberto Locatelli, who reviews and is accountable.

## Members not read (added 2026-10-10, corrected 2026-10-11)

The suite's manifest does not say what a verifier does with an `input` member it does not define. This verifier keeps
the manifest's verdict (the kind functions ignore members they do not read) and REPORTS such members beside the row;
a report never changes a verdict.

The 2026-10-10 version learned the "known" members per kind from the suite it was verifying (`learn_input_members`).
A member planted in that suite's own vectors therefore became known and was never named: measured on bd0cd8c with
`x_injected_2026` planted at the top of `input`, 0/1 rows named it with one vector changed, 0/56 with 56, 0/69 with
all 69; `unknown_input_members(vec)` on a single vector named nothing unless a suite had been run before in the same
process (0/206 planted object positions in a fresh process, 69/206 after a suite run: the 69 top-level ones, none
nested); and members this verifier does not read, such as chain_set
`witness`, were never listed.

Since 2026-10-11 (input schema 1, `INPUT_SCHEMA_VERSION`) the lists are FIXED in `verify_tersign.py` and nothing is
learned at run time:

- `_INPUT_READ[kind]` — the members the kind function for `kind` reads (on some path), nested where it reads inside
  an object or an array of objects. A unit test checks it three ways: every member the functions touch on the 69
  vectors, the 5 held-out vectors and the `--mutate` mutants is in it; every path in it is touched on at least one of
  those inputs (the list is not padded); and every quoted name the functions read with `.get("x")`, `["x"]` or
  `"x" in` is a name in it (a static check of the source, which also covers branches no vector reaches).
- `_INPUT_SUITE_053_NOT_READ[kind]` — the members the 69 vectors of suite 0.5.3 carry and this verifier does not read,
  frozen on 2026-10-11 (chain_set `witness` and `attestations`, which the manifest permits without reading them;
  independence_claim `attestations[].role`, `deliverable_signer`, `payTo`; decision_evidence_binding `record.outcome`;
  phase_claim `record.amount`, `record.asset`, `record.deliverable_digest`). A unit test checks it equals what the
  0.5.3 vectors carry beyond the read list, no more and no less.

Each row of `run_suite`, and `input_member_report(vec, kind)` for a single vector, carries three lists of RFC 6901
pointers, the first two relative to `input` and the third relative to the vector (the topmost member only; members
inside `payload`, `payload_text`, `offer`, `decision_evidence` and `prefix` are content, not walked):

- `input_members_not_read` — present, not in `_INPUT_READ[kind]`;
- `unknown_input_members` — present, in neither list: not read by this verifier and not in suite 0.5.3;
- `unknown_vector_members` — top-level vector members other than `kind`, `input` and the metadata the 0.5.3 vectors
  carry (`id`, `expect`, `reason`, `description`, `provenance`).

`run_suite` uses the manifest's `kind`, the one the verdict uses. A vector whose `kind` has no list (an unknown kind)
rejects as `input_reject` with both `input` lists empty; `unknown_vector_members` does not depend on the kind and is
still filled. The text report prints the lists beside the row, each pointer as a JSON string (`json.dumps`, ASCII
escapes), so a member name cannot add a line to the report or make the print raise; `--json` writes a lone surrogate
in a member name as its `\uXXXX` escape. Measured on the fixed version (2026-10-11, Python 3.9.25 / 3.11.2 /
3.13.15): on the 69 vectors `unknown_input_members` and `unknown_vector_members` are empty on every row and
`input_members_not_read` is non-empty on 30 rows (on the 5 held-out vectors the three counts are 0, 0 and 2 rows);
a member planted at each of the 206 object positions of the 69 vectors is named in 206/206,
in a fresh process and after a suite run, with verdict, reason and detail unchanged; in `run_suite` it is named
whether one vector or all 69 carry it (`TestClosedInputMembers`, generative over every position, 13 key spellings
and 11 value types; a duplicate member is a `canonicalization_reject` with nothing reported). The 11 tests of the
class run against bd0cd8c give 4 failures and 7 errors: the two `run_suite` tests fail on the defect itself (no row
names the planted member), the single-vector test on the first planted member (bare name instead of a pointer, after
the suite run an earlier test made), the report-output test because no list is printed, the other seven on the new
fields and functions.

On the 162 vectors of v0.5.7 (verifier 0.2.0, 2026-10-12, the three interpreters): `unknown_input_members` and
`unknown_vector_members` are empty on every row, so the frozen 0.5.3 lists cover every member v0.5.7 carries (a unit
test checks it); `input_members_not_read` is non-empty on 42 rows. The lists keep their 0.5.3 names and contents.
