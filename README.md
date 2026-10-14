# evidence-record-cleanroom-verifier

An **independent, clean-room verifier for the Tersign `evidence-record-conformance` suite** (v0.5.9, 239 vectors,
upstream tag `v0.5.9` = commit 851eb766; written first against v0.5.3, 69 vectors, upstream commit 0eda3038, and
aligned to v0.5.7, 162 vectors, tag 112b3ed6; it still runs both). Not affiliated with, endorsed by, or maintained by Tersign; "Tersign" here only names the suite this
verifier targets.

Python 3.9+ standard library only. One command:

```
python3 verify_tersign.py spec-0.5.9/      # v0.5.9, 239 vectors
python3 verify_tersign.py spec-0.5.7/      # v0.5.7, 162 vectors (byte-identical to the same 162 files in v0.5.9)
python3 verify_tersign.py spec/            # v0.5.3, 69 vectors (byte-identical to the same 69 files in v0.5.7)
```

prints a verdict (`valid` / `reject`) and a reason code for each vector and exits 0 only if every verdict, and every
reason the manifest names, matches the manifest's `expect`, and (on a manifest that has `defined_members`, v0.5.8 and
later) the manifest's `closed` lists equal the lists pinned in `verify_tersign.py`.

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

Alignment to v0.5.9 (2026-10-14, verifier 0.3.0), in a separate session given ONLY: the v0.5.9 `MANIFEST.json`, its
`LICENSE` and the 239 files in `vectors/`, fetched with a sparse checkout of those three paths at the tag `v0.5.9`
(commit 851eb766), and this repository; the upstream file list (`git ls-tree`, names only) and the commit message of
851eb766 (read through the GitHub API to identify the tag) were read too. NOT read in that session: `verify.py`,
`keccak.py`, `tools/`, `crypto/`, `.github/`, README, CONTRIBUTORS, CONTRIBUTING or SECURITY of the upstream
repository. The session did read the operator's own notes, one line of which, written by an earlier session that had
opened parts of the upstream `verify.py` for a probe on 2026-10-11 (tersignhq/evidence-record-conformance#17), names
how that file dispatches a kind to its check; no rule here was taken from it. Every rule changed for v0.5.9 cites the
manifest sentence it implements.

Limit of this claim: the session transcript proves which tools and files were used; it cannot prove what a
language model already knew. Take "clean room" as "no Tersign code was opened", not as a statement about
prior knowledge. The manifest's rule texts and the vectors' descriptions are Tersign's prose: where a rule exists
only there, the verifier follows that prose and says so.

## Measured results

Verifier 0.3.0 (2026-10-14), Python 3.9.25, 3.11.2 and 3.13.15 with identical rows; headed logs and JSON in
`results/v0.3.0/`:

| measure | value | reproduce |
|---|---|---|
| suite v0.5.9: verdicts / named reasons | **239/239**, **172/172**; manifest `defined_members.closed` = pinned lists | `python3 verify_tersign.py spec-0.5.9/` |
| suite v0.5.7: verdicts / named reasons | **162/162**, **106/106** | `python3 verify_tersign.py spec-0.5.7/` |
| suite v0.5.3: verdicts / named reasons | **69/69**, **40/40** | `python3 verify_tersign.py spec/` |
| held-out vectors (ours, 5; h5 now follows the suite's p63) | 5/5 | `python3 verify_tersign.py heldout/` |
| unit tests | 93/93 | `python3 -m unittest -v test_verify_tersign` |
| positive control: every `expect` flipped | 0/239, 0/162 and 0/69 concordant, exit 1 | `python3 verify_tersign.py spec-0.5.9/ --flip-expect` |
| positive control: mutations of the valid vectors (undefined members included) | 301/301 (v0.5.9, 67 valid vectors), 237/237 (v0.5.7), 146/146 (v0.5.3) become reject | `python3 verify_tersign.py spec-0.5.9/ --mutate` |
| positive control: the manifest's `closed` lists edited six ways (a name added / removed, a kind added / removed, a closed object removed, a non-string name) | 6/6 runs fail (exit 1, "RUN FAILS") with every verdict still right | unit test `test_pinned_lists_equal_the_manifest_and_a_difference_fails_the_run` |
| positive controls on live-ledger values, independent of `expect` | 11/11 on each directory | `python3 positive_controls.py spec-0.5.9/` |
| ablations, one rule off at a time (32 rules) | 25/32 produce discordant vectors on v0.5.9; 21/32 on v0.5.7; 14/32 on v0.5.3 | `python3 ablation_study.py spec-0.5.9/` |
| out-of-suite differential vs the upstream v0.5.3 verifier's recorded output, 524 variants | 512/524 accept/non-accept; 428/430 on the 430 variants that change `input`; 490/492 verdict+reason on non-malformed; 1 case upstream-reject / ours-valid (see below) | `docs/differential/` with `results/v0.3.0/differential_compare_py*.json` |

The seven ablations that produce no discordant vector on v0.5.9 are rules the manifest itself says no vector pins:
`no_pair_join` (as on v0.5.7), `no_head_seq_bound`, `absent_prev_rejects`, `zero_prev_as_bytes`, `claim_null_unknown`,
`empty_claim_lists_ok` and `int_digit_limit`. Each of the ten switches added for 0.3.0 is killed by the unit tests
(1 to 10 of the 93 tests fail with the switch off for the whole run; `results/v0.3.0/mutants_py311.json`).

Differential with 0.3.0 against the same v0.5.3 recording: the two disagreements on `input`-changing variants are
`mut0375` (p20 with `attestedPrefixLength` 4 on a 3-entry prefix: upstream v0.5.3 valid, ours reject, now by the
v0.5.9 rule "an integer token from 0 to the number of entries in `prefix`"; its input is the suite's n153, which
rejects) and `mut0391` (see below). Against 0.2.0 two things moved toward the recording: `mut0359` (an attestation of
0, no coverage claimed) is now valid on both sides, as v0.5.9's p63 (the same input), and `mut0038` / `mut0492` (a head
with no digest) now carry upstream's `completeness_reject`, as v0.5.9's n165 (`mut0038`'s input is n165's). No output of an upstream v0.5.7 or v0.5.9 verifier was recorded or compared.

Verifier 0.2.0 (2026-10-12) on v0.5.7, kept for reference (`results/v0.2.0/`): 162/162 and 106/106, 69/69 and 40/40,
81/81 unit tests, 114/114 and 66/66 mutations, 20/22 ablations on v0.5.7 and 13/22 on v0.5.3.

With 0.3.0, `no_position_binding` is pinned on all three suites: n25 (no `position`) used to reject also for lacking
`attestedPrefixLength`, which v0.5.9 allows to be absent (p67), so it now rejects for `position` alone; v0.5.9 adds
n168 (a position that is not the prefix's end). What follows describes 0.2.0.

The two ablations that produced no discordant vector on v0.5.7 with 0.2.0: "do not require `position`" (under our reading the
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
is lowercased, the scheme included") parses it, the attestor stays outside the parties, and 0.2.0 accepts (0.3.0 too).

Verifier 0.1.0 (2026-09-29, v0.5.3 only; `results/*.log`, `results/*.json`): the vector audit of the suite
(`docs/vector-audit/`: 58 CORRECT / 11 DOUBTFUL / 0 WRONG on the 69 vectors, live checks 34/34, OTS 13/13) was
measured with that version and is not repeated for the 170 vectors v0.5.7 and v0.5.9 added. Four v0.5.3 reasons (n4, n34, n11,
n35) are pinned only through the order of checks (`docs/vector-audit/AUDIT_69.md`).

## Changes

**0.3.0 (2026-10-14) — aligned to suite v0.5.9 (which includes v0.5.8).** On the 239 v0.5.9 vectors the 0.2.0 code
(d63e47a) gave 189/239 fully concordant (207/239 verdicts, 124/172 named reasons); 0.3.0 gives 239/239 (239/239,
172/172), and still 162/162 on v0.5.7 and 69/69 on v0.5.3. The 50 discordant vectors, by the manifest clause that
decides them:

- `defined_members` (v0.5.8, new reason `unknown_member_reject`), 46: n107-n132 and n146-n149 were accepted (30
  verdicts); n133-n145 and n150-n152 rejected with the criterion's reason (16 reasons). Implemented as a check before
  every criterion, with the lists pinned in the code and compared with the manifest's `closed` on every run;
- `boundary_binding` (v0.5.9), 2 verdicts: p63 (an attestation of 0, no coverage claimed) and p67 (no
  `attestedPrefixLength`, no coverage claimed) were rejected;
- `chain_set` order (v0.5.9), 2 reasons: n165 (no head digest) and n169 (an unparseable head digest) were
  `continuity_reject`, now `completeness_reject`, read before the records.

Also changed, each from a v0.5.9 sentence that no vector pins: a chain_set first record with no `prev_digest` member,
or with 32 zero bytes, accepts (both rejected until 0.2.0); 32 zero bytes on a later record rejects even after a record
whose artifact digest is 32 zero bytes (accepted until 0.2.0); head.seq above 100000 rejects with
`completeness_reject`; `claimed` null or `""` is silence (both failed closed until 0.2.0); an empty `parties` or
`attestations` array under a claim rejects (an empty `parties` was accepted until 0.2.0); `covered_through` without
`attestedPrefixLength` rejects, and coverage 0 over an attestation of 0 accepts; an integer token longer than 4300
digits is read as the integer it is (until 0.2.0 the file was unreadable, `input_reject`); `boundary_event` `event`,
`ruleVersion`, `fromSuite` and `toSuite` are no longer read (see the readings); the `--mutate` control adds an
undefined member at the top of `input` and inside each closed object of every valid vector, and the
coverage-beyond-attested mutant no longer assumes `attestedPrefixLength` is present (p67 made it raise). Held-out `h5`
follows the suite's p63 (see below).

Ten new ablation switches, one per rule above (32 in all); 12 new unit tests (93 in all) and 14 changed to the v0.5.9 rules; six of the new ones are
generative: every near spelling of every defined name at every closed object of every valid v0.5.9 vector (letter
case, Cyrillic confusables, fullwidth forms that NFKC folds to the name, whitespace and invisible characters at either
end, combining marks, separators) with null, empty and other values; an undefined member at every closed object of
every rejecting vector; members at every open object left unjudged; every `prev_digest` form at every record position
of sets of 1 to 4 records; 234 combinations of `attestedPrefixLength` and `covered_through` and 3,024 `claimed` values
against oracles written from the manifest text; the closed lists are read from the manifest itself in the tests,
independently of the pinned table. 11 of the 12 new tests fail on d63e47a (the twelfth checks that the 162 v0.5.7
files are byte-identical in v0.5.9). Mutants of the changed lines (`results/v0.3.0/mutants_059.py`, Python 3.11.2): the
ten switches plus 35 textual mutants (names compared case-folded, stripped or NFKC-folded; only the first array entry
checked; the member check after the criterion; the lists not compared; the profile bound, the zero-prev rule, the
`attestedPrefixLength` / `covered_through` bounds, the silence vocabulary, the 4300-digit reader, ...): 44/45 killed
by the unit tests. The survivor, "the claim holds when every remaining token is `independent`" in place of "when any
is", is equivalent while unknown tokens fail closed (the remaining tokens can then only be `independent`): 0
differences on 9,378 exhaustive `claimed` arrays of up to four tokens, as on the 3,024 of the generative test.
Four other mutants survived the first round and are now killed by added checks: head.seq 0 refused for what it is
(the completeness path gave the same reason), an empty `prefix` whose digest and position fit it, a non-object
`records` entry beside a valid one, and the `--mutate` control losing its top-level undefined member (now counted:
one per valid vector).

Review before publication (2026-10-14): the 4300-digit reader depended on the interpreter's own limit (started with
`PYTHONINTMAXSTRDIGITS=640`, a 700-digit token was `input_reject`); it now reads every integer token whatever that
limit, and the ablation `int_digit_limit` stands for CPython's default of 4300 digits. The mutant script, run as its
docstring said (`.` as the repository), symlinked the suites to themselves and counted every mutant as killed; it now
resolves the path and runs the unmutated copy first, which must pass (the 44/45 above was measured with an absolute
path and is unchanged with the corrected script). Two unit tests gained checks: the comparison with the manifest's
`closed` (lists in another order match; a `defined_members` or `closed` that is empty, null or not an object, or a kind
that is not an object, fails the run; the full report prints "RUN FAILS" too), which kills five mutants of that
comparison that the 93 tests let through, and the reader under the limits 640, none and 4300.

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
[1, 2^53-1]. Since v0.5.9 it also states the independence-claim vocabulary (absent, null, `""`, `none`,
`issuer_attested` are silence; a set drops its silence tokens), the boundary rule (`attestedPrefixLength` may be absent,
0..len(prefix) when present, 0 with no coverage claimed accepts; `covered_through` needs `attestedPrefixLength`), and
the chain_set order (head and sequence shape as completeness_reject before any record's digests; an absent
`prev_digest` is null; 32 zero bytes is null wherever it sits; head.seq bounded by 100000). They are implemented as
written and are no longer readings. What remains:

- digests: "Digests compare after the same whitespace strip, lowercased" is applied to the whole string, so a
  digest written `0X…` reads as `0x…` (no vector has one); the same holds for a chain_set `prev_digest` of 32 zero
  bytes written with padding or upper case, which is read as null like the plain spelling;
- `chain_link`: an ABSENT `prev_digest` is read as the genesis predecessor (null), as v0.5.9 states for `chain_set`
  ("both engines read a record with no prev_digest member as one whose prev_digest is null"); the chain_link text speaks
  only of the wire form;
- `chain_set`: a record whose `seq` lies outside 1..head.seq rejects with `completeness_reject` (completeness is
  "every seq 1..head.seq present exactly once"); a `link` member holding null is a presented link that does not parse
  (`continuity_reject`); a record `seq` is not bounded by 2^53-1 (the profile bound 100000 is stated for head.seq);
- boundary events: prefix digest = keccak256(JCS(prefix array)) (now the manifest's text; first calibrated here on
  p18 and independently confirmed by n29's sha3 value); `position` "must be an integer": read as an integer TOKEN
  (canonicalization: "the boundary is the token class"), so `3.0` rejects (no vector pins a position that is not an
  integer); `event`, `ruleVersion`, `fromSuite` and `toSuite` are not read: the manifest says the suite reads
  `prefixDigest`, `position` and `attestedPrefixLength`, and `boundary_event` is an open object whose other members
  "decide nothing" (0.1.0-0.2.0 rejected an unknown `event` or `ruleVersion`, a `fromSuite` other than
  keccak256-jcs, or a suite transition without a `toSuite`; no vector of any version carries one);
- member names (`defined_members`) compare as the strings the JSON text decodes to, so a name written with escapes
  (`"\u0073eq"`) is the name `seq`, and a surrogate pair written half raw is joined first, as `canonicalization`
  compares names; the manifest says "exact strings" and pins case, a Cyrillic letter, fullwidth letters and a
  trailing space (n126-n128, n149), not escapes;
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
  `payload_text`, a `claimed` token) a non-integer number token such as `1.5` is not one, as an integer is not (until
  the 2026-10-12 review it was read as its text); a `payload_text` given as `2.0` therefore rejects as "not a string
  holding JSON text" (`canonicalization_reject`, n43/n44), not as `number_domain_reject` (no vector pins this case);
- an integer token longer than 4300 digits is read as the integer it is (manifest `canonicalization`, v0.5.9),
  whatever int/str limit the interpreter was started with (`PYTHONINTMAXSTRDIGITS` or `-X int_max_str_digits`, down
  to 640, or none); a token longer than that limit is printed in a detail as its digit count, since the interpreter
  refuses to print it; a plain Python integer past the limit passed by a caller gets a verdict too;
- inputs the manifest's reason vocabulary does not cover (unreadable file, JSON nesting deeper than the parser
  allows, an unknown `kind`, an `input` that is not a JSON object, which `defined_members` places "outside the suite")
  reject with the extra reason `input_reject`: a reject, never a crash (until 2026-10-11 a `kind` that was a JSON
  array or object raised `TypeError` with no verdict; fixed, with a test).

K1–K3 were applied on 2026-09-29 after the out-of-suite differential exposed them; each is motivated by the
clause quoted in the code, has positive and negative unit tests, and a held-out vector in `heldout/`. K1 and K3 are now
the manifest's own text (v0.5.9). One held-out vector changed its expectation on 2026-10-14: `h5` (an attestation of 0
with no coverage claimed) pinned the reject of our reading of n26; its input is byte-for-byte the input of the suite's
new p63, which v0.5.9 accepts ("0 with no coverage claimed accepts"), so `h5` now expects `valid`. Two
robustness fixes from an adversarial code review of the same day (a `RecursionError` on deep nesting escaped as a
crash; a huge `head.seq` materialised a range and exhausted memory) are covered by tests too. The 69-vector result
did not change.

## Scope (honest, the same as the suite's structural profile)

Digests, canonical bytes, chain arithmetic, sequence closure, declared-claim evaluation. **Not** verified by the
verifier: secp256k1 counter-signatures over the links, the real-world identity behind an attestor address,
OpenTimestamps proofs or Bitcoin blocks (the anchor relation is checked as a SHA-256 relation only). A structurally
complete set recomputed wholesale by one forging party passes the structural predicate, here as upstream.
Identifier equivalences the v0.5.9 manifest does not fold (its `identifier_normalization` is unchanged since v0.5.7) (a default port, an ENS name, a did:web) compare as
distinct, as the manifest says. The vector audit in `docs/vector-audit/` does
go further for the three live vectors (counter-signature recovery, OTS proof replay against two public block
explorers), as a check of the suite's data, not as part of the verifier.

## Layout

- `verify_tersign.py` — the verifier; each rule cites the manifest / specification sentence it derives from.
- `test_verify_tersign.py` — unit tests (`unittest`).
- `crypto_profile/verify_countersig.py`, `test_crypto_profile.py` — the crypto-profile runner (PR #11) and its tests.
- `positive_controls.py`, `ablation_study.py`, `run_logged.py` — the bench that can fail, and headed logs.
- `spec-0.5.9/` — the upstream v0.5.9 manifest and 239 vectors, unmodified, Apache-2.0, hash-pinned
  (`SPEC_0.5.9_SHA256SUMS`, `spec-0.5.9/NOTICE.tersign.md`).
- `spec-0.5.7/` — the upstream v0.5.7 manifest and 162 vectors, unmodified, Apache-2.0, hash-pinned
  (`SPEC_0.5.7_SHA256SUMS`, `spec-0.5.7/NOTICE.tersign.md`).
- `spec/` — the upstream v0.5.3 manifest and 69 vectors, unmodified, Apache-2.0, hash-pinned (`SPEC_SHA256SUMS`, `spec/NOTICE.tersign.md`).
- `heldout/` — 5 separator vectors written here (not part of the upstream suite).
- `vendor/` — Roberto Locatelli's primitives with provenance (`vendor/PROVENANCE.md`).
- `results/v0.3.0/` — measured artefacts of verifier 0.3.0 (JSON + headed logs) on the three interpreters, and the
  mutation run of the lines changed for 0.3.0 (`mutants_py311.json`, with the script `mutants_059.py`).
- `results/v0.2.0/` — measured artefacts of verifier 0.2.0 (JSON + headed logs) on the three interpreters;
  `results/` (top level) — those of verifier 0.1.0.
- `docs/vector-audit/` — the vector-by-vector audit (`AUDIT_69.md`, `audit_69.json`), its scripts, captured live
  bytes and measurement files. The committed measurement files document verifier 0.1.0. Re-running the audit
  scripts rewrites them in place; with verifier 0.2.0 the timestamps, the interpreter line and the verifier line
  (sha256, version) change, and `audit_driver` adds the ablations added since (eight for v0.5.7, ten for v0.5.9), none of which flips a v0.5.3 vector.
- `docs/differential/` — the deterministic variant generator, the comparison script, the recorded upstream
  output with the exact procedure that produced it, and the results.
- `DELIVERABLES_SHA256SUMS` — SHA-256 of every tracked file except itself (the upstream vectors are also
  covered by `SPEC_SHA256SUMS`, the vendored primitives by `vendor/PROVENANCE.md`).

CI (`.github/workflows/ci.yml`): Python 3.9 / 3.11 / 3.13 run the hash checks, unit tests (verifier and crypto profile), the three suites, held-out, the
positive controls, the ablations, the offline audit checks and the deterministic regeneration of the 524 variants
offline; the EIP-712 and evidence-pinning steps run too, and the latter fetch a hash-pinned corpus and a pinned clone
over the network; a separate job runs gitleaks (pinned release, default rules).

## License and attribution

Apache-2.0 (`LICENSE`, `NOTICE`). The upstream vectors are redistributed unmodified under their Apache-2.0 license
with attribution to their authors (Tersign (@wowlegend), @Rul1an, @0rkz, @mohammedmessaoudene-cmd, @navigatorbuilds).
One folder is not under Apache-2.0: `evidence-pinning-rev10-proposed/` is dedicated to the public domain under CC0 1.0
(its `NOTICE.md`), so that the proposed vectors can be copied into another corpus without a licence condition.

## Acknowledgements

The v0.5.8 and v0.5.9 rules this release follows were written by Tersign (@wowlegend), who also wrote all 77 vectors
they added (manifest `author` fields). Two of them answer reports from this repository's author: `defined_members`
and n107-n117 come from tersignhq/evidence-record-conformance#17 (the manifest's `origin` fields name the probe), and
p63, n153 and n165 from the differential in #9 (p67's description names it as well). Thanks to @wowlegend for turning
both into rules and vectors. Ours are the reports, not the rules.

## Authorship

Noûs, AI agent operating under a revocable mandate from Roberto Locatelli, who reviews and is accountable.

## Members not read (added 2026-10-10, corrected 2026-10-11; verdicts since suite v0.5.8, 2026-10-14)

**Since verifier 0.3.0 a member the suite does not define is a verdict, not only a report.** Suite v0.5.8 added
`defined_members` to its manifest (from tersignhq/evidence-record-conformance#17): every kind's `input` is a closed
object, and so are chain_set / chain_commitment `head` and each object in `records`, and each object in
independence_claim `attestations`; a member those lists do not name rejects with `unknown_member_reject`, decided
before the kind's criterion. `check_defined_members` implements it with the lists pinned in `DEFINED_MEMBERS_CLOSED`;
`run_suite` compares them with the manifest's `closed` and the run fails (exit 1, "RUN FAILS") if they differ. The
objects the manifest leaves open (`payload`, `offer`, `decision_evidence`, prefix entries, `record`, `receipt`,
`settlement_result`, `boundary_event`, and the contents of chain-set `witness` / `attestations`) are not judged by name.

What follows describes the REPORT, which is kept unchanged in meaning: for each row, the members this verifier does not
read and those outside the 0.5.3 lists, whatever the verdict. Until v0.5.8 the suite's manifest did not say what a
verifier does with an `input` member it does not define; this verifier kept the manifest's verdict and reported such
members beside the row.

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

Input schema 2 (verifier 0.3.0, 2026-10-14): the boundary criterion no longer reads `boundary_event` `event`,
`ruleVersion`, `fromSuite` and `toSuite` (v0.5.9 names the three members the suite reads), so they moved from the read
list to `_INPUT_SUITE_053_NOT_READ` (the 0.5.3 vectors carry them). Measured on 0.3.0: `input_members_not_read` is
non-empty on 35/69 rows of v0.5.3, 48/162 of v0.5.7 and 117/239 of v0.5.9; `unknown_input_members` is non-empty on 0
rows of v0.5.3 and v0.5.7 and on 52 of v0.5.9 (the 46 `unknown_member_reject` vectors, and six that carry a member
the 0.5.3 vectors did not where the suite permits it: p57 and p61, chain_commitment `witness`/`attestations`; p58,
members inside chain-set `witness` and `attestations`; p59, settlement-result `payer`; p60, receipt `issuedAt`; the
first five accept, n163 rejects with `binding_reject` for its missing `offerDigest`); `unknown_vector_members` is empty
everywhere.
The member-planting tests above now also check the verdict: a member planted at a closed position rejects with
`unknown_member_reject` naming it, one planted at an open position leaves verdict, reason and detail unchanged.
