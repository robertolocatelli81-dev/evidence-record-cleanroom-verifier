# Proposed vectors toward -04 / rev 10: presence rule, candidate content bytes, trailing newline

Eight proposed vectors for the evidence-set step, for review toward draft-krausz-verification-state-04 and
evidence-pinning rev 10. Vectors 1–6 were requested on x402-foundation/tsc#4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6030823657). Vectors 7 and 8 are the two cases of
babyblueviper1/preaction-governance-conformance#12 (a form check written as `^…$` with Python's `re.match` accepts
one trailing `"\n"`), built as babyblueviper1 proposed on tsc#4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6034322483): one complete-object vector each, with
the root recomputed so the run reaches the form condition.

**Separate from rev 9.** Nothing here changes TKCollective/tanilo-receipt-spec `fixtures/evidence-pinning-fixtures-v2-rev9.json` (sha256
`3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724`), its bytes or its `0dffb77` pin.

**The filed -03 text is unchanged** (sha256 `1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`)
and its wording remains ambiguous on vector 1: the presence exemption in Section 5.4.1(a) names
`*_present_when_*` and `*_absent_when_*`, not `resource_sha256_present_for_full_resource`, and read literally the
general rule there would leave only `resource_sha256_not_lowercase_hex64`. Vector 1 encodes the clarification
proposed for review on tsc#4 (issuecomment-6024083056, 2026-10-06): "this condition tests non-null presence,
independently of the digest's form. With a valid content_kind: full_resource and a malformed non-null
resource_sha256, both conditions would be reported. A malformed content_kind would still suppress the dependent
check." Agreement on that clarification does not remove the ambiguity from the filed wording. Vectors 7 and 8 rest
on the filed wording as it stands (Section 5.3.2: `snippet_sha256` "not exactly 64 lowercase hexadecimal
characters"; `retrieved_at` "in UTC with the Z designator and exactly three fractional-second digits").

## The vectors

Every vector is a complete `evidence_set` (version, set-level `retrieved_at`, `source_count`, `pinned_count`,
`fully_pinned`, `evidence_root`, `sources`), so no harness step (H1–H4) is needed. Vectors 1–4 start from the
entry of `evi-resource-sha256-with-full-resource-rejects`, vectors 5–8 from the two entries of
`evi-step-resolves-affirmatively`; the digests are sha256("alpha") and sha256("beta"), as in the rev 9 generator.
The malformed `resource_sha256` is that digest in uppercase hex (64 characters; only the lowercase rule fails).
The invalid `content_kind` is `"Full_Resource"` (outside the three-value domain). Rev 9 names no vector's condition
`resource_sha256_not_lowercase_hex64` (its README lists it among the registry conditions not named); vectors 1 and 3
expect it as the second member of their sets.

| # | id | entry | expected |
|---|---|---|---|
| 1 | `evi-resource-sha256-malformed-with-full-resource-reports-both-rejects` | `full_resource`, malformed `resource_sha256` | halt; exactly {`resource_sha256_present_for_full_resource`, `resource_sha256_not_lowercase_hex64`} |
| 2 | `evi-content-kind-invalid-suppresses-full-resource-check-rejects` | invalid `content_kind`, well-formed `resource_sha256` | halt; exactly {`content_kind_absent_or_invalid_when_pinned`} |
| 3 | `evi-content-kind-invalid-resource-sha256-malformed-rejects` | invalid `content_kind`, malformed `resource_sha256` | halt; exactly {`content_kind_absent_or_invalid_when_pinned`, `resource_sha256_not_lowercase_hex64`} |
| 4 | `evi-resource-sha256-null-with-full-resource-accepted` | `full_resource`, `resource_sha256: null`, no content held | no condition; root recomputes; per-item `content_not_held`; `unknown` |
| 5 | `evi-candidate-bytes-match-resolves` | two pinned entries, bytes `alpha` and `beta` held | no condition; per-item `content_matches`, `content_matches`; `resolved` |
| 6 | `evi-candidate-bytes-one-byte-changed-unknown` | as 5, bytes for item a are `alphA` (offset 4, 0x61 → 0x41) | no condition; MUST NOT halt; per-item `content_differs`, `content_matches`; `unknown` |
| 7 | `evi-snippet-sha256-trailing-newline-rejects` | as 5, item a's `snippet_sha256` with one trailing `"\n"` (65 characters), root recomputed | halt; exactly {`snippet_sha256_not_lowercase_hex64`} |
| 8 | `evi-retrieved-at-trailing-newline-rejects` | as 5, item a's `retrieved_at` is `"2026-09-01T12:00:00.000Z\n"`, root recomputed | halt; exactly {`retrieved_at_not_canonical_form`} |

Vector 2 keeps the digest well-formed so it isolates the suppression; vector 3 is the case where both members are
malformed. With an exact comparison an out-of-domain `content_kind` never equals `full_resource`, so vector 2's
set alone does not tell suppression from "condition not met"; an implementation that folds case or drops the
`content_kind` guard fails vectors 2 and 3 (see the controls below).

Vectors 7 and 8 keep vector 5's candidate bytes and recompute the root over the members as carried (the `"\n"` is
part of the leaf preimage), so a checker that accepts the value does not stop on the root either: it reaches (d)
and ends `unknown` (vector 7: the 65-character value is not the digest of `alpha`) or `resolved` (vector 8). In
vector 8 the set-level `retrieved_at` stays `2026-09-01T12:00:00.000Z`, the bytewise-least value (a prefix sorts
first), so `set_retrieved_at_not_bytewise_least` does not apply.

The roots: vectors 1 and 4 carry `7125a9d8…40af2`, which is `root_2` of rev 9 `evi-leaf-binds-content-kind`;
vectors 5 and 6 carry `7f6addf1…4e960`, the `computed.evidence_root` of rev 9 `evi-step-resolves-affirmatively`
(the same two entries). Vectors 2 and 3 carry the root over the members as carried (`79fc919d…2869c`); it is not
reached, because (a) halts first. Vectors 7 and 8 carry the root over the members as carried (`3a91c9b6…241e5` and
`d50b4762…154f79`); a checker whose form check rejects the value halts in (a) before using it.

## Members added to the rev 9 vector format

- `expected_conditions` (array): the exact condition set, compared as a set. `condition` is kept, as in rev 9, on
  MALFORMED vectors, naming the condition the vector is about.
- `expected_token` and `expected_item_reasons` (in `sources` order) on vectors that do not halt.
- `input.verifier_holds_bytes_hex` (object, url → lowercase hex of the candidate bytes): the one new input member.
  Rev 9 carries `verifier_holds_bytes_for` with `content_matches: true` or `verifier_recomputed_sha256`, so no rev 9
  vector carries bytes. A runner decodes the hex and computes SHA-256 itself. `computed.candidate_sha256` is
  informational and must not be fed to a checker.
- `basis`: the sections each expectation rests on.

## Reported results

Measured 2026-10-07 on Python 3.9.25, 3.11.2 and 3.13.15 (output identical apart from the interpreter version in the
summary line), with `run_vectors.py` (unchanged since vectors 1–6), vector file sha256
`d33638d9704a301c0387d92c6556190667a61e65e7d4d7142d9e0fae07350573`:

- robertolocatelli81-dev/evidence-record-cleanroom-verifier `evidence-pinning-rev9/es_check_filed.py` (unchanged
  since `2bdc3ae`): 8/8.
- babyblueviper1/preaction-governance-conformance `tools/evidence_set_check.py` at `bcf6592` (the fix for #12): 8/8.
- Positive control, the same checker at `5c72428` (before the fix): 6/8; vectors 1–6 pass, vector 7 ends `unknown`
  (`content_differs`, `content_matches`) and vector 8 `resolved`, instead of halting.
- `build.py --check` rebuilds the JSON byte-identically on all three interpreters; vectors 1–6 are the same JSON
  objects as in the six-vector file (sha256 `43c3c928…fba2e`).
- Each carried root agrees with `build.py`, with both checkers' `evidence_root` (babyblueviper1's at `bcf6592`), and
  with `root()` from TKCollective/tanilo-receipt-spec `fixtures/evidence-pinning-fixture-crosscheck-rev9.mjs` at
  `0dffb77` (lines 1–185, unmodified, node v22): 8/8.
- Controls, applied to copies of both checkers, each changing exactly the predicted vectors on both: the literal
  reading of 5.4.1(a) (vector 1); a case-folding comparison of `content_kind` (2, 3); the `content_kind` guard
  removed (2, 3); the `resource_sha256` form check suppressed by an invalid `content_kind` (3); null treated as
  present (4); the byte comparison skipped (6); the `snippet_sha256` form check written as `^[0-9a-f]{64}$` with
  `re.match` (7); the `retrieved_at` form check anchored with `$` (8). An unmutated copy passes 8/8. An altered
  expected set (vector 1), an altered root and one changed candidate byte in vector 5, and the pre-fix outcome
  written as the expectation of vector 7 are each flagged.

Limits. The two checkers are not independent of the tsc#4 thread: both were aligned to the readings discussed
there, and babyblueviper1's checker reports both conditions on vector 1 since `c64b41d`, after the question was
raised. babyblueviper1's checker passes vectors 7 and 8 since `bcf6592`, after #12 was reported, and the two
vectors were built after that fix. Agreement between them is agreement between two implementations, not evidence
about the filed text.
