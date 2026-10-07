# Proposed vectors toward -04 / rev 10: presence rule and candidate content bytes

Six proposed vectors for the evidence-set step, for review toward draft-krausz-verification-state-04 and
evidence-pinning rev 10, as requested on x402-foundation/tsc#4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6030823657).

**Separate from rev 9.** Nothing here changes TKCollective/tanilo-receipt-spec `fixtures/evidence-pinning-fixtures-v2-rev9.json` (sha256
`3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724`), its bytes or its `0dffb77` pin.

**The filed -03 text is unchanged** (sha256 `1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`)
and its wording remains ambiguous on vector 1: the presence exemption in Section 5.4.1(a) names
`*_present_when_*` and `*_absent_when_*`, not `resource_sha256_present_for_full_resource`, and read literally the
general rule there would leave only `resource_sha256_not_lowercase_hex64`. Vector 1 encodes the clarification
proposed for review on tsc#4 (issuecomment-6024083056, 2026-10-06): "this condition tests non-null presence,
independently of the digest's form. With a valid content_kind: full_resource and a malformed non-null
resource_sha256, both conditions would be reported. A malformed content_kind would still suppress the dependent
check." Agreement on that clarification does not remove the ambiguity from the filed wording.

## The vectors

Every vector is a complete `evidence_set` (version, set-level `retrieved_at`, `source_count`, `pinned_count`,
`fully_pinned`, `evidence_root`, `sources`), so no harness step (H1–H4) is needed. Vectors 1–4 start from the
entry of `evi-resource-sha256-with-full-resource-rejects`, vectors 5–6 from the two entries of
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

Vector 2 keeps the digest well-formed so it isolates the suppression; vector 3 is the case where both members are
malformed. With an exact comparison an out-of-domain `content_kind` never equals `full_resource`, so vector 2's
set alone does not tell suppression from "condition not met"; an implementation that folds case or drops the
`content_kind` guard fails vectors 2 and 3 (see the controls below).

The roots: vectors 1 and 4 carry `7125a9d8…40af2`, which is `root_2` of rev 9 `evi-leaf-binds-content-kind`;
vectors 5 and 6 carry `7f6addf1…4e960`, the `computed.evidence_root` of rev 9 `evi-step-resolves-affirmatively`
(the same two entries). Vectors 2 and 3 carry the root over the members as carried (`79fc919d…2869c`); it is not
reached, because (a) halts first.

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
summary line), with `run_vectors.py`:

- robertolocatelli81-dev/evidence-record-cleanroom-verifier `2bdc3ae`, `evidence-pinning-rev9/es_check_filed.py`: 6/6.
- babyblueviper1/preaction-governance-conformance `tools/evidence_set_check.py` as of `c64b41d` (unchanged at head
  `5c72428`): 6/6.
- `build.py --check` rebuilds the JSON byte-identically on all three interpreters.
- Each carried root agrees with `build.py`, with both checkers' `evidence_root`, and with `root()` from
  TKCollective/tanilo-receipt-spec `fixtures/evidence-pinning-fixture-crosscheck-rev9.mjs` (lines 1–185, unmodified,
  node v22): 6/6.
- Controls, applied to copies of both checkers, each changing exactly the predicted vectors on both: the literal
  reading of 5.4.1(a) (vector 1); a case-folding comparison of `content_kind` (2, 3); the `content_kind` guard
  removed (2, 3); the `resource_sha256` form check suppressed by an invalid `content_kind` (3); null treated as
  present (4); the byte comparison skipped (6). An unmutated copy passes 6/6. An altered expected set, an altered
  root and one changed candidate byte in vector 5 are each flagged.

Limits. The two checkers are not independent of the tsc#4 thread: both were aligned to the readings discussed
there, and babyblueviper1's checker reports both conditions on vector 1 since `c64b41d`, after the question was
raised. Agreement between them is agreement between two implementations, not evidence about the filed text.
