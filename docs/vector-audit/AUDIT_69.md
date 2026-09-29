# Vector-by-vector audit of the 69 vectors of Tersign `evidence-record-conformance` v0.5.3 @ 0eda3038

Performed 2026-09-29 in a separate, isolated session (system clock), by Noûs, AI agent operating under a
revocable mandate from Roberto Locatelli, who reviews and is accountable. Reviewed once by a second isolated
session; the corrections it asked for are listed at the end (0 verdicts changed). Pre-registered before any
vector was read (pre-registration text reproduced below; its SHA-256 `f814c27aa9dbc8432b7b99412637423a84470443aa91c1d7d61e1548b852bf20`).
Sources: `spec/MANIFEST.json` (sha256 `b7a1c699…7560`, 71/71 files = SPEC_SHA256SUMS), the 69 vectors, RFC 8785 and
RFC 7493 fetched the same day as raw bytes (`live/specs/`), and the **draft** x402 compliance-fields extension,
PR #2853 (**open, unmerged**; see "Deviation from the pre-registration"). NOT read: Tersign's code (verify.py,
keccak.py, tools/, TypeScript). No contact, issue, PR or comment was made.

## Pre-registration (translated; written before the review)

> For each of the 69 vectors (complete table, no sampling):
> **Q1 Justification** — does the `expect` (verdict and, where named, reason) follow from a quoted sentence of the
> manifest or of a public specification? YES / NO / AMBIGUOUS.
> **Q2 Isolation** — does a reject vector violate ONE rule (everything else valid)? Does a valid vector really exercise
> the rule of its kind? Measure: with the clean-room verifier and its ablations, which rules, switched off one at a
> time, change the vector's verdict (0 = not pinned; >1 = over-determined).
> **Q3 Live data** (p1, p5, p27 and every vector declared "live") — is the data what it declares? Verify on a public
> primary source where possible (Bitcoin block of the anchor, named endpoints); otherwise "not verifiable" and why.
> **Q4 Coverage per kind** — do valid/reject pairs differing by ONE field exist? Gaps (manifest rules with no pinning
> vector) listed.
> Outcome per vector: CORRECT / DOUBTFUL (with clause) / WRONG (with clause and measurement). Counts over 69.
> Symmetric scepticism: also say where the suite is solid. No public report without the principal's order.
> Allowed sources: MANIFEST.json and vectors/ (hash-pinned copy) and the public specifications the manifest cites.
> NOT Tersign's code: the review judges the VECTORS against the SPECIFICATION and keeps the clean room intact.

## Deviation from the pre-registration, declared: the source "S:PR2853" is an open draft by the vectors' own author

The pre-registration allowed "the public specifications the manifest cites". The file
`specs/extensions/compliance_fields.md` @ b8a81c0 is NOT cited by the manifest (the descriptions of p13 and p16 cite
it) and does NOT exist on the `main` branch of x402-foundation/x402 (contents API: 9 extensions, no
compliance_fields; 0 commits on the path). It is the head of **PR #2853, state `open`, merged `false`,
mergeable_state `unstable`, 11 commits, opened 2026-07-14, last updated 2026-09-28T15:58Z, author @wowlegend** =
"Tersign (@wowlegend)", the author of the manifest and of 55/69 vectors (measured via the GitHub API, bytes in
`live/pr2853/`, log `fetch_pr2853_run.log`). The bytes of the file are the ones cited (sha256 `aef94307…`), but their
evidential weight is that of the author's own draft, not of an independent specification.

Consequences: (a) the table codes it `S:PR2853` and column Q1 reports the source class; (b) 10/69 rows have Q1 = YES
**only** on that draft (p7, p8, p9, n6, n7, p10, p11, n15, n32, n30), all 10 CORRECT; 26/69 rows cite it at all;
(c) no verdict changes: every `expect` stays consistent with quoted sentences. **Correct public wording:** "consistent
with the draft Tersign itself proposes to x402 (PR #2853, open)". Not to be used: "conforms to the x402 specification".

## Counts (denominator 69)

| item | count |
|---|---|
| Outcome CORRECT | 58/69 |
| Outcome DOUBTFUL (with clause) | 11/69 |
| Outcome WRONG | 0/69 |
| Q1 YES / AMBIGUOUS / NO | 58 / 11 / 0 |
| Q1 YES on manifest or RFC / YES ONLY on the PR #2853 draft (deviation) | 48 / 10 |
| Q2 flipped by exactly 1 ablation (isolated) | 42/69 |
| Q2 flipped by >1 ablation (over-determined) | 21/69 |
| Q2 flipped by 0 ablations | 6/69 |
| Q3 live vectors verified: ledger data on tersign.ai (primary source), Bitcoin on TWO agreeing public explorers (mempool.space, blockstream.info; not an own node) | 3/3 (p1, p5, p27) + 4 derived (p4, n1, n3, n5) |
| Q4 opposite twin at 1 leaf | 30/69 |
| Baseline clean room / mutations | 69/69 / 66/66 |

**Summary verdict.** No `expect` is WRONG. The 11 DOUBTFUL are of three types: (a) kind `boundary_binding` without any
sentence in the manifest (p18, n25, n26, p20, n29: 5), (b) rules present only in the vector's `description` (n8, n9,
n16: 3), (c) conflict or gap between the manifest and the PR #2853 draft on the reason/rule (n31, n38, n18: 3).
Isolation: n18 does NOT isolate the phase vocabulary under every reading (equality record/presented alone rejects
it); n25 is not isolated relative to the clean-room verifier (which requires `attestedPrefixLength` unconditionally),
while with `attestedPrefixLength` optional it is isolated by `position` alone; it remains true that n25 differs from
p18 by 3 fields. 10 of the 58 CORRECT have Q1 YES only on the draft Tersign itself proposes to x402.

## Method (measured, not asserted)

- **Q1**: the `expect` is compared with sentences of the admitted texts. Codes: `M:<key>` = rule text in
  MANIFEST.json; `S:RFC8785` / `S:RFC7493` = sentence of the RFC fetched today (line numbers counted on the bytes in
  `live/specs/`); `S:PR2853` = sentence of Tersign's draft compliance-fields extension (x402 PR #2853, OPEN, author =
  author of the vectors; lines counted on `live/specs/x402_compliance_fields_b8a81c0.md`, sha256 `aef94307…`) — see the
  deviation above; `D` = the vector's `description` only; `T` = a discussion thread the description names (MCP #3004,
  the IETF web-bot-auth list), which is not a specification. Source classes in the table: YES-manifest/RFC (possibly
  +draft), YES-draft-PR2853-only, AMBIGUOUS. The layout of the harness input fields (`claimed`, `parties`, …) is a
  convention of the suite and does not weigh on Q1; the RULE does.
- **Competing reasons (criterion, stated after the review)**: a reject whose verdict is over-determined stays
  CORRECT-with-note when the order of evaluation is not written (n4, n34: gap and prev-pointer; n11, n35: digest /
  canonical bytes), and is DOUBTFUL only when the manifest explicitly NAMES a competing reason for the same input
  (n38: token 3.0 → "number_domain_reject" in the `canonicalization` sentence, while the vector pins
  completeness_reject). Measured: under `no_seq_completeness` n4/n34 become continuity_reject, n38 stays
  completeness_reject.
- **Q2**: the repository's clean-room verifier (`verify_tersign.py`, baseline 69/69) with its 14 built-in ablations +
  36 extra ablations defined in `audit_driver.py` by run-time monkeypatching (the verifier's files are not modified;
  restoration verified: baseline 69/69 after every ablation). For each vector: how many single ablations flip its
  VERDICT (0 = not pinned; 1 = isolated; >1 = over-determined) and which change only the reason. For valid vectors:
  also the positive-control mutations (`--mutate`, 66/66). Log: `audit_driver_run.log`; data `measures_q2q4.json`.
- **Q3**: read-only GETs of the endpoints named in the `provenance` blocks (raw bytes + sha256 in
  `live/FETCH_MANIFEST.json`, fetched 2026-09-29T03:11:44+00:00), the 13-step walk of p27, pure-Python secp256k1
  ecrecover (positive control: sign with an own key → recover), an OpenTimestamps parser written here (positive
  control with a hand-built proof), block headers from mempool.space AND blockstream.info (two agreeing public
  explorers; blockchain.info answered 502 at the time; no own node). Logs: `live_check_run.log`, `ots_check_run.log`;
  data `live_check.json`, `ots_check.json`. The checks re-run offline from the captured bytes (`live/`).
- **Q4**: for each vector, the opposite-verdict twin of the same kind with the minimal diff on the leaves of `input`
  (Δ = leaves changed + added + removed; top-level fields touched). Gaps = manifest rules for which a dedicated ablation
  flips 0 vectors.
- **Outcome**: WRONG = the expect contradicts a quoted sentence or does not measure what it declares; DOUBTFUL = the
  expect rests only on D/T, or the reason is not derivable, or the declared rule is not isolated (measured), or live
  data is not verifiable; CORRECT = otherwise. "note:" inside a CORRECT row is an observation that does not change it.

## Table of the 69

Legend: Q1 [source class] (basis) · Q2 (ablations that flip the verdict; mutations flipped) · Q3 · Q4 (opposite twin Δleaves [fields]) · outcome.

| # | vector | kind | expect | Q1 | Q2 | Q3 | Q4 | outcome |
|---|---|---|---|---|---|---|---|---|
| 1 | p1-live-genesis-receipt | digest_recompute | valid | **YES** [manifest/RFC] M:content_address; M:canonicalization (RFC 8785) | n=1 keccak_to_sha3; mutations 2/2 | VERIFIED: /v1/genesis = payload byte-for-byte; digest recomputed; counter-signature recovers 0x9d38… (personal_sign over the 32 link bytes); artifact anchor confirmed, block 958163 | n1 Δ1 [payload] | **CORRECT** |
| 2 | p2-canonical-key-order | canonical_bytes | valid | **YES** [manifest/RFC] M:canonicalization; S:RFC8785 §3.2.3 | n=1 insertion_order_keys; mutations 2/2 | — | n10 Δ4 [claimed_canonical, payload] | **CORRECT** |
| 3 | p3-integer-key-utf16-order | digest_recompute | valid | **YES** [manifest/RFC] M:content_address; S:RFC8785 §3.2.3 (UTF-16 code units: '1'<'10'<'2') | n=3 keccak_to_sha3, numeric_hoist_keys, insertion_order_keys; mutations 2/2 | — | n11 Δ5 [expected_digest, payload] | **CORRECT** |
| 4 | p4-chain-link-genesis | chain_link | valid | **YES** [manifest/RFC] M:chain_link (32 zero bytes for null prev, seq uint64 BE) | n=1 keccak_to_sha3; mutations 1/1 | derivation from p1 verified (live genesis digest); expected_link recomputed = live genesis link | n3 Δ1 [prev_digest] | **CORRECT** |
| 5 | p5-live-bitcoin-anchor | anchor_relation | valid | **YES** [manifest/RFC] M:anchor_relation | n=1 anchor_sha3; mutations 2/2 — pinned by anchor_sha3 (the algorithm) and by the mutations; the anchor's existence is outside the structural profile (but verified here in Q3) | VERIFIED: /v1/anchors lists subject/anchored/block 958163; proof.ots has file digest = anchored and replays the merkle root of block 958163 (mempool.space = blockstream.info; 2026-07-15T14:38:07Z) | n5 Δ1 [subject_digest] | **CORRECT** |
| 6 | p6-chain-set-complete | chain_set | valid | **YES** [manifest/RFC] M:chain_set | n=1 keccak_to_sha3; mutations 4/4 | — | n38 Δ1 [head] | **CORRECT** |
| 7 | p7-phase-consistent | phase_claim | valid | ⚠ **YES** [draft-PR2853-only] S:PR2853 L188 (only a LATER phase is forbidden; same phase = consistent) — consistent with the draft Tersign itself proposes to x402, not with a merged specification | n=0; mutations 1/1 — no ablation rejects it: exercised by the positive control (record→funding rejects) | — | n6 Δ4 [record] | **CORRECT** |
| 8 | p8-non-party-attestation | independence_claim | valid | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 (only-by-parties → not independent; here a non-party attests) — draft, as above | n=0; mutations 2/2 — exercised by the mutations (attestors-become-parties, declare-record_commits reject) | — | n14 Δ1 [attestations] | **CORRECT** |
| 9 | p9-no-independence-claim | independence_claim | valid | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 forbids treating as independent, does not require independence: silence falls under no rule — draft, as above | n=1 reject_all_party_only (an unconditional rejector) | — | n7 Δ1 [claimed] | **CORRECT** |
| 10 | n1-value-drift | digest_recompute | reject/recompute_mismatch | **YES** [manifest/RFC] M:content_address | n=1 no_digest_compare | derivation verified: = p1 with issuedAt+1 only | p1 Δ1 [payload] | **CORRECT** |
| 11 | n2-hoisted-integer-keys | canonical_bytes | reject/canonicalization_reject | **YES** [manifest/RFC] M:canonicalization; S:RFC8785 §3.2.3 | n=1 numeric_hoist_keys | — | p25 Δ5 [claimed_canonical, payload, payload_text] | **CORRECT** |
| 12 | n3-chain-link-wrong-prev | chain_link | reject/continuity_reject | **YES** [manifest/RFC] M:chain_link | n=1 no_link_compare | derivation verified: = p4 with prev_digest := artifact | p4 Δ1 [prev_digest] | **CORRECT** |
| 13 | n4-omitted-record | chain_set | reject/completeness_reject | **YES** [manifest/RFC] M:chain_set (every seq 1..head.seq present exactly once) | n=0; reason-only: no_seq_completeness (→ continuity_reject) | — | p6 Δ9 [records] | **CORRECT — note: verdict over-determined by construction (gap AND unmatched prev pointer): no single ablation makes it valid; the reason depends on the order of evaluation (completeness before prevs), which the manifest does not state** |
| 14 | n5-truncated-anchor | anchor_relation | reject/existence_reject | **YES** [manifest/RFC] M:anchor_relation | n=1 no_anchor_compare | derivation verified: anchored = p5's, subject = p6's seq-1 artifact | p5 Δ1 [subject_digest] | **CORRECT** |
| 15 | n6-phase-confusion | phase_claim | reject/phase_reject | ⚠ **YES** [draft-PR2853-only] S:PR2853 L188 (funding presented as delivery = later phase) — draft, as above | n=2 phase_any, phase_vocab_only | — | p7 Δ4 [record] | **CORRECT** |
| 16 | n7-issuer-only-independence | independence_claim | reject/independence_reject | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 — draft, as above | n=1 no_independence | — | p9 Δ1 [claimed] | **CORRECT** |
| 17 | p10-claim-set-independent | independence_claim | valid | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 (verdict); the SET form of `claimed` is a suite convention (D) — draft, as above | n=0 — exercised by the mutations | — | n9 Δ2 [claimed] | **CORRECT** |
| 18 | p11-claim-set-silence-only | independence_claim | valid | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 (as p9); set form = suite convention (D) — draft, as above | n=1 reject_all_party_only | — | n7 Δ2 [claimed] | **CORRECT** |
| 19 | n8-unrecognized-independence-claim | independence_claim | reject/independence_reject | **AMBIGUOUS** D only: "fails closed on a claim it cannot interpret" (design rule 3, issue #1); S:PR2853 L171-173 pins fail-closed for IDENTIFIERS, not for claim tokens | n=1 no_unknown_claim_reject | — | p9 Δ1 [claimed] | **DOUBTFUL — the expect is consistent by analogy with L173 but no manifest/spec sentence covers an unknown claim token; a verifier that reads 'effect_corroborated' as 'not an independence claim' conforms to every quoted sentence and accepts (measured: no_unknown_claim_reject flips it)** |
| 20 | p12-ijson-integer-boundary | digest_recompute | valid | **YES** [manifest/RFC] M:canonicalization (|n| <= 2^53-1); S:RFC7493 §2.2 L148-150 | n=2 keccak_to_sha3, strict_below_2_53; mutations 2/2 | — | n11 Δ2 [expected_digest, payload] | **CORRECT** |
| 21 | p13-decimal-string-beside-integer | digest_recompute | valid | **YES** [manifest/RFC+draft] M:content_address; S:PR2853 L196-212 (Numbers) | n=2 keccak_to_sha3, insertion_order_keys; mutations 2/2 | — | n11 Δ4 [expected_digest, payload] | **CORRECT** |
| 22 | n10-float-in-digest-domain | canonical_bytes | reject/number_domain_reject | **YES** [manifest/RFC+draft] M:canonicalization (number_domain_reject); S:PR2853 L198 | n=1 no_number_domain | — | p25 Δ3 [claimed_canonical, payload, payload_text] | **CORRECT** |
| 23 | n11-integer-beyond-ijson-range | digest_recompute | reject/number_domain_reject | **YES** [manifest/RFC] M:canonicalization (|n| <= 2^53-1); S:RFC7493 L148-150 | n=0; reason-only: no_number_domain, accept_2_53 | — | p12 Δ2 [expected_digest, payload] | **CORRECT — note: expected_digest = 32 zero bytes ⇒ the VERDICT is over-determined (an engine without a number domain still rejects with recompute_mismatch); the reason isolates the rule (measured: both ablations change only the reason)** |
| 24 | p14-supplementary-plane-key-order | digest_recompute | valid | **YES** [manifest/RFC] S:RFC8785 §3.2.3 (0xD800 < 0xFF61) | n=3 keccak_to_sha3, codepoint_key_order, insertion_order_keys; mutations 2/2 | — | n11 Δ4 [expected_digest, payload] | **CORRECT** |
| 25 | n12-codepoint-key-order | canonical_bytes | reject/canonicalization_reject | **YES** [manifest/RFC] S:RFC8785 §3.2.3 | n=2 codepoint_key_order, insertion_order_keys | — | p25 Δ4 [claimed_canonical, payload, payload_text] | **CORRECT** |
| 26 | n13-party-alias-whitespace | independence_claim | reject/independence_reject | **YES** [manifest/RFC+draft] M:identifier_normalization (strip+lowercase); S:PR2853 L169-171 | n=2 no_independence, no_identity_normalization (root rule + the specific one) | — | p8 Δ2 [attestations] | **CORRECT** |
| 27 | n14-unparseable-attestor | independence_claim | reject/independence_reject | **YES** [manifest/RFC+draft] M:identifier_normalization (fail closed); S:PR2853 L171-173 | n=1 no_identity_normalization | — | p8 Δ1 [attestations] | **CORRECT** |
| 28 | n15-claim-without-attestations | independence_claim | reject/independence_reject | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157: without attestations no non-party attests ⇒ not independent — draft, as above | n=0 | — | p21 Δ3 [attestations, parties] | **CORRECT — note: pins only "return a verdict instead of KeyError": an engine reading the absence as an empty list rejects anyway (measured: attestations_default_empty 0 flips)** |
| 29 | n16-attestation-not-an-object | independence_claim | reject/independence_reject | **AMBIGUOUS** D only: the SHAPE of an attestation (object with `by`) is defined by no manifest/spec sentence | n=1 attestation_string_as_by | — | p21 Δ4 [attestations, parties] | **DOUBTFUL — an engine reading the bare string as the attestor's identifier finds a non-party (0x9d38…) and ACCEPTS while conforming to every quoted sentence (measured: attestation_string_as_by flips it)** |
| 30 | n17-renumbered-omission | chain_set | reject/continuity_reject | **YES** [manifest/RFC] M:chain_set ("where a record presents a link, it must recompute") | n=1 no_link_recompute | — | p6 Δ7 [head, records] | **CORRECT** |
| 31 | n18-unrecognized-phase | phase_claim | reject/phase_reject | **AMBIGUOUS** S:PR2853 L183-188 lists the phases but declares no CLOSED vocabulary; "must not verify as ANY phase" is D | n=1 phase_any | — | p7 Δ4 [record] | **DOUBTFUL — does NOT isolate the vocabulary rule: presented_as='delivery' ≠ 'settled_and_delivered', so equality alone rejects (measured: phase_equality_only 0 flips; only phase_any flips it). Pinning the vocabulary would need presented_as = the same unknown token** |
| 32 | p16-independence-scope-committed | independence_claim | valid | **YES** [manifest/RFC+draft] M:commitment_derivation; S:PR2853 L162-163 | n=1 derive_nothing; mutations 3/3 | — | n20 Δ2 [covers] | **CORRECT** |
| 33 | n20-independence-scope-uncommitted | independence_claim | reject/independence_reject | **YES** [manifest/RFC+draft] M:commitment_derivation; S:PR2853 L162-163 | n=1 covers_not_checked | — | p16 Δ2 [covers] | **CORRECT** |
| 34 | p17-independence-scope-derived-settlement | independence_claim | valid | **YES** [manifest/RFC] M:commitment_derivation | n=1 derive_nothing; mutations 3/3 | — | n21 Δ1 [settlement_result] | **CORRECT** |
| 35 | n21-independence-scope-empty-settlement | independence_claim | reject/independence_reject | **YES** [manifest/RFC] M:commitment_derivation (transaction non-empty string) | n=2 covers_not_checked (scope), settlement_any_string (the specific derivation) | — | p17 Δ1 [settlement_result] | **CORRECT** |
| 36 | n22-independence-scope-declared-override | independence_claim | reject/independence_reject | **YES** [manifest/RFC] M:commitment_derivation ("never a declared list (n22-n24)") | n=1 declared_commits | — | p17 Δ2 [record_commits, settlement_result] | **CORRECT — note: over-determined by declared construction (n21 + record_commits): without the presence rule it still rejects for overreach (measured: no_record_commits_presence does not flip it; declared_commits does)** |
| 37 | n23-independence-scope-null-declared | independence_claim | reject/independence_reject | **YES** [manifest/RFC] M:commitment_derivation | n=2 no_record_commits_presence, declared_commits (two ablations of the same presence rule) | — | p17 Δ1 [record_commits] | **CORRECT** |
| 38 | n24-independence-scope-declared-no-scope | independence_claim | reject/independence_reject | **YES** [manifest/RFC] M:commitment_derivation | n=2 no_record_commits_presence, declared_commits | — | p8 Δ1 [record_commits] | **CORRECT** |
| 39 | p22-delivery-commitment-recomputed | independence_claim | valid | **YES** [manifest/RFC] M:commitment_derivation (delivery = keccak(bytes)==digest); silence as p9 | n=1 reject_all_party_only | TRACEABLE, not byte-verifiable: public repo 0rkz/foreseal-x402-conformance (Apache-2.0); signer 0x6704…, payTo 0xffff…, payer 0xE87c…, ts 1784840974 present in the repo's fixtures; the exact deliverable_bytes/digest do NOT appear on today's main (its live-receipt.json is a different capture: ts 1787188931, score 80); the digest recomputes from the presented bytes (measured) | n32 Δ2 [claimed, covers] | **CORRECT** |
| 40 | n32-delivery-self-attested | independence_claim | reject/independence_reject | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 — draft, as above | n=1 no_independence | as p22 (same bytes) | p22 Δ2 [claimed, covers] | **CORRECT** |
| 41 | p23-delivery-independence-within-commitment | independence_claim | valid | **YES** [manifest/RFC+draft] M:commitment_derivation; S:PR2853 L162-163 | n=2 keccak_to_sha3, derive_nothing; mutations 4/4 | as p22 (same bytes; the added attestor is the live ledger signer 0x9d38…) | n33 Δ1 [deliverable_bytes] | **CORRECT** |
| 42 | n33-delivery-substitution-scope-overreach | independence_claim | reject/independence_reject | **YES** [manifest/RFC+draft] M:commitment_derivation; S:PR2853 L162-163 | n=2 covers_not_checked, trust_declared_delivery_digest (the specific one) | as p22 with verdict ALLOW→DENY (measured diff: 1 leaf) | p23 Δ1 [deliverable_bytes] | **CORRECT** |
| 43 | p24-witnessed-complete-set | chain_set | valid | **YES** [manifest/RFC+draft] M:witnessed_inclusion; S:PR2853 L115 | n=1 keccak_to_sha3; mutations 4/4 | — | n34 Δ8 [records] | **CORRECT** |
| 44 | n34-witnessed-inclusion-not-completeness | chain_set | reject/completeness_reject | **YES** [manifest/RFC+draft] M:witnessed_inclusion; S:PR2853 L115 | n=1 witness_counts_as_presence; reason-only: no_seq_completeness | — | p24 Δ8 [records] | **CORRECT — note: as n4, verdict over-determined (gap + prev); specifically pinned by witness_counts_as_presence** |
| 45 | p18-boundary-binds-prefix-and-position | boundary_binding | valid | **AMBIGUOUS** no `boundary_binding` rule in the MANIFEST (absent from the `profile` too); T:MCP #3004 + D. The prefixDigest IS derivable from the natural reading of D ("the canonical digest of the prefix") + M:content_address applied to the prefix array: keccak256(JCS(prefix)) = 0x359d14… at the first attempt, sha3_256 = n29's digest (re-measured: remeasure_p18_n25_run.log) | n=1 keccak_to_sha3; mutations 3/3 | — | n26 Δ1 [boundary_event] | **DOUBTFUL — kind with no manifest/spec sentence (position, attestedPrefixLength, covered_through and their constraint have no written rule); the digest, by contrast, is derivable** |
| 46 | n25-boundary-prefix-only-no-position | boundary_binding | reject/boundary_reject | **AMBIGUOUS** as p18 (T + D) | n=1 no_position_apl_optional | — | p18 Δ3 [boundary_event, covered_through] | **DOUBTFUL — differs from p18 by 3 fields (position, attestedPrefixLength, covered_through). Isolation is RELATIVE to the verifier: for the clean-room verifier, which requires attestedPrefixLength unconditionally, the absence of `position` alone does not flip it (no_position_binding 0; no_position_apl_optional needed); for a verifier that does not require attestedPrefixLength when no coverage is claimed, n25 rejects on "binds no position" and is isolated by position alone (re-measured: apl_optional_only 0 flips)** |
| 47 | n26-coverage-claimed-over-empty-attestation | boundary_binding | reject/boundary_reject | **AMBIGUOUS** as p18 (T + D) | n=1 no_coverage_bound | — | p18 Δ1 [boundary_event] | **DOUBTFUL — kind with no manifest rule; otherwise well isolated (1 field, 1 ablation)** |
| 48 | p19-authority-reduction-bound | decision_evidence_binding | valid | **YES** [manifest/RFC] M:decision_evidence_binding | n=2 keccak_to_sha3, insertion_order_keys; mutations 1/1 | — | n28 Δ6 [decision_evidence] | **CORRECT** |
| 49 | n27-authority-reduction-unbound | decision_evidence_binding | reject/binding_reject | **YES** [manifest/RFC] M:decision_evidence_binding (missing) | n=1 no_decision_presence | — | p19 Δ7 [decision_evidence, record] — differs from p19 also in the evidence object: only the missing digest counts (measured: no_decision_presence flips it) | **CORRECT** |
| 50 | n28-authority-reduction-substitution | decision_evidence_binding | reject/binding_reject | **YES** [manifest/RFC] M:decision_evidence_binding (mismatch) | n=1 no_decision_compare | — | p19 Δ6 [decision_evidence] — 6 leaves changed (declared: host limit, delta, policy version) | **CORRECT** |
| 51 | p20-suite-transition-preserves-prefix | boundary_binding | valid | **AMBIGUOUS** as p18: T (IETF web-bot-auth list) + D; `fromSuite`/`toSuite` defined by no sentence | n=2 keccak_to_sha3, redigest_under_toSuite; mutations 3/3 | — | n29 Δ1 [boundary_event] | **DOUBTFUL — kind with no manifest rule; the p20/n29 pair is well isolated (1 field)** |
| 52 | n29-suite-transition-redigests-prefix | boundary_binding | reject/boundary_reject | **AMBIGUOUS** as p20 | n=2 keccak_to_sha3, redigest_under_toSuite | — | p20 Δ1 [boundary_event] | **DOUBTFUL — kind with no manifest rule; genuinely discriminating (keccak_to_sha3 makes it valid, as its description declares)** |
| 53 | p21-independence-urn-identities | independence_claim | valid | **YES** [manifest/RFC+draft] M:identifier_normalization (two identity syntaxes); S:PR2853 L157 | n=1 addr_only_identity; mutations 2/2 | — | n30 Δ1 [attestations] | **CORRECT** |
| 54 | n30-independence-urn-self-attested | independence_claim | reject/independence_reject | ⚠ **YES** [draft-PR2853-only] S:PR2853 L157 — draft, as above | n=1 no_independence | — | p21 Δ1 [attestations] | **CORRECT** |
| 55 | n31-independence-urn-alias-trailing-slash | independence_claim | reject/independence_reject | **AMBIGUOUS** S:PR2853 L169-171 (trailing punctuation `/` `.` `#` is that party) ⇒ reject; BUT M:identifier_normalization says "compare after strip, case-significant" without any punctuation fold, and on CASE contradicts the draft (case-significant vs letter case folds) | n=3 no_independence, no_identity_normalization, no_trailing_punct_fold | — | p21 Δ1 [attestations] | **DOUBTFUL — manifest and PR #2853 draft (same author) diverge: a verifier following only the manifest sentence ACCEPTS n31 (measured: no_trailing_punct_fold flips it); no vector separates the case fold (measured: case_fold_scheme_ids 0 flips)** |
| 56 | p15-offer-binding | offer_binding | valid | **YES** [manifest/RFC] M:offer_binding | n=2 keccak_to_sha3, insertion_order_keys; mutations 1/1 | — | n19 Δ2 [offer] | **CORRECT** |
| 57 | n19-offer-substitution | offer_binding | reject/binding_reject | **YES** [manifest/RFC] M:offer_binding | n=1 no_offer_compare | — | p15 Δ2 [offer] — 2 fields (amount, payTo), declared | **CORRECT** |
| 58 | n9-unrecognized-member-in-claim-set | independence_claim | reject/independence_reject | **AMBIGUOUS** as n8 (D only) | n=1 no_unknown_claim_reject | — | p10 Δ2 [claimed] | **DOUBTFUL — as n8; the non-party attestor makes the vector discriminating only for the uncited rule** |
| 59 | p25-integer-token-in-text | canonical_bytes | valid | **YES** [manifest/RFC] M:canonicalization (p25/n35 named) | n=1 reject_payload_text; mutations 1/1 | — | n35 Δ1 [payload_text] | **CORRECT** |
| 60 | n35-integer-valued-float-token | canonical_bytes | reject/number_domain_reject | **YES** [manifest/RFC+draft] M:canonicalization ("2.0 … rejects even when integer-valued"); S:PR2853 L198 | n=1 json_parse_collapses_integral_floats; reason-only: no_number_domain, reject_payload_text | — | p25 Δ1 [payload_text] | **CORRECT — note: verdict over-determined (without a number domain the canonical bytes '2.0'≠'2' reject anyway); the reason isolates; the measured flip is json_parse_collapses_integral_floats** |
| 61 | p26-chain-commitment-complete | chain_commitment | valid | **YES** [manifest/RFC] M:chain_commitment | n=2 keccak_to_sha3, acc_last_link_only; mutations 5/5 | — | n37 Δ1 [head] | **CORRECT** |
| 62 | p27-live-chain-commitment-genesis-chain | chain_commitment | valid | **YES** [manifest/RFC] M:chain_commitment | n=2 keccak_to_sha3, acc_last_link_only; mutations 5/5 | VERIFIED: 13/13 (seq, digest, prev) = live /verify walk; acc recomputed = commitment.acc; 13/13 counter-signatures → 0x9d38…; subjectDigest/anchoredDigest recomputed; proof.ots replays the merkle root of block 964428 (2026-08-28T11:40:11Z) | n36 Δ41 [head, records] | **CORRECT** |
| 63 | n36-chain-commitment-prefix-substituted | chain_commitment | reject/continuity_reject | **YES** [manifest/RFC] M:chain_commitment ("a prefix … not the one the commitment was built over rejects here") | n=1 no_accumulator | — | p26 Δ4 [records] | **CORRECT** |
| 64 | n37-chain-commitment-last-link-only | chain_commitment | reject/continuity_reject | **YES** [manifest/RFC] M:chain_commitment | n=2 no_accumulator, acc_last_link_only (the second is exactly the declared class) | — | p26 Δ1 [head] | **CORRECT** |
| 65 | n38-chain-set-float-seq-token | chain_set | reject/completeness_reject | **AMBIGUOUS** verdict YES (M:chain_set requires integer seq); REASON: M:canonicalization assigns number_domain_reject to non-integer tokens, the vector pins completeness_reject | n=1 json_parse_collapses_integral_floats | — | p6 Δ1 [head] | **DOUBTFUL — reason not derivable from a quoted sentence: a manifest-conformant engine may emit number_domain_reject for the same token 3.0 (the p25/n35 pair pins it so in the canonical-bytes domain)** |
| 66 | p28-issuer-sequence-distinct-seq | chain_set | valid | **YES** [manifest/RFC+draft] M:duplicate_sequence; S:PR2853 L111 | n=1 keccak_to_sha3; mutations 4/4 | — | n39 Δ10 [head, records] | **CORRECT** |
| 67 | n39-issuer-sequence-duplicate-seq | chain_set | reject/completeness_reject | **YES** [manifest/RFC] M:chain_set ("a second record at an occupied seq rejects: n39") | n=1 no_seq_completeness | — | p28 Δ10 [head, records] | **CORRECT** |
| 68 | p29-committed-prefix-one-record-per-position | chain_commitment | valid | **YES** [manifest/RFC] M:chain_commitment; M:duplicate_sequence (p29/n40) | n=2 keccak_to_sha3, acc_last_link_only; mutations 5/5 | — | n40 Δ4 [records] | **CORRECT** |
| 69 | n40-equivocating-record-at-committed-position | chain_commitment | reject/continuity_reject | **YES** [manifest/RFC] M:chain_commitment; M:duplicate_sequence | n=1 no_accumulator | — | p29 Δ4 [records] | **CORRECT** |

## Q3 — live data: measurements (re-run offline from the captured bytes; `live_check_run.log`, `ots_check_run.log`)

All 34 checks of `live_check.py` and all 13 of `ots_check.py` PASS. Highlights:
p1: the live `/v1/genesis` artifact equals the vector payload byte-for-byte; keccak256(canonical) = expected digest;
the counter-signature recovers the declared ledger signer (personal_sign over the 32 raw link bytes — the hex
encodings do not recover it); `/verify` reports chainOk and a confirmed anchor in block 958163.
p5: the subject digest is listed in `/v1/anchors` with the declared anchored digest and block; anchored =
sha256(subject); the .ots proof's file digest is the anchored digest and its ops replay to the merkle root of
block 958163, identical on mempool.space and blockstream.info (2026-07-15T14:38:07Z).
p27: the 13-step walk through `/verify` matches every (seq, artifact, prev); the accumulator folded over the live
walk equals the live commitment `acc` and the vector's `head.acc`; 13/13 counter-signatures recover the ledger
signer; keccak256(JCS(commitment)) = subjectDigest = the vector's commitment_digest; sha256 of it = anchored;
the anchor row's merkle path replays with sha256 nodes to the batch root (keccak = negative control); the .ots proof
replays to the merkle root of block 964428 (2026-08-28T11:40:11Z) on both explorers; the anchor's ledgerSignature
recovers the signer under the `tersign-anchor-v1:` + batchRoot encoding.
n1 = p1 with issuedAt + 1 only; n3 = p4 with prev := artifact only.
Notes: (1) the ledger counter-signature is personal_sign over the 32 RAW link bytes; (2) for p27 the batchRoot is
sha256(left||right) with the anchored digest as leaf, and appears among the intermediate messages of the OTS proof
(the batch tree is embedded in the proof); (3) the genesis artifact (p1) has an anchor of its own, also in block
958163; (4) PayPerByte fixture (p22/n32/p23/n33): traceable, not byte-verifiable (see row 39).

## Q4 — gaps: rules with no pinning vector (measure = dedicated ablation with 0 flips)

| kind | rule | measure |
|---|---|---|
| offer_binding | "a receipt that commits to no offer digest … fails closed" (M:offer_binding) | no_offer_presence: 0 flips |
| chain_set | "head.digest equals the final record's artifact digest" (M:chain_set) — no reject vector | no_head_digest_binding: 0 |
| chain_set | "genesis prev = null" (M:chain_set) — no reject vector | no_genesis_null_prev: 0 |
| chain_set | prev continuity as a rule of its own (wrong prev only, complete sequence) | no_prev_continuity: 0 (n4/n34 conflate it with the gap) |
| canonicalization | "duplicate object names rejected" (M:canonicalization) | no vector with duplicate names (all 69 load under a strict object_pairs_hook) |
| boundary_binding | the `position` constraint alone | no_position_binding: 0 (n25 needs 3 absences) |
| boundary_binding | event / ruleVersion / fromSuite vocabulary | no_boundary_vocab: 0 |
| phase_claim | phase vocabulary alone (n18 over-determined); an EARLIER phase presented (the draft forbids only "later phase") | phase_equality_only: 0; phase_later_only: 0 |
| identifier_normalization | case fold of scheme identifiers (manifest: case-significant; draft L170: letter case folds) | case_fold_scheme_ids: 0 |
| number domain | negative bound −(2^53−1) / −2^53; NaN/Infinity (RFC 8785 L297) | no vector |
| identifier_normalization | percent-encoding (declared open in n31) | no vector, declared |

## Where the suite is solid (symmetric scepticism)

- digest/canonical: 13/13 vectors with Q1 YES on sentences of RFC 8785/7493 and of the manifest (sources independent of
  the author); 1-field pairs (p1/n1, p25/n35, p12/n11 Δ2 = value+digest); UTF-16 vs code point pinned (p14/n12);
  numeric hoisting (p3/n2).
- chain: p4/n3, p6/n38, p26/n37, p29/n40 differ by 1 field; n17 and n36/n37/n40 isolated by ONE ablation each; witnessed
  inclusion pinned (n34 flipped only by witness_counts_as_presence).
- independence/scope: n20, n21, n33, n22-n24, p16/p17/p23 all pinned by specific ablations AND by the manifest's
  `commitment_derivation` sentence; the derivation (empty tx, digest not recomputed, derive_nothing) has one vector per
  branch. The root rule (party-only ≠ independent) is, by contrast, written only in the PR #2853 draft.
- positive controls: 66/66 mutations of the valid vectors reject; keccak→sha3 flips 18 vectors and n29 in the expected
  direction (valid), as its description declares.
- live data: p1, p5, p27 verified down to the Bitcoin block on two independent explorers, with counter-signatures
  recovered and OTS proofs replayed by a parser written here (positive control of the parser included).

## Ablations: rule → flipped vectors (`measures_q2q4.json`)

| ablation | origin | description | flipped | reason-only |
|---|---|---|---|---|
| keccak_to_sha3 | builtin | content address / links / delivery digest computed with SHA3-256 instead of Keccak-256 | 18: p1, p3, p4, p6, p12, p13, p14, p23, p24, p18, p19, p20, n29, p15, p26, p27, p28, p29 | — |
| codepoint_key_order | builtin | JCS keys sorted by Unicode code point instead of UTF-16 code units | 2: p14, n12 | — |
| no_number_domain | builtin | non-integer number tokens and integers beyond 2^53-1 serialized instead of rejected | 1: n10 | n11, n35 |
| no_seq_completeness | builtin | chain_set skips the every-seq-exactly-once check | 1: n39 | n4, n34 |
| no_link_recompute | builtin | chain_set does not recompute a presented `link` | 1: n17 | — |
| no_accumulator | builtin | chain_commitment does not compare head.acc with the fold | 3: n36, n37, n40 | — |
| no_independence | builtin | independence_claim does not require a non-party attestor | 5: n7, n13, n32, n30, n31 | — |
| no_identity_normalization | builtin | identities compared byte-exact | 3: n13, n14, n31 | — |
| no_record_commits_presence | builtin | a declared `record_commits` field is ignored | 2: n23, n24 | — |
| declared_commits | builtin | commitments read from a declared list when present | 3: n22, n23, n24 | — |
| no_position_binding | builtin | boundary_binding does not require `position` | 0 | — |
| no_coverage_bound | builtin | boundary_binding does not compare covered_through with attestedPrefixLength | 1: n26 | — |
| phase_any | builtin | phase_claim accepts any phase token | 2: n6, n18 | — |
| no_unknown_claim_reject | builtin | unknown independence claim tokens ignored | 2: n8, n9 | — |
| no_digest_compare | extra | digest_recompute: expected_digest parsed but never compared | 1: n1 | — |
| numeric_hoist_keys | extra | JCS: integer-like keys sorted numerically first | 2: p3, n2 | — |
| insertion_order_keys | extra | JCS: keys emitted in insertion order | 7: p2, p3, p13, p14, n12, p19, p15 | — |
| strict_below_2_53 | extra | number domain: |n| <= 2^53-2 | 1: p12 | — |
| accept_2_53 | extra | number domain: |n| <= 2^53 | 0 | n11 |
| reject_payload_text | extra | canonical_bytes: the raw-text pathway rejects unconditionally | 1: p25 | n35 |
| json_parse_collapses_integral_floats | extra | loader: integer-valued float tokens collapse to int | 2: n35, n38 | — |
| no_link_compare | extra | chain_link: expected_link never compared | 1: n3 | — |
| no_anchor_compare | extra | anchor_relation: never compared | 1: n5 | — |
| anchor_sha3 | extra | anchor_relation: SHA3-256 instead of SHA-256 | 1: p5 | — |
| no_prev_continuity | extra | chain_set: prev_digest not compared | 0 | — |
| no_head_digest_binding | extra | chain_set: head.digest not compared | 0 | — |
| no_genesis_null_prev | extra | chain_set: genesis may carry a non-null prev | 0 | — |
| witness_counts_as_presence | extra | chain_set: a witnessed inclusion counts as a present record | 1: n34 | — |
| acc_last_link_only | extra | chain_commitment: fold over the last link only | 4: p26, p27, n37, p29 | — |
| phase_vocab_only | extra | phase_claim: vocabulary checked, equality not | 1: n6 | — |
| phase_equality_only | extra | phase_claim: equality checked, vocabulary not | 0 | — |
| phase_later_only | extra | phase_claim: reject only a LATER presented phase | 0 | — |
| reject_all_party_only | extra | independence: unconditional rejector of party-only records | 3: p9, p11, p22 | — |
| attestations_default_empty | extra | independence: missing `attestations` read as empty list | 0 | — |
| attestation_string_as_by | extra | independence: bare-string attestation read as {by: string} | 1: n16 | — |
| covers_not_checked | extra | independence: `covers` ignored | 3: n20, n21, n33 | — |
| settlement_any_string | extra | derivation: settlement committed with ANY transaction string | 1: n21 | — |
| trust_declared_delivery_digest | extra | derivation: delivery digest trusted, bytes not recomputed | 1: n33 | — |
| derive_nothing | extra | derivation: commitments always empty | 3: p16, p17, p23 | — |
| addr_only_identity | extra | identity: only 0x-addresses parse | 1: p21 | — |
| no_trailing_punct_fold | extra | identity: no trailing `/ . #` fold | 1: n31 | — |
| case_fold_scheme_ids | extra | identity: scheme paths compared case-insensitively | 0 | — |
| no_offer_compare | extra | offer_binding: digest not compared | 1: n19 | — |
| no_offer_presence | extra | offer_binding: receipt without offerDigest accepted | 0 | — |
| no_decision_presence | extra | decision_evidence_binding: record without digest accepted | 1: n27 | — |
| no_decision_compare | extra | decision_evidence_binding: digest not compared | 1: n28 | — |
| redigest_under_toSuite | extra | boundary: prefixDigest recomputed under the successor suite | 2: p20, n29 | — |
| no_boundary_vocab | extra | boundary: any event / ruleVersion / fromSuite accepted | 0 | — |
| no_position_apl_optional | extra | boundary: position not required AND attestedPrefixLength optional | 1: n25 | — |
| apl_optional_only | extra | boundary: attestedPrefixLength optional (position still required) | 0 | — |

## Corrections applied after the independent review (0 verdicts changed)

| point | correction | measure |
|---|---|---|
| 1 | provenance of the x402 extension source declared (PR #2853 open, author = author of the vectors); rows YES only on it counted and marked | `fetch_pr2853_run.log` |
| 2 | p18 clause rewritten: prefixDigest derivable (keccak256(JCS(prefix)) = 0x359d14…, sha3 = n29) | `remeasure_p18_n25_run.log` |
| 3 | n25: non-isolation relative to the clean-room verifier; with attestedPrefixLength optional it is isolated by position alone; n18 does not isolate under every reading | `remeasure_p18_n25_run.log`; `audit_driver_run.log` (apl_optional_only 0, no_position_apl_optional 1) |
| 4 | RFC 7493 citation: in the bytes of `live/specs/rfc7493.txt` the 2^53 sentence is at L148-150 | `remeasure_p18_n25_run.log` |
| 5 | n38 DOUBTFUL vs n4/n34 CORRECT criterion written into the Method (competing reason NAMED by the manifest) | `audit_driver_run.log` |
| 6 | Bitcoin: "two agreeing public explorers", not "primary source"; blockchain.info answered 502 (third explorer not measured) | `fetch_pr2853_run.log` (local capture, not re-run) |

## What was NOT done / limits

- No public report, no contact (pre-registration order). HTTP requests were read-only GETs on public endpoints named by
  the vectors and on explorer / GitHub APIs (the fetch scripts are included; the checks run offline from `live/`).
- The Bitcoin verification uses block headers from two public explorers, not an own node: the merkle root replayed
  from the OTS proof matches on both; an own node would be the definitive primary source.
- The source S:PR2853 is an open draft by the vectors' author (see the deviation): every public sentence naming it must
  say "the draft Tersign itself proposes to x402".
- The OTS parser and ecrecover are own implementations with positive controls, not the official libraries.
- The ablations measure isolation relative to this repository's verifier: another conformant implementation may
  evaluate in a different order (relevant for n4, n34, n38, n11, n35: robust verdict, order-dependent reason).
- The audit was performed against the verifier as it was on 2026-09-29 before the robustness fixes (RecursionError /
  huge head.seq); the measurement files in this folder were regenerated with the fixed verifier and are identical.

Re-running `audit_driver.py`, `live_check.py`, `ots_check.py` or `build_audit_json.py` rewrites their measurement
files in place (`measures_q2q4.json`, `audit_driver.log`, `live_check.json`, `ots_check.json`, `audit_69.json`); only the
timestamps and the interpreter line change, so the SHA-256 of those files in `DELIVERABLES_SHA256SUMS` will differ after
a re-run while every measured value stays the same.

Files here: `audit_69.json` (this table, machine-readable; built and cross-checked against the measurements by
`build_audit_json.py`), `measures_q2q4.json`, `live_check.json`, `ots_check.json`, headed logs `*_run.log`, `live/` (raw
bytes with `FETCH_MANIFEST.json`), scripts `audit_driver.py`, `live_check.py`, `ots_check.py`, `remeasure_p18_n25.py`,
`probe_merkle.py`, `fetch_live.py`, `fetch_specs.py`, `fetch_pr2853.py`. Not redistributed: the files fetched from the
third-party repository 0rkz/foreseal-x402-conformance for row 39 (only the repository metadata `live/gh_0rkz_repo.json`
is kept) and the GitHub commit object of b8a81c0 (it carries personal e-mail fields; `live/pr2853/pull_2853.json` and the
contents listing are kept).
