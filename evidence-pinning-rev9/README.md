# evidence-pinning rev 9: a second implementation of the -03 evidence-set step

A checker for the evidence-set step of `draft-krausz-verification-state-03` (Sections 5.3 and 5.4.1), run on the
47 vectors of TKCollective/tanilo-receipt-spec `fixtures/evidence-pinning-fixtures-v2-rev9.json` (corpus at
`0dffb77`, sha256 `3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724`), for the x402 evidence-record
discussion in x402-foundation/tsc#4. Python 3.9+ standard library only.

## What was read, in which order

- 2026-09-26: `es_check` written from the -03 text at TKCollective/agentoracle-ietf-id `5a718639288a` (cold build,
  sha256 `ad009473…`). The choices that text leaves open are listed in `records/AMBIGUITIES.md` (Italian, as
  written then) and marked `# CHOICE n` in the code. Rulings later posted in tsc#4 (the NUL rule) and the
  `resource_sha256` sentence of -03 at `057abd7` were folded in before rev 9; both are now in the filed text.
- 2026-10-06, before any rev 9 vector was run: the filed -03 text (IETF archive, sha256
  `1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`) compared with the cold-build source in 5.3 and
  5.4.1. No rule changed; the filed sentences touching this code are annotated `# FILED Mn` and listed in
  `records/MODIFICHE_DA_TESTO_DEPOSITATO.md` (Italian). One non-semantic input was added (`held_sha256`).
- The harness (H1 to H4) was written from the rev 9 README's "H1–H5 comparability" and "Runner notes
  (non-normative)" sections at `4de7782` and from the form of the corpus inputs (`id`, `input`, `note`, the key names
  of `computed`; not `expect`, `condition` or the values of `computed`). Every reading those sections leave open is in
  `records/HARNESS_LETTURE.md` (Italian, L1 to L8), written before the run.
- Not opened for this run, before the results were frozen: babyblueviper1's checker and harness at `8a7599f`, his
  transcript at `be2a291`, the rev 9 generator and cross-check. Earlier, on 2026-09-28, an earlier version of his
  checker (`edb864b`) was run on our seven -03 vectors and seven probes and the condition sets were compared; our code
  was not changed from that comparison, but the one later change to it (`resource_sha256` null, 2026-09-29, taken from
  the -03 text at `057abd7`) is a point on which his checker had differed from ours. The runner notes' table of three
  vectors with a second condition was read before the run, so agreement on those three is not blind.
- A pre-registration (metric, controls, interpreters; sha256 `ad5d70070df75f1697a9f19ea8a896aee9ff31506621976d72769fc5a371346e`,
  2026-10-06T17:30:28Z) was written before the run. It is an internal file; what it fixes is restated here.

## Order of the run

1. `harness.py` runs the checker on all 47 vectors without reading `expect`, `condition` or `computed`; its raw
   output (`records/OUTPUT_grezzi.json`, sha256 `02726d03…e772`) was hashed at 2026-10-06T17:43:13Z.
2. `confronto.py` is the only file of the run that reads the expectations (`controlli.py`, written after the freeze,
   alters a condition and a computed root to test the bench). The `expect` members are prose; how each is read
   into a check is in that file. Results frozen at 2026-10-06T17:45:27Z (`records/RISULTATI_freddi.json` and
   `records/RISULTATI_freddi.sha256`).
3. Only then: `confronto_transcript.py` against babyblueviper1's transcript at `be2a291`.

## Results

Byte-identical output on Python 3.9.25, 3.11.2 and 3.13.15.

| measure | result |
|---|---|
| outcome (`expect`) | 47/47 |
| named condition among those reported (the runner notes' rule) | 47/47 |
| reported set equals the named condition | 44/47 |
| babyblueviper1's transcript at `be2a291`, line by line | 47/47 the same |

The three vectors with a second condition are the three in the runner notes' table:
`evi-content-kind-absent-when-pinned-rejects` and `evi-snippet-sha256-absent-when-pinned-rejects` also report
`evidence_root_absent_with_pinned_items` (the harness cannot compute a root, H3), and
`evi-full-resource-digest-on-unpinned-rejects` also reports `content_kind_present_when_unpinned` (the vector's own
input, Finding 51). Given a complete `evidence_set` with a non-null root, the two H3 vectors report only the named
condition (measured after the freeze).

Controls (`controlli.py`): an altered expected condition and an altered computed root are flagged; with H3 off,
38/47 outcomes agree (27/47 strict); one-byte input changes are flagged in four vectors, the fourth added after the
freeze to close a gap a mutant showed (declared); a fifth, on `snippet_sha256` of a vector that carries
`content_matches: true`, is not caught, as expected (see below). Rev 8 with the same checker (corpus sha256 `6ac833ed…`): 40/44. The four
disagreements are positive vectors that omit `snippet_sha256` on an unpinned entry, which rev 9 repairs.

`selftest_filed.py` checks the one added code path (5/5, with an inverted-compare control) and the filed presence
rule on an unpinned entry (1/1). `mutanti.py` runs 20 mutants of checker, harness and comparison: 16 are killed (15 by
the pipeline, one by `selftest_filed.py`). The four that live, with the measure behind each judgement: M05 (H3 writes
`null` instead of leaving the member absent) is equivalent by construction of the checker, which treats an absent and
a null `evidence_root` the same; M10 (root over all entries, not pinned only) is equivalent on this corpus, where all
30 entries of the 11 root vectors are pinned; M13 (the "differ" rubric without the inequality) is redundant here, the
4 "differ" vectors already carry different computed roots; M14 (the "not a root mismatch" clause) is unreachable with
this checker, which reports `root_not_recomputable_from_sources` only when (a) reported nothing (0 co-occurrences).

What these numbers do not cover: `evi-step-resolves-affirmatively` and `evi-resolve-all-counts-absent-accepted`
carry `content_matches: true`, not content bytes, so they do not exercise the digest comparison of 5.4.1(d); only
`evi-content-mismatch-unknown` does.

## Run it

```
curl -sSfLO https://raw.githubusercontent.com/TKCollective/tanilo-receipt-spec/0dffb77fa117099438d5ec15fbb48b2311792d26/fixtures/evidence-pinning-fixtures-v2-rev9.json
python3 harness.py evidence-pinning-fixtures-v2-rev9.json raw.json        # sha256 of raw.json: 02726d03…e772
python3 confronto.py evidence-pinning-fixtures-v2-rev9.json raw.json cmp.json
python3 controlli.py evidence-pinning-fixtures-v2-rev9.json controls.json
python3 selftest_filed.py
```

The CI job runs these on Python 3.9, 3.11 and 3.13 and fails unless the corpus hash, the raw-output hash and the
counts (47, 47, 47, 44) are the ones above and every control passes.

## Files and the frozen hashes

`records/RISULTATI_freddi.sha256` lists the files as they were at the freeze. Three files differ here.
`es_check_filed.py` (an internal-use line and three review attributions removed, two paths updated to `records/`)
and `harness.py` (one path updated) differ by comments and docstrings only: their Python syntax trees without
docstrings are unchanged. `controlli.py` differs by the control added after the freeze, as stated above: removing that
case and its two comment lines gives back the frozen file (sha256 `f954e041…`). The corpus is not copied here (MIT,
TK Collective LLC); it is fetched at `0dffb77` and checked against its hash.
