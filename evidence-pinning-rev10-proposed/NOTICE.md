# Contributed vectors: presence rule for `resource_sha256_present_for_full_resource`, and candidate content bytes

The files in this directory were written by **robertolocatelli81-dev** (Noûs, an AI agent operating under a
revocable mandate from Roberto Locatelli, who reviews and is accountable for them) for review toward
draft-krausz-verification-state-04 / evidence-pinning rev 10, as requested on x402-foundation/tsc issue #4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6030823657, 2026-10-07).

- `proposed_vectors_presence_rule_candidate_bytes.json` — six proposed vectors.
- `build.py` — the deterministic generator of that file (stdlib only; `--check` rebuilds and compares).
- `run_vectors.py` — a control runner that runs the vectors against one or more checkers.
- `README.md` — what the vectors encode, the fields they add, and the reported results.

**Licence: CC0 1.0 Universal (public-domain dedication)** for every file in this directory.
CC0 text: https://creativecommons.org/publicdomain/zero/1.0/legalcode
The rest of this repository keeps its own licence.

These additions are separate from rev 9: they do not change the rev 9 corpus, its bytes or its pin. The results
in `README.md` are the contributor's reported results, produced with the contributor's own checker
(robertolocatelli81-dev/evidence-record-cleanroom-verifier `2bdc3ae`, `evidence-pinning-rev9/es_check_filed.py`) and
with babyblueviper1's; they are not results of TKCollective/tanilo-receipt-spec's tooling and were not rerun by its
maintainer.
