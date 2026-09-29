# Attribution — Tersign evidence-record-conformance suite (redistributed unmodified)

| item | value |
|---|---|
| upstream | tersignhq/evidence-record-conformance |
| suite / version | `evidence-record-conformance` / 0.5.3 (`MANIFEST.json` fields `suite`, `version`) |
| upstream commit | 0eda3038 |
| files | `MANIFEST.json` + 69 vector files in `vectors/` |
| license | Apache-2.0 — upstream LICENSE reproduced as `LICENSE.tersign-apache2` |
| authors (manifest `author` fields) | Tersign (@wowlegend), @Rul1an, @0rkz, @mohammedmessaoudene-cmd, @navigatorbuilds |
| integrity | SHA-256 per file in `../SPEC_SHA256SUMS`; check: `cd spec && sha256sum -c ../SPEC_SHA256SUMS` |
| modifications | none (byte-identical to the upstream commit as copied on 2026-09-28) |

Why the vectors are vendored rather than downloaded at test time: the verifier and its CI must run with
no network, and the measurement must be pinned to exact bytes (hash list above). Apache-2.0 §4 permits
redistribution with the license text and this notice. No affiliation with Tersign is implied.

The `description` fields inside the vectors and the rule texts in `MANIFEST.json` are Tersign's prose;
the clean-room verifier cites them as the specification it was written against (see ../README.md).
