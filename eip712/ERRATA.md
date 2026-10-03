# Errata to the committed runner (commitment `3b766320…7f9e`)

The files in `commitment-3b766320/` are the committed bytes and are not modified. The defects below were found after the
commitment was posted (2026-09-30T22:53:10Z). E1–E4 were found while auditing the same class of defect in our crypto-profile
runner; they concern how the runner reads its MANIFEST and vector files and how it prints, and **none changes a verdict or a
reason on the 52 committed vectors** (measured on 2026-10-01: identical file, verdict and reason on all 52, and identical
killer lists for the 11 built-in mutants, on Python 3.9, 3.11 and 3.13 with `PYTHONINTMAXSTRDIGITS` unset, 0 and 640).
**E5 changes one verdict and one committed expectation:** `ea3`. It is a misreading of x402, pointed out in Tersign's review
of tersignhq/evidence-record-conformance PR #13, where the same misreading had been adopted on our cross-check. The corrected
runner is `runner/verify_eip712.py`; `ERRATA_EXPECT.json` holds the corrected expectation and is passed with `--errata`, so
the committed MANIFEST stays byte for byte. `runner/test_verify_eip712.py` fails on the committed runner for each item below.

| | Recorded (UTC) | Committed runner (measured) | Corrected runner |
|---|---|---|---|
| E1 | 2026-09-30 23:25 | a listed file name containing NUL raises `ValueError` (traceback, exit 1) | run stopped, exit 2 |
| E2 | 2026-10-01 00:06 | `"vectors": []` exits 0 with "concordant 0/0"; a `file` such as `../MANIFEST.json` or `/etc/hostname` is read outside `vectors/`; a FIFO blocks the run | run stopped, exit 2, in each case |
| E3 | 2026-10-01 05:15 | a file name stdout cannot encode (e.g. `café.json` with `PYTHONIOENCODING=ascii`) raises `UnicodeEncodeError` (traceback, exit 1) | printed with backslash escapes; exit code and `--json` unaffected |
| E4 | 2026-10-01 06:01 | MANIFEST.json was parsed with the plain `json` module: a 5,000-digit integer in an unread key stopped the run with the default int-string limit and not with `PYTHONINTMAXSTRDIGITS=0`; a duplicate key let the last value win; a `NaN` token was accepted | MANIFEST.json is parsed like the vector files: no int-string limit, no NaN/Infinity, a duplicate key stops the run |
| E5 | 2026-10-03 05:15 | an omitted `transaction` is hashed as `""`, so `ea3` (`ea2`'s test-key payload and signature, without `transaction`) verifies, and the committed MANIFEST expects `valid`. x402 `extension-offer-and-receipt` 5.3 has the signer set an unused `transaction` to `""` and maps `""` to absence, not absence to `""`; 5.5 step 3 uses the payload "exactly as transmitted". Measured on `ea3`'s input: x402's `verifyReceiptSignatureEIP712` (`03b3919`, the function as written, run with viem 2.57.2) throws `TypeError`, and eth_account 0.14.0 recovers `0xb2E9373874d288bb50B629EF06cfd47873Ba39ec`, not the signer; both recover the signer once `transaction: ""` is present | all six Receipt fields required: `ea3` rejects as `malformed_payload` (expected so in `ERRATA_EXPECT.json`); the committed reading is kept as the built-in mutant `transaction_filled_when_absent`, killed by `ea3` |
