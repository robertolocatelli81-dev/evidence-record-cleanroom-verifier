# Errata to the committed runner (commitment `3b766320…7f9e`)

The files in `commitment-3b766320/` are the committed bytes and are not modified. The defects below were found after the
commitment was posted (2026-09-30T22:53:10Z), each while auditing the same class of defect in our crypto-profile runner. They
concern how the runner reads its MANIFEST and vector files and how it prints; **none changes a verdict or a reason on the 52
committed vectors** (measured: identical file, verdict and reason on all 52, and identical killer lists for the 11 built-in
mutants, on Python 3.9, 3.11 and 3.13 with `PYTHONINTMAXSTRDIGITS` unset, 0 and 640). The corrected runner is
`runner/verify_eip712.py`; `runner/test_verify_eip712.py` fails on the committed runner for each item below.

| | Recorded (UTC) | Committed runner (measured) | Corrected runner |
|---|---|---|---|
| E1 | 2026-09-30 23:25 | a listed file name containing NUL raises `ValueError` (traceback, exit 1) | run stopped, exit 2 |
| E2 | 2026-10-01 00:06 | `"vectors": []` exits 0 with "concordant 0/0"; a `file` such as `../MANIFEST.json` or `/etc/hostname` is read outside `vectors/`; a FIFO blocks the run | run stopped, exit 2, in each case |
| E3 | 2026-10-01 05:15 | a file name stdout cannot encode (e.g. `café.json` with `PYTHONIOENCODING=ascii`) raises `UnicodeEncodeError` (traceback, exit 1) | printed with backslash escapes; exit code and `--json` unaffected |
| E4 | 2026-10-01 06:01 | MANIFEST.json was parsed with the plain `json` module: a 5,000-digit integer in an unread key stopped the run with the default int-string limit and not with `PYTHONINTMAXSTRDIGITS=0`; a duplicate key let the last value win; a `NaN` token was accepted | MANIFEST.json is parsed like the vector files: no int-string limit, no NaN/Infinity, a duplicate key stops the run |
