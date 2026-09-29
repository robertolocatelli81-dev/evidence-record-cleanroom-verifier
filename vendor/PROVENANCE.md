# Provenance of the vendored primitives (copied 2026-09-28, read-only inputs of the isolated session)

| file | origin | license | note |
|---|---|---|---|
| `roberto_x402_eip712.py` | Roberto Locatelli, `x402-signature-vectors/lib/eip712.py` @ 985b46d | Apache-2.0 | Keccak-256 (pre-NIST padding 0x01) — copied verbatim into `verify_tersign.py` |
| `roberto_omega_evidence_aat.py` | Roberto Locatelli, `omega-evidence/omega_evidence/interop/aat.py` @ 6728ced (0.9.1) | Apache-2.0 | consulted for its JCS sketch only; NOT used. Known defect: its strict mode accepts 2^53, while the I-JSON exact bound is ±(2^53-1) — the verifier's own JCS applies the correct bound |

SHA-256:
```
1871f55b7ec5f110e1c40c90dc9c2a1cf835644041941b84ddf1e3c60afc1908  vendor/roberto_omega_evidence_aat.py
8f1ae28568fdeab8713c3595631ab313ec9cc14bddc6772e0dd78946b804e608  vendor/roberto_x402_eip712.py
```
