# EIP-712 receipt signatures: a second runner and vector set (commit-reveal)

A runner and 52 vectors for x402 receipt payload signatures (`format: "eip712"`), the EIP-712 milestone of
tersignhq/evidence-record-conformance PR #11. They were committed before the milestone's own set was revealed:
`commitment_sha256 3b7663201182e564f8649f835c4f3e8544438be49b838fde9ff887702a7a7f9e`, posted at 2026-09-30T22:53:10Z
(https://github.com/tersignhq/evidence-record-conformance/pull/11#issuecomment-5921105343).

## Check the commitment

```
python3 verify_commitment.py
```

It hashes every file in `commitment-3b766320/`, compares the result with `record_body.json`, and computes
`sha256(NONCE ‖ canonical_json(record_body))` with the nonce in `NONCE` (64 hex characters, published with this package); it exits
0 only on `MATCH`. `commitment-3b766320/` holds the committed bytes
unchanged: 52 vectors and their manifest (`out/`), the runner, its library (`lib/`) and the generator.

## Run the vectors

```
python3 runner/verify_eip712.py commitment-3b766320/out              # concordant 52/52
python3 runner/verify_eip712.py commitment-3b766320/out --mutants    # 11 built-in mutants, each killed by a named vector
(cd runner && python3 -m unittest -v test_verify_eip712)             # 25 tests
```

`runner/verify_eip712.py` is the committed runner with the input-handling corrections listed in `ERRATA.md`; on the 52
committed vectors it returns the same verdict and reason as the committed runner, vector by vector. Stdlib only; measured
on Python 3.9.25, 3.11.2 and 3.13.15. The vectors are 6 accept and 46 reject, over eight reasons: `malformed_input`,
`unsupported_format`, `malformed_payload`, `unsupported_version`, `malformed_signature`, `non_canonical_s`,
`unrecoverable`, `signer_mismatch`. The test key and the nonce derivation are in `out/MANIFEST.json`.

## What the runner reads, and what it chooses

Sources: EIP-712, x402 `extension-offer-and-receipt` (sections 3.2 and 5.3–5.5), and the construction published on PR #11
(domain `{name: "x402 receipt", version: "1", chainId: 1}`, the `Receipt` type, the payload as served). The live vector
`ea1` is p1's artifact as served, which recovers to `0x36f82906859e5b0bd076069f8cdfaea355358b14` with a low-s signature.
The runner's docstring lists the checks in order and, separately, every reading the sources do not decide (for example:
extra keys in the payload or the artifact reject, `uint256` only as a JSON integer, low-s required by analogy with the
crypto profile, `payer` hashed as written). Not checked: `network` against `eip155:<chainId>`, the `issuedAt` policy
(x402 5.5 step 6) and signer authorization (4.5.1); each vector names its expected signer.

## Errata

`ERRATA.md` lists four input-handling defects of the committed runner found after the commitment (E1–E4), with the
committed runner's measured behaviour and the corrected one. None changes a verdict on the committed vectors.
