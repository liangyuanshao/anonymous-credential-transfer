# U-Prove baseline

This directory contains two deliberately separate implementations:

* `upstream/`: unmodified Microsoft TypeScript reference, commit
  `77933b3e8a739008bb65389d7a8ce79bcde73f91`, including MIT license, original
  specification, test vectors and tests. `upstream-manifest.json` hashes every
  source file. This snapshot implements the Lite profile of specification 1.1
  revision 5, without device binding, scope-exclusive pseudonyms or committed
  attribute presentations.
* `uprove.hpp`: this project's C++/PBC reproduction of the issuance, token
  signature, subset presentation and token-ID equations in sections 2.3--2.5.
  It uses the same PBC G1, SHA-512 transcript helper and fixed codec as OTAC/ACL.
  It is an **algebraic reproduction, not a byte-compatible U-Prove SDK**.

## Reproduce

Run the root `scripts/bootstrap.ps1`, then:

    build-native/uprove_reproduction.exe parameters/type-f.param

For the actual Microsoft implementation:

    .venv/Scripts/python scripts/setup_uprove_reference.py
    cd build-native/uprove-reference
    npm test -- --runInBand

From the repository root:

    node baselines/uprove/reference_benchmark.mjs 100 results/uprove-reference

The original dependency branch `export-math-lib` no longer resolves. The setup
script uses the exact dependency commit recorded in the original lock file,
`5b9a6dd4539a0968ea4ffa68d14c3c99a7bfc3e7`, in an excluded build copy. TypeScript
4.9.5 is pinned explicitly; emitted JS JSON imports use `with` for Node 22+.
The original upstream snapshot stays unchanged. Runtime package/lock files are
retained here to record the compatibility environment.

## Measurement contract

Exactly **one token per issuance**; no batching or amortization. Issuer/user
constructors and issuance validation are timed. Selective subset proof generation
and full verification include the token signature. An experimental spent-ID set
wraps verification to align one-spend workloads; this set is not supplied by the
U-Prove standard. The wrapper is an in-process model, not a deployed blockchain.

PBC attributes are pre-encoded field elements (the direct-encoding case); the
official reference hashes synthetic byte-string attributes. Native public policy
values are verifier inputs and excluded from response payload size, consistently
with the existing OTAC/ACL experiment. Official JSON sizes include disclosed
values and are recorded separately. Official P-256 / JavaScript timings and
JSON byte counts must not be merged with common-PBC timings / binary sizes.

Sources:
https://www.microsoft.com/en-us/research/project/u-prove/
https://github.com/microsoft/uprove-node-reference

The project's MIT license covers its wrappers/reproduction; upstream files retain
Microsoft's original notices. Inclusion does not imply Microsoft endorsement.
