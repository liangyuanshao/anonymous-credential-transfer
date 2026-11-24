# Chan--Yuen, CANS 2022: honest-party issuance core and single-show AND

Kwan Yin Chan and Tsz Hon Yuen. *Attribute-Based Anonymous Credential:
Optimization for Single-Use and Multi-Use*. CANS 2022, LNCS 13641, pp. 89--121.

DOI: https://doi.org/10.1007/978-3-031-20974-1_5
Preprint: https://eprint.iacr.org/2022/1585

No author implementation was located in the paper, authors' publication pages or
targeted GitHub searches on 2026-11-04. These are independently written source
files derived from the published equations, not downloaded author code.

## What runs

* `pairing.hpp`: actual asymmetric PBC G1/G2/GT and pairing verification.
* `paillier.hpp`: actual GMP/OpenSSL Paillier, 3072-bit modulus, not a simulated
  encryption or a timing estimate. Signed integer plaintext decoding precedes
  reduction to the pairing-group field; the modulus exceeds the MtA product
  bound. Paillier key generation is measured separately and reused.
* `chan_yuen.hpp`: section 4.2 honest-party issuance, including a Schnorr
  instantiation of pi_s, actual encrypted MtA, partial/final CL signature and
  user-side signature validation; section 6.1.1 AND presentation and Appendix
  E.1 pairing relation. A commitment uses n public attribute roots plus one
  opening root; setup supports polynomial degree n+1 explicitly.

After the root build:

    build-native/chan_yuen_reproduction.exe parameters/type-f.param

## Boundaries that affect the comparison

1. **Incomplete malicious-secure issuance.** Section 2.4 explicitly omits
   cryptosystem-specific range/ZK proofs while requiring them. Section 4.2 step
   4 names pi_U(t',u2,gamma2) without its concrete encryption-specific protocol.
   This implementation does not replace them with accepting stubs. The API is
   explicitly named `*_core`; every issuance timing has `operation_complete=0`.
   Communication for issuance is an incomplete-core **lower bound**, never a
   complete issuance size. A safe complete-issuance value is left unavailable.
2. **Issuer linkage in the printed workflow.** Section 4.2 sends C,o to the
   issuer; section 6.1/6.1.1 presents C. Following these formulas, an issuer that
   retains its transcript can compare C directly. This conflicts with the prose
   in section 6.1 claiming the issuer learns no information about C. The code
   follows the concrete equations and does not silently repair this issue or
   claim issuer-unlinkability. Cost measurements are not confirmation of the
   paper's privacy claims.
3. **Single-show is a privacy-use restriction.** Section 6.3 requires one show
   to retain unlinkability. There is no global spent registry in the source.
   `verify` adds an experimental in-process spent-key wrapper based on v solely
   for a workload comparison. No new global one-spend theorem is claimed.
4. **AND only.** The common policy checks membership of the requested typed
   attribute=value roots. OR/NAND/NANY and multi-show are outside this experiment.
   Presentation has no fresh session-bound possession proof in the source;
   adding one would be an additional construction and is not hidden in timings.

Attribute names/values are encoded into distinct public field elements before
timing, as for the other schemes. The issuer attribute table is pre-provisioned;
the common n-scalar attribute-submission cost is included in communication for
alignment. Credentials/presentations exclude the holder's private attribute
list and opening; they include public C and signature (t,s,v), plus W for show.
G2 polynomial evaluation uses ordinary exponentiation/products; the measurements
describe this research reproduction, not an optimized author implementation.
G1 operations use the repository's shared MSM helper.

The local source PDF was the 33-page Springer publication, SHA-256
`eb41077c33551ad8120695dcbe7454e2649074043b4813ffc4e85addd17c9758`.
It is not redistributed here. Complete-issuance comparisons remain pending
explicit instantiation/audit of the omitted proofs; they must not be plotted as
if those proofs cost zero.
