# Protocol-to-code mapping

The current implementation follows the seven algorithms and three concrete
knowledge proofs in Section 6 of the Chinese manuscript. It lives in
`otac::scheme` in `src/ours.hpp`; `tests/protocol_checks.hpp` contains the
corresponding executable checks. The four-scheme batch in `results/current/`
has its own measured source archive. The paired comparison of the current
prover and the archived windowed prover is in `results/oom-comb/`. The
earlier studies are in `results/oom-factoring/` and `results/oom-reuse/`.

## Groups and setup

`Params` wraps the shared PBC group parameters and supplies the credential
protocol's independent tag generator `k` and parameter fingerprint. The group is
PBC G1 over the committed asymmetric Type F parameter file. Scalar arithmetic is
modulo its actual subgroup order. OpenSSL supplies the CSPRNG and SHA-512.
Domain-separated public labels derive the generators; the protocol does not
store their discrete-log relations. Issuance, consumption and transfer compute
no pairing; the PBC pairing context supplies the source group.

## Seven algorithms

1. **Setup.** Initialize commitment and proof parameters, an ordinary Schnorr
   issuer signing key, and empty `AttrSet` and `SpentTagSet` ledger state. The
   implementation uses a local ledger interface and does not emulate consensus.
2. **CredGen.** Given the existing identity secret `x` and attributes `a`, sample
   `r` inside `cred_gen` and construct `Y=h0^x`, `R=Y^r`,
   `C=g^r product_i h_i^a_i`. The request includes `Y,R,a,C` and a joint
   Schnorr proof of `Y=h0^x`, `R=Y^r` and `C/P_a=g^r`. These three equations
   share two responses, for `x` and `r`. Local credential opening material is
   **only `(a,r)`**; `x` is not part of the commitment or later spending tag.
3. **Issue.** Check the supplied attributes against issuer-accepted attributes,
   verify the joint request proof, and sign `C` with ordinary Schnorr. The
   benchmark uses synthetic accepted attributes; human document inspection and
   authenticated confidential transport are external. `register_issued`
   verifies the signature and atomically inserts the commitment only once.
   A usable credential requires registration confirmation.
4. **ProofGen.** Sample a distinct registered list containing the owned `C` at
   a random position `j`. Sample `Delta`, then compute `T=k^r`, `D=C g^Delta`,
   `rho=r+Delta` and `U=T k^Delta`. The joint proof combines paired GK
   membership for `(D/C_j,U/T)=(g^Delta,k^Delta)` with
   `D/P_S=g^rho product_(hidden i) h_i^a_i` and `U=k^rho`.
5. **Verify.** Check the actual candidates are distinct and registered, verify
   the full joint proof and requested public attribute equalities, then
   atomically check/insert `T` in `SpentTagSet`. A repeated tag is rejected.
6. **Transfer.** The receiver is given `(C_A,a,r_A)` through an authenticated
   confidential channel. It checks the opening and old tag, samples a fresh
   `r_B`, and creates `C_B=g^r_B P_a`. It proves hidden membership of the old
   commitment, the old tag `T_A=k^r_A`, and the identical attributes in `C_B`.
   It retains `(a,r_B)` and does not send the new tag `k^r_B` as a public field.
7. **VerifyTransfer.** Verify the joint transfer proof and atomically reject a
   spent old tag or an already-registered `C_B`; otherwise insert `C_B` in
   `AttrSet` and `T_A` in `SpentTagSet`. The old opening remains physically
   copyable, but cannot consume or transfer after successful registration.

The receiver creates transfer proof helpers `D_tr=C_A g^delta` and
`U_tr=T_A k^delta`. One paired GK proof binds their hidden old source. The
representation proof simultaneously establishes
`D_tr=g^rho_tr P_a`, `U_tr=k^rho_tr`, and `C_B=g^r_B P_a`. The first and third
equations use the same response for every attribute; the first and second use
the same response for `rho_tr`. The new tag is not a proof input.

## Three concrete joint proofs

The request proof is generalized Schnorr with three first messages and two
responses. Consumption and transfer each use **one** GK One-out-of-Many proof
over pairs, with `Com_x(m;s)=(g^(m+s),k^s)`, joined to their representation
proof. Each GK bit has four paired first-round commitments, eight group
coordinates in total. Its polynomial coefficients use only the selected index
and fresh masks; other candidates' private openings are not available to the
prover.

Actual lists may have non-power-of-two lengths. Let `m=ceil(log2 ell)` and pad
deterministically by `Q_t=Q_(t mod ell)` up to `2^m`; these are internal repeated
items, while the actual registered list must remain distinct.

Each proof has one domain-separated Fiat–Shamir challenge over the complete
public statement and all first messages. Proof challenges are 128-bit values
embedded in the group scalar field, as specified by the manuscript's
`q>2^lambda` condition. Consuming or transferring does not use the holder's
identity secret `x`. Signature challenges are separate from proof challenges.

## Ledger and benchmark boundary

Candidate decoys are real signed, registered commitments generated outside the
timed calls; their openings are then discarded. A fresh measured credential is
registered in a copy of that pool for each repetition. Candidate selection uses
random position selection and partial Fisher–Yates sampling inside the timed
ProofGen/Transfer call, together with list processing, copying, complete
transcript hashing and proof randomizers.

Holder identity secrets, common parameters and synthetic attribute encodings
exist before timing. The credential opening `r`, proof masks, rerandomizers and
new transfer opening `r_B` are sampled inside their respective timed functions.
Issuer cryptographic verification and signing are timed; human review,
registration confirmation, network and consensus are not.

Verification runs on parsed PBC objects. One consumption and transfer output
per configuration is actually serialized, decoded and checked outside timing;
dedicated rejection tests cover malformed encodings. Every verification includes
candidate membership/uniqueness checks, all proof equations, and the local
atomic ledger operation. Independent copies of the same pre-consumption ledger
isolate consumption and transfer timings; they do not claim both can succeed
against one shared live state.

## Independent baselines

ACL in `baselines/acl` follows Section 5 of Baldimtsi–Lysyanskaya 2013, including
both OR-proof branches and user blinding. Its public token is
`(m,zeta,zeta1,rho,omega,rho1,rho2,omegap,mu)`, with a 32-byte signed message `m`.
Registration uses an explicit Fiat–Shamir opening proof; the subsequent blind
signing interaction is retained. First issuance includes registration and the
holder's final signature check. Selective disclosure proves the required
attribute equalities and verifies the signature, not only a signature substep.

U-Prove is an algebraic reproduction on the shared PBC parameters. The official
Microsoft P-256/Node implementation and tests remain a separate reference; its
timings are not mixed with PBC rows. One token is issued per execution, with no
batch amortization.

Chan–Yuen uses actual Paillier arithmetic for the honest-party issuance core and
the paper's single-use AND pairing equations. The unspecified `pi_U` and HE
range/well-formedness/key proofs are absent; complete issuance time and size are
therefore unavailable. Its issuance rows have `operation_complete=0`. Reusing
the same source-paper `C` at issuance and presentation also prevents asserting
issuer-unlinkability from these checks. A shared spent-identifier wrapper on
the baselines is experimental, not a claim that every source protocol supplies
the current ledger semantics. See each baseline README for details.

## Encoding and communication

Group payload encoding is one identity/type byte followed by a fixed-size native
PBC compressed point. Scalars are fixed-width unsigned big-endian values.
Canonical wire parsers check lengths, tags, subgroup membership, scalar ranges,
vector format and unused trailing bytes. Version/shape framing belongs to the
wire encoding and is reported separately from cryptographic payloads. Policies
known to the verifier and external evidence are not repeated in the payload
comparison.

For group size `B_G`, scalar size `B_q`, `u=n-d`, and `m=ceil(log2 ell)`:

| Current object | Cryptographic payload |
| --- | --- |
| Request proof | `3 B_G + 2 B_q` |
| Request, excluding external evidence | `6 B_G + (n+2) B_q` |
| Credential `(C,sigma_I)` | `2 B_G + B_q` |
| Bilateral issuance | `8 B_G + (n+3) B_q` |
| Issuance including one chain submission | `10 B_G + (n+4) B_q` |
| Consumption joint proof | `(8m+2) B_G + (3m+u+2) B_q` |
| Full consumption | `(ell+8m+5) B_G + (3m+u+2) B_q` |
| Transfer proof, including internal `D_tr,U_tr` | `(8m+5) B_G + (3m+n+3) B_q` |
| Full public transfer submission | `(ell+8m+7) B_G + (3m+n+3) B_q` |

The full messages include the actual candidate list; padding is deterministic
and not transmitted as additional candidates. Concrete byte lengths are checked
against serialized objects by the current audit script.

The transfer submission excludes the prior confidential handoff `(C_A,a,r_A)`
from the old holder to the receiver. That handoff has `B_G+(n+1)B_q` fixed
cryptographic bytes: 1154 B at the default point. It plus the 10222 B public
submission totals 11376 B, excluding secure-channel framing and confirmations.


## Group arithmetic

The shared PBC backend uses Jacobian coordinates for scalar multiplication and bucket MSM in both G1 and G2. Field operations remain PBC operations. Public fixed bases are prepared during parameter initialization; masks and witnesses are never cached across proofs. G1/G2 scalar powers, degenerate additions, MSM and the GK coefficient identity are checked against native PBC computations in tests/group_arithmetic.cpp.

The GK prover uses sum_i p_i(X)=X^m: low-degree coefficient sums vanish, so its first coordinates use the original candidate bases with negated coefficients. The second coordinates are k^eta. Verifier product equations are evaluated as MSMs. The transcript, common challenge, witness relations and serialized payload sizes are unchanged. Transfer reuses its attribute product within the operation.

For the grouped prover, let `J` be the positions that contribute `X`
in the expansion of the GK polynomial. Fix each candidate bit in `J` to
the witness bit. At each remaining position, the constant terms of the
two choices are `-a_b` and `a_b`. Fold a pair of bases `C_0,C_1`
into `C_1/C_0` on that branch. The other branch keeps the base on the
witness side. After all positions, the aggregate for `J` occurs in
degree `|J|` with exponent minus the product of the masks outside `J`.
Every proper subset contributes one exponent to one degree. For the
padded size `N=2^m`, the fold uses `mN/2` group divisions and supplies
`N-1` candidate exponent terms across all coefficients. This evaluates
the same first messages for each fixed random tape. The code computes the
aggregates inside each proof, including the candidate order used in the
challenge. The comparison measures this work and the rest of the original
generation path together.

The verifier's padded weights sum to `c^m` because each bit contributes
the two factors `c-f` and `f`. Its first-coordinate product can therefore
use the original commitments and a single factor `D^(c^m)` in place of
forming every quotient `D/C_i`. The second coordinate uses the same
power `c^m`. This identity holds for arbitrary responses in the scalar
field, so both exact equality checks retain their acceptance conditions.

OoM products with up to 128 terms use width-five signed recoding and
interleaved point additions. The two powers of each bit commitment share
its odd multiples. The per-call tables are built inside the measured
operation. This is a variable-time evaluator within the PBC prototype.
For the signed window method, see [Möller, Efficient Multi-Exponentiation](https://www.bmoeller.de/pdf/pkc-tp.pdf).

The current scheme-specific parameter object constructs two comb tables
for the public bases `g` and `k`. With eight teeth and four blocks, each
block holds subset products of shifted public powers. The online evaluator
accumulates these affine points in Jacobian coordinates and normalizes the
final point once. The `k` comb replaces its former PBC fixed-base table.
The shared `PP` and the baseline implementations use their existing paths.
Scheme-specific construction is timed separately in the current comparison.

During presentation and transfer generation, the opening check and
attribute proof evaluate products of the same attribute bases. They share
the per-proof odd-multiple tables while using their own exponents. The
benchmark includes construction of those tables inside each generation.
The comb and attribute products evaluate the existing exponent equations.

Coordinate formulas: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
PBC fixed-base interface: https://crypto.stanford.edu/pbc/manual/ch04s05.html

## Scope of evidence

The current service request is `req=(S,v_S)` and has no session nonce. A valid
proof is not claimed to provide session-binding or resistance to cross-session
forwarding. Local atomic-state checks establish that repeated or competing
uses cannot both succeed in the tested state machine; they do not measure a
deployed consensus protocol.

Executable checks establish algebraic consistency, rejection behavior and
serialization round trips. They do not complete extraction, anonymity or the
noninteractive composition proofs. The asymmetric G1 setting is a prerequisite
for the intended DDH assumption, not a certificate that the fixed parameter file
proves every assumption. No common end-to-end 128-bit security equivalence with
the baselines is asserted.

