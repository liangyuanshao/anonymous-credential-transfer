# Independent ACL reproduction

This directory implements registration, preparation, validation, unblinding and
signature verification from Baldimtsi and Lysyanskaya, *Anonymous Credentials
Light*, ACM CCS 2013, Section 5 / Table 2:
https://cs.brown.edu/people/alysyans/papers/bl13a.pdf

It is a new reproduction of those equations, not the authors' original code.
The group backend and scalar/RNG/transcript utilities are shared with the main
project for controlled timing; ACL protocol logic is isolated in acl.hpp.

For the same attribute-equality task, disclosed attributes are public at
registration, and registration proves the opening of the remaining randomness
and holder secret. Presentation proves two linked linear relations using
u=gamma^{-1}, retaining the original blinded commitment.
Registration uses the Fiat--Shamir form for a common comparison convention;
the blind-signature preparation and validation remain interactive.

An explicit application wrapper records the random 32-byte signed message after
successful presentation. This supplies the shared spent-state rule for the
comparison; it is not an additional theorem or native ledger component in ACL.
Report both first-issuance and reissuance costs. The fixed serialized token is
not counted twice in the presentation.
