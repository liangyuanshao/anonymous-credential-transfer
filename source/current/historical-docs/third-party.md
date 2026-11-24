# Dependencies and sources

PBC 1.0.0 is downloaded from its official site, checksum-verified, and built
without changes. Its sources and license are in the excluded vendor directory.
PBC is LGPL-3.0; GMP and OpenSSL retain their respective licenses. The project's
MIT license applies to its own implementation and scripts, not those libraries.
No third-party source or original paper is relabeled as project-authored code.

- PBC: https://crypto.stanford.edu/pbc/
- PBC manual: https://crypto.stanford.edu/pbc/manual/
- ACL original: https://cs.brown.edu/people/alysyans/papers/bl13a.pdf
- GK original: https://discovery.ucl.ac.uk/id/eprint/1502142/1/Groth_764.pdf
- Figure export guidance: https://research-figure-guide.nature.com/

ACL reproduction is derived from the published equations rather than the
authors' historic BlackBerry software. Performance results belong to the
new reproduction and this machine, not the original authors' experiments.

## Additional baselines

Microsoft U-Prove reference source is included under `baselines/uprove/upstream`
at a fixed commit, with its complete original MIT license/notices and a SHA-256
manifest. The specifications remain original Microsoft documents, not original
project writing. The MSR crypto dependency is fetched at the exact original-lock
commit into an excluded build directory and retains its upstream notices.
Local TypeScript/Node compatibility changes are documented separately; the
vendored source snapshot is unchanged.

Chan--Yuen 2022 is independently reproduced from the published equations; no
author implementation was found. The copyrighted Springer PDF is not included.
The omitted encryption-specific proofs and the C-linkage issue are documented
in `baselines/chan_yuen_2022/README.md`; measurements are not a claim that these
research questions have been resolved.
