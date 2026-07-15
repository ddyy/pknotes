# Security policy

pknotes is a small, self-hostable E2EE notes app. The security model and its
limits are documented in the [threat model](README.md#threat-model) — reading
it first will tell you whether something is a known trade-off or a real bug.

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub's private vulnerability reporting](../../security/advisories/new)
("Report a vulnerability" on the repo's Security tab). Please don't open
public issues for security problems.

You can expect an acknowledgement within a few days. This is a personal
open-source project: there is no bug bounty, but reports are taken seriously,
fixes are prioritized over features, and credit is given in the fix commit
unless you prefer otherwise.

## Scope notes

Especially interested in: anything that lets the server (or a database dump)
recover plaintext; cross-user data access; WebAuthn/PRF ceremony flaws;
ciphertext malleability the AAD binding should have caught; recovery-code or
rotation flaws that violate the revocation semantics described in the README.

Out of scope: the web-delivery trust floor (the server ships the client —
documented), metadata visibility (timestamps, sizes, IPs — documented), and
denial-of-service against a personal instance beyond the documented rate
limits.
