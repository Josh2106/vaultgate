# Security Policy

## Supported versions

vaultgate is pre-1.0. Only the latest `main` receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private
[security advisory](https://github.com/Josh2106/vaultgate/security/advisories/new)
form. Include affected version/commit, reproduction steps and impact.

* Acknowledgement within 72 hours; triage and severity assessment within 7 days.
* Fixes for confirmed issues are released as soon as practical, with credit to
  the reporter unless you prefer otherwise.
* Good-faith research that respects user privacy and avoids service disruption
  will not be pursued legally.

## Scope

In scope: authentication/authorisation bypass, tenant isolation (BOLA/IDOR),
cryptographic weaknesses, audit-log tampering that verification does not detect,
injection, secret disclosure via logs or errors.

Out of scope: findings that require a compromised host or KEK, denial of service
by volumetric traffic, missing hardening on the example infrastructure files.

## Design documentation

The crypto design and threat model are in [`docs/security-design.md`](docs/security-design.md)
and the ADRs under [`docs/adr/`](docs/adr).
