## Electronic Invoicing Minimum Critical Test Plan

### Goal

Prove the electronic invoicing backend is safe enough for first controlled DGII precert testing without changing architecture.

### Automated proof required

- Environment validation must reject unsafe boundary values and allow FE runtime-only secrets to remain optional at startup.
- Certificate registration must prove real `.p12` parsing works and invalid passwords fail fast.
- XML generation must cover outbound document types `31` and `32`.
- XML signing must prove `Signature`, `DigestValue`, `SignatureValue`, and `X509Certificate` are present.
- Sequence allocation must show unique e-CF generation across consecutive allocations.
- Seed creation must persist a challenge and expiration; expired seeds must be rejected.
- Inbound token enforcement must reject missing tokens when FE auth is enabled.
- Outbound generate to sign must prove a real unsigned XML becomes a signed XML using a registered certificate.
- Credit note generation must preserve original invoice references in XML.
- DGII failure handling must create audit evidence.
- Track result lookup must define current behavior for malformed or unknown TrackId values.

### Still manual after automation

- Real DGII precert submission with live credentials.
- DGII schema compliance against live validators or official XSDs.
- Certificate ownership and trust-chain enforcement.
- Replay resistance for semilla and public tokens.
- Multi-branch inbound behavior beyond branch `0`.