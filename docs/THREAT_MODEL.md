# Threat model / 威胁模型 (v0)

## System boundaries

Phone/controller -> account or pairing -> relay / messaging service / direct WebSocket -> host Gateway -> Agent session -> approval gate -> local tool execution.

A controller may be a phone app, a web page, or an IM account; these are **not equivalent principals**. Distinguish user account, device key, paired device, transport connection, session, task, authorization grant, and tool invocation.

## Adversaries

- **External web attacker:** controls a web origin; does not inherently control localhost or know gateway secrets.
- **Untrusted controller or channel sender:** may supply messages but lacks owner permissions.
- **Revoked or formerly paired device:** held a valid grant in the past, but it was removed.
- **Relay or integration operator:** can observe or transform traffic only to the extent allowed by the actual design.
- **Agent-content adversary:** controls untrusted task data; not the same as an authenticated user approving execution.

Do not assume the attacker possesses another user's credentials, local administrator access, or private cryptographic keys without explicitly stating that prerequisite.

## Candidate security properties (hypotheses, not vendor specifications)

| ID | Property | Offline oracle baseline |
| --- | --- | --- |
| P1 | Pair request binding | user, device, nonce and request ID match |
| P2 | Time/one-time binding | request unexpired and nonce not reused |
| P3 | Least-grant progression | approved scopes subset of requested scopes |
| P4 | Principal binding | approver corresponds to owner under strict model |
| P5 | Session binding | session user and scopes match active pair |
| P6 | Approval-to-execution binding | same action ID, session, tool, argument digest |
| P7 | Revocation freshness | no new execution through revoked grant |
| P8 | Pairing epoch isolation | prior sessions do not inherit newly re-paired grant |

P4/P7/P8 are **strict candidate policies**; real products can legitimately support delegated approvers, delayed cancellation or explicit resumption. An observed disagreement is not automatically a flaw.

## Trust and measurement assumptions

1. Input JSONL is a **normalized trace produced by a trusted observer**, not a raw remote client's asserted log.
2. The event timestamp is in a consistent logical clock domain; `expiresAt` uses that same domain. Distributed traces will need clock uncertainty annotations.
3. Scope strings are opaque. An adapter must document how product permissions map to them; no mapping is assumed.
4. Digest strings identify a canonical action representation. Real adapters must define canonicalization and protected argument extraction; fixtures use symbolic values, not cryptographic proof.
5. Current oracle treats approval as necessary for every executed action. Real systems often have automatically allowed operations; policy must become action-class configurable before product studies.

## Out of scope for v0

No cryptographic proof, no E2EE audit, no browser exploit, no cloud relay penetration testing, no performance claims and no prompt-injection benchmark.
