# Evidence & target verification ledger

Source: user-supplied Claude report, dated 2026-10-19. It labels 4 original pages as read (A), with many other claims based on summaries (B). We **do not** promote those B claims into confirmed facts.

| Candidate | Role in study | Claimed design (to verify against pinned version) | Evidence | Next action |
| --- | --- | --- | --- | --- |
| OpenClaw | primary open protocol/adapter target | Gateway WebSocket, role/scopes, device pairing | official Gateway documentation | obtain release/source/permission semantics |
| OpenCode | contrasting local API | HTTP service and optional remote access | user report B | verify server auth, version and control semantics |
| Claude Code Remote Control | proprietary relay comparison | outbound HTTPS mediated session | user report marks A | record primary official docs and limits |
| Codex remote | proprietary relay comparison | host-server-controller relay, pairing | user report marks A | source-check product docs; no unsolicited probing |
| Hermes | IM gateway comparison | sender whitelist and session authorization | user report B | pin official repository/version |
| WorkBuddy | domestic IM/enterprise angle | IM-based control and approvals | user report B | verify vendor documentation; don't assert E2EE |

## Confidence levels

- `primary_verified`: directly matched to an accessible publication or official versioned document.
- `secondary_lead`: only the attached Claude note, snippet or third-party summary supports it.
- `hypothesis`: plausible weakness, **not an observation**.
- `lab_reproduced`: tested on an explicitly specified version in an authorized isolated setup.
- `vendor_confirmed`: confirmed by maintainers/advisory.

## Verification questions

- What principals are independently authenticated? account, device, tab, session, node?
- Is a grant scoped to role, tool, workspace, action digest or only a bearer token?
- Can a paired connection survive token rotation, logout, revocation or re-pairing?
- Is in-flight execution after revocation explicitly allowed? What cancellation guarantee?
- Does an IM identity represent a sender, a group, a client app or a trusted approver?
- What can a relay observe, authenticate or modify? Don't infer E2EE from TLS.

## Do not conflate

Network reachability != authorization; API response != executed side effect; anomaly != vulnerability; CVE count != new root causes; mobile as controller != Agent controlling the phone.
