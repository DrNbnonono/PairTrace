# Adapter contract / 协议适配器规范

No adapter is implemented in v0. This document describes the boundary between authentic wire frames and PairTrace's normalized event schema.

## Interface proposal

```ts
interface TraceAdapter {
  readonly product: string;
  readonly version: string;
  readonly channel: "local-ws" | "http" | "cloud-relay" | "im";
  normalize(capturedFrame: unknown): Event[];  // or none if irrelevant
  explain(event: Event): { source: string; rawEventId: string; confidence: string };
}
```

A compliant adapter must supply provenance: product/version, ingress surface, event timestamp source, transport source, observer location, account/device/session IDs (pseudonymized), correlation IDs and how scopes/approvals map to product semantics.

## Requirements

1. Never interpret a user-supplied `deviceId`, `role`, `scope`, or approval response as verified authority solely because it is in a packet.
2. Preserve distinction between *requested*, *approved*, *effective* and *executed* authority.
3. Map approval to an immutable canonical action representation; hash alone is not enough if canonicalization is ambiguous.
4. Record whether an operation is auto-allowed, human-approved, policy-approved or retried; current simulator only models human approval.
5. Represent disconnect, cancellation, timeout, revocation propagation and in-flight work in future schema versions.
6. Use mocked tools and benign sentinel files for local reproductions. Do not connect to a third-party service without permission.

## Initial candidates

| System | Channel class | Official source for future analysis | State |
| --- | --- | --- | --- |
| OpenClaw | Gateway WS / pairing | https://docs.openclaw.ai/gateway/protocol | not started |
| OpenCode | Local HTTP control | https://docs.opencode.ai/docs/server/ | not started |
| Claude Code Remote Control | Cloud-mediated, proprietary | https://code.claude.com/docs/en/remote-control | docs only; no adapter |
| Codex remote | Cloud-mediated, proprietary | user-supplied report; independent official source required | docs pending |
| Hermes Agent | IM gateway | vendor source/version pending confirmation | pending |

Cloud products may not expose enough observable internals for a trustworthy test oracle; record these as **not evaluable**, not safe or unsafe.

## Capture discipline

Safe initial method: self-hosted instance + test user + local loopback instrumentation + independently logged mock tool. Never store access tokens, pairing QR payload secrets or full conversation transcripts in Git.
