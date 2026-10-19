# OpenClaw Gateway real-protocol analysis / 真实协议分析 (M2, v0.2)

**Scope:** protocol-**aware offline observer**, not a live network probe or a completed empirical vulnerability study.

## Pinned, primary implementation evidence

Verified on 2026-10-19 against upstream OpenClaw **v2026.10.5**, annotated tag object `9171d0a427738902efd811c648325cf54116743c`, commit `1b58cb9a1b4f4353e1add63c8506db4d890962e8`.

- [Gateway frame schema](https://github.com/openclaw/openclaw/blob/v2026.10.5/packages/gateway-protocol/src/schema/frames.ts): `req` / `res` / `event` and `HelloOkSchema.auth`.
- [Handshake and roles](https://github.com/openclaw/openclaw/blob/v2026.10.5/docs/gateway/protocol/handshake.md): `connect.challenge`, `connect`, `hello-ok`, role/scope and device signature fields.
- [Transport / framing](https://github.com/openclaw/openclaw/blob/v2026.10.5/docs/gateway/protocol/transport.md): WS JSON frame envelopes.
- [Device identity and pairing](https://github.com/openclaw/openclaw/blob/v2026.10.5/docs/gateway/protocol/auth.md): token/device pairing, pre-admission `device.pair.resolved` semantics.
- [Node pairing](https://github.com/openclaw/openclaw/blob/v2026.10.5/docs/gateway/pairing.md): node capability approval is distinct from device pairing. Pending node capability approvals are **not** the same as the five-minute-expiring device pairing request.

The upstream docs changed during 2026. Our study must not mix older claims that `node.pair.request` or `node.pair.verify` are current RPCs; v2026.10.5 documents their removal in July 2026.

## Observed (schema-grounded) handshake

```text
 Gateway                               Controller (phone/UI/node)
    |-- event: connect.challenge -------------------------->|
    |<--------------------------- req: connect (role/scopes, device, auth)
    |-- res: hello-ok {auth.role, auth.scopes} ------------>| admitted
              OR
    |-- res: NOT_PAIRED {PAIRING_REQUIRED} ---------------->| not admitted
    |-- event: device.pair.resolved (for waiting client) -->| notice only
    |<--------------------------- new authenticated connect| necessary
```

A device's `connect.params.role` and `scopes` are **client declarations**.
The Gateway's successful `hello-ok.auth` is the observable negotiated authorization. Neither grants unrestricted tool execution. A pairing-resolution event is not a successful admission. A capability approval `node.pair.*` does not imply a device grant or the right to bypass node-local command approvals.

## New interface

```bash
npm run gateway:demo
npm run gateway:pending
npm run gateway:capability
node --experimental-strip-types src/cli-gateway.ts fixtures/openclaw/handshake.jsonl --json
```

Each capture JSONL begins with explicit provenance:

```json
{"kind":"capture.header","product":"openclaw","version":"2026.10.5","origin":"authorized-local-lab","observer":"gateway-side"}
```

Each subsequent record wraps a real WS frame (or a doc-derived fake frame):

```json
{"ts":1,"connection":"lab-local","direction":"gateway->client","frame":{"type":"event","event":"connect.challenge","payload":{"nonce":"REDACTED"}}}
```

For real capture, **do not replace the live nonce before analysis** if nonce matching is to be tested; keep the input file private and ephemeral, and publish only PairTrace's redacted output. The adapter compares nonce values in volatile memory, never outputs their contents. A replacement/redacted nonce makes the nonce-consistency check invalid.

To obtain real evidence, deploy the exact pinned release on an **isolated, owned, loopback-only** lab machine, use a disposable account and controlled pairing, and instrument the **trusted Gateway side** or a consented local test-client WS debug tap. Export only the needed envelope fields. Capture client/server origin explicitly; do not infer authorization from client-supplied values. Pair server-side trace with separate mocked tool execution logs before making execution-integrity claims.

The test fixtures checked into Git are **doc-derived synthetic examples**, not packets observed from a running OpenClaw instance. Their `snapshot: {}` is abbreviated and would not pass the full upstream `HelloOkSchema` validator: these fixtures test the **observer projection**, not upstream end-to-end protocol conformance.

## Output categories

- `connect.challenge` — server nonce issued, sensitive value excluded from output.
- `connect.request` — client-declared identity/scope, **not** authorization.
- `connect.hello (admitted_by_gateway)` — matched successful response with the server's effective authorization; not a tool-execution assertion.
- `connect.rejected` — failed handshake, including pending device pairing.
- `device.pair.resolved` — outcome notification, no implicit admission.
- `node.capability.requested` / `node.capability.resolved` — independent command-surface approval state.
- `rpc.response` — response accepted/rejected, **not** proof that any tool action happened.

Security review items are merely **observational discrepancies** (e.g. missing challenge capture, mismatched nonce, unexpected preauth success). The auditor must check that the log is complete, that the actual Gateway enforced policy, and that the outcome is beyond the official trust model. The observer does not verify crypto, signed client identity, device grant status, a command's operating-system effects, or revocation timing.

## What is still missing (M2 acceptance gap)

1. No **real local Gateway capture** has been produced yet in this repo or verified against a running instance.
2. No operator/device identity verification from a trusted DB/logging plane.
3. No event-to-action causal proof; hello and RPC response alone are insufficient.
4. Node capability approval events may be scoped to particular audiences; a client-side capture cannot treat absent events as absent state.
5. No public network discovery, no deployed-system claim, no disclosed new vulnerability.

**Next:** local pinned deployment → authorized trace of device pairing/hello/re-pair → trusted state snapshot → mock node command → safe, independently verified observation chain.
