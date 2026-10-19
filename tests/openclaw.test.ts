import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeOpenClawWire, parseOpenClawCapture } from "../src/adapters/openclaw.ts";
import type { OpenClawCapture } from "../src/adapters/openclaw.ts";

const good = (): OpenClawCapture =>
  parseOpenClawCapture(readFileSync("fixtures/openclaw/handshake.jsonl", "utf8"));
const report = (capture: OpenClawCapture) => analyzeOpenClawWire(capture);
const codes = (capture: OpenClawCapture) => report(capture).review.map((x) => x.code);

test("document-shape Gateway handshake projects to admitted only after server hello", () => {
  const full = good();
  const before = report({ ...full, frames: full.frames.slice(0, 2) });
  assert.equal(before.observations.some((o) => o.status === "admitted_by_gateway"), false);
  const after = report(full);
  assert.equal(after.observations.at(-1)?.status, "admitted_by_gateway");
  assert.equal(after.review.length, 0);
});
test("raw token, signature, device ID and nonce never appear in report", () => {
  const encoded = JSON.stringify(report(good()));
  for (const secret of ["FAKE_TOKEN_SHOULD_NOT_APPEAR", "FAKE_SIGNED_NONCE", "FAKE_DEVICE_ID", "FAKE_SIGNATURE"])
    assert.equal(encoded.includes(secret), false);
});
test("missing server challenge is only flagged as incomplete observation", () => {
  const input = good();
  const withoutChallenge = { ...input, frames: input.frames.slice(1) };
  assert.ok(codes(withoutChallenge).includes("CHALLENGE_NOT_OBSERVED"));
});
test("nonce mismatch is detectable from reference wire frames without signature verification", () => {
  const cap = good();
  const connect = cap.frames[1]!.frame;
  const params = connect.params as Record<string, unknown>;
  const wrong = { ...cap, frames: cap.frames.map((e, i) =>
    i === 1 ? { ...e, frame: { ...connect, params: { ...params, device: { ...(params.device as object), nonce: "not-the-challenge" } } } } : e) };
  assert.ok(codes(wrong).includes("CHALLENGE_NONCE_MISMATCH"));
});
test("pairing resolution event never authorizes socket", () => {
  const cap = parseOpenClawCapture(readFileSync("fixtures/openclaw/pending-pair.jsonl", "utf8"));
  const result = report(cap);
  assert.equal(result.observations.some((o) => o.status === "admitted_by_gateway"), false);
  assert.equal(result.observations.at(-1)?.kind, "device.pair.resolved");
});
test("node capability event is not device pairing authorization", () => {
  const cap = parseOpenClawCapture(readFileSync("fixtures/openclaw/node-capability.jsonl", "utf8"));
  const kinds = report(cap).observations.map((x) => x.kind);
  assert.ok(kinds.includes("node.capability.requested"));
  assert.ok(kinds.includes("node.capability.resolved"));
  assert.equal(kinds.includes("device.pair.resolved"), false);
});
test("preauth ok RPC response creates review only; no execution claim", () => {
  const base = good();
  base.frames.push(
    { ts: 4, connection: "new-socket", direction:"client->gateway", frame:{ type:"req", id:"req-x", method:"node.invoke", params:{ command:"NEVER_LOG_THIS" } } },
    { ts: 5, connection: "new-socket", direction:"gateway->client", frame:{ type:"res", id:"req-x", ok:true, payload:{ message:"ALSO_NEVER_LOG_THIS" } } }
  );
  const r = report(base);
  assert.ok(r.review.some((x) => x.code === "PREAUTH_RPC_RESPONSE"));
  assert.equal(JSON.stringify(r).includes("NEVER_LOG_THIS"), false);
  assert.equal(JSON.stringify(r).includes("ALSO_NEVER_LOG_THIS"), false);
});
test("parser rejects unknown capture header and malformed raw envelope", () => {
  assert.throws(() => parseOpenClawCapture('{"kind":"capture.header","product":"other"}\n{}'), /Invalid OpenClaw capture header/);
  const header = '{"kind":"capture.header","product":"openclaw","version":"2026.10.5","origin":"doc-derived-synthetic","observer":"gateway-side"}';
  assert.throws(() => parseOpenClawCapture(header + '\n{"ts":1,"connection":"x","direction":"gateway->client","frame":{"type":"garbage"}}'), /Invalid frame envelope/);
});
test("an unknown wire method name is classified without echoing it", () => {
  const cap = good();
  cap.frames.push({ts:99,connection:"lab-1",direction:"client->gateway",frame:{type:"req",id:"new",method:"LEAK_ME",params:{token:"LEAK_ME"}}});
  const result = report(cap);
  assert.equal(result.observations.at(-1)?.kind, "other.request");
  assert.equal(JSON.stringify(result).includes("LEAK_ME"), false);
});
