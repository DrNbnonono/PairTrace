import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../src/oracle.ts";
import { parseJsonl } from "../src/parser.ts";
import type { Event } from "../src/types.ts";

const valid: Event[] = [
  { type:"pair.requested", ts:1, userId:"alice", deviceId:"phone", requestId:"req1", nonce:"n1", requestedScopes:["tool.exec"], expiresAt:100 },
  { type:"pair.approved", ts:2, userId:"alice", deviceId:"phone", requestId:"req1", nonce:"n1", approverId:"alice", approvedScopes:["tool.exec"] },
  { type:"session.opened", ts:3, userId:"alice", deviceId:"phone", sessionId:"s1", scopes:["tool.exec"] },
  { type:"action.requested", ts:4, actionId:"a1", sessionId:"s1", tool:"fixture.noop", argsDigest:"sha256:fixture", requiredScope:"tool.exec" },
  { type:"action.approved", ts:5, actionId:"a1", sessionId:"s1", approverId:"alice", tool:"fixture.noop", argsDigest:"sha256:fixture" },
  { type:"action.executed", ts:6, actionId:"a1", sessionId:"s1", tool:"fixture.noop", argsDigest:"sha256:fixture" }
];
const rules = (events: Event[]) => analyze(events).map((f) => f.rule);

test("valid reference trace has no policy violations", () => {
  assert.deepEqual(analyze(valid), []);
});
test("execution after revocation is detected", () => {
  const trace = [...valid.slice(0, 5), { type:"device.revoked", ts:5.5, deviceId:"phone" } as Event, valid[5]!];
  assert.ok(rules(trace).includes("EXECUTION_AFTER_REVOCATION"));
});
test("approved operation is bound to exact executed arguments", () => {
  const changed = { ...valid[5]!, argsDigest:"sha256:different" } as Event;
  assert.ok(rules([...valid.slice(0, 5), changed]).includes("EXECUTION_BINDING_MISMATCH"));
});
test("cannot approve scopes beyond requested grant", () => {
  const wider = { ...valid[1]!, approvedScopes:["tool.exec", "admin"] } as Event;
  assert.ok(rules([valid[0]!, wider]).includes("PAIR_SCOPE_ESCALATION"));
});
test("expired pairing is rejected", () => {
  const late = { ...valid[1]!, ts:101 } as Event;
  assert.ok(rules([valid[0]!, late]).includes("PAIR_EXPIRED"));
});
test("wrong approver is rejected", () => {
  const wrong = { ...valid[4]!, approverId:"mallory" } as Event;
  const found = rules([...valid.slice(0, 4), wrong, valid[5]!]);
  assert.ok(found.includes("ACTION_APPROVER_MISMATCH"));
  assert.ok(found.includes("EXECUTION_WITHOUT_APPROVAL"));
});
test("a previous session stays stale after revoke and re-pair", () => {
  const newPair: Event[] = [
    { type:"device.revoked", ts:7, deviceId:"phone" },
    { type:"pair.requested", ts:8, userId:"alice", deviceId:"phone", requestId:"req2", nonce:"n2", requestedScopes:["tool.exec"], expiresAt:100 },
    { type:"pair.approved", ts:9, userId:"alice", deviceId:"phone", requestId:"req2", nonce:"n2", approverId:"alice", approvedScopes:["tool.exec"] },
    { type:"action.executed", ts:10, actionId:"a1", sessionId:"s1", tool:"fixture.noop", argsDigest:"sha256:fixture" }
  ];
  assert.ok(rules([...valid, ...newPair]).includes("STALE_SESSION_EPOCH"));
});
test("parser rejects unknown events and malformed fields", () => {
  assert.throws(() => parseJsonl('{"type":"bogus","ts":1}'), /Unknown event/);
  assert.throws(() => parseJsonl('{"type":"device.revoked","ts":1}'), /Invalid deviceId/);
  assert.equal(parseJsonl(JSON.stringify(valid[0]) + "\n").length, 1);
});
