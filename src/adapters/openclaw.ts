/**
 * OpenClaw Gateway wire-frame OBSERVER, pinned to upstream v2026.10.5.
 * Input: authenticated operator's own local, consented WS trace.
 * Output: minimal redacted observations; NEVER returns raw params, tokens,
 * device identifiers, request IDs, nonces, messages, or tool arguments.
 *
 * This is intentionally not the synthetic authorization oracle. A connect
 * request is only a CLAIM; a successful server hello is authorization evidence.
 */
export const OPENCLAW_SOURCE = Object.freeze({
  tag: "v2026.10.5",
  commit: "1b58cb9a1b4f4353e1add63c8506db4d890962e8",
  frameSchema: "packages/gateway-protocol/src/schema/frames.ts",
  url: "https://github.com/openclaw/openclaw/tree/v2026.10.5"
});

export type Direction = "client->gateway" | "gateway->client";
export type CaptureOrigin = "doc-derived-synthetic" | "authorized-local-lab" | "historical-replay";
export interface CaptureHeader {
  kind: "capture.header";
  product: "openclaw";
  version: string;
  origin: CaptureOrigin;
  observer: "gateway-side" | "client-side" | "trusted-proxy";
}
export interface CaptureFrame {
  ts: number;
  connection: string;
  direction: Direction;
  frame: Record<string, unknown>;
}
export interface OpenClawCapture {
  header: CaptureHeader;
  frames: CaptureFrame[];
}
export interface WireObservation {
  index: number;
  connection: string; // ephemeral alias c1/c2 only
  kind: string;        // controlled classification only, NOT verbatim method/event
  status?: string;     // controlled classification only
}
export interface WireReview {
  index: number;
  connection: string;
  code: string;
  explanation: string;
}
export interface WireReport {
  schema: string;
  origin: CaptureOrigin;
  observer: CaptureHeader["observer"];
  frames: number;
  observations: WireObservation[];
  review: WireReview[];
  limitations: string[];
}

function object(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown> : undefined;
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length ? v : undefined;
}
function strings(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? v : undefined;
}
const origins = new Set<CaptureOrigin>(["doc-derived-synthetic", "authorized-local-lab", "historical-replay"]);
const observers = new Set<CaptureHeader["observer"]>(["gateway-side", "client-side", "trusted-proxy"]);
const knownMethods: Record<string, string> = {
  "connect": "connect.request",
  "device.pair.list": "device.pair.list",
  "device.pair.approve": "device.pair.approve",
  "device.pair.reject": "device.pair.reject",
  "device.token.revoke": "device.token.revoke",
  "device.token.rotate": "device.token.rotate",
  "node.pair.list": "node.capability.list",
  "node.pair.approve": "node.capability.approve",
  "node.pair.reject": "node.capability.reject",
  "node.pair.remove": "node.role.remove",
  "node.invoke": "node.invoke.request",
  "exec.approval.resolve": "exec.approval.resolve"
};
const knownEvents: Record<string, string> = {
  "connect.challenge": "connect.challenge",
  "device.pair.resolved": "device.pair.resolved",
  "device.pair.requested": "device.pair.requested",
  "node.pair.requested": "node.capability.requested",
  "node.pair.resolved": "node.capability.resolved",
  "exec.approval.requested": "exec.approval.requested",
  "exec.approval.resolved": "exec.approval.resolved"
};
const knownErrorCodes = new Set(["PAIRING_REQUIRED", "AUTH_SCOPE_MISMATCH", "AUTH_TOKEN_MISMATCH", "OPERATOR_ACCESS_DENIED", "DEVICE_AUTH_NONCE_REQUIRED", "DEVICE_AUTH_NONCE_MISMATCH", "DEVICE_AUTH_SIGNATURE_INVALID", "DEVICE_AUTH_SIGNATURE_EXPIRED", "NOT_PAIRED"]);
const failures = new Set(["PAIRING_REQUIRED", "AUTH_SCOPE_MISMATCH", "AUTH_TOKEN_MISMATCH"]);

export function parseOpenClawCapture(input: string): OpenClawCapture {
  const lines = input.split(/\r?\n/).map((x) => x.trim()).filter((x) => x.length > 0);
  if (lines.length < 2 || lines.length > 50001) throw new Error("Expected header plus 1..50000 captured frames");
  let headerRaw: unknown;
  try { headerRaw = JSON.parse(lines[0]!); } catch { throw new Error("Malformed capture header JSON"); }
  const h = object(headerRaw);
  if (!h || h.kind !== "capture.header" || h.product !== "openclaw" ||
      typeof h.version !== "string" || h.version.length > 64 ||
      !origins.has(h.origin as CaptureOrigin) || !observers.has(h.observer as CaptureHeader["observer"]))
    throw new Error("Invalid OpenClaw capture header");
  const frames: CaptureFrame[] = [];
  for (let i = 1; i < lines.length; i++) {
    let raw: unknown;
    try { raw = JSON.parse(lines[i]!); } catch { throw new Error("Malformed frame JSON at line " + (i + 1)); }
    const v = object(raw);
    const frame = object(v?.frame);
    if (!v || typeof v.ts !== "number" || !Number.isFinite(v.ts) ||
        typeof v.connection !== "string" || !v.connection || v.connection.length > 128 ||
        (v.direction !== "client->gateway" && v.direction !== "gateway->client") ||
        !frame || !["req", "res", "event"].includes(String(frame.type)))
      throw new Error("Invalid frame envelope at line " + (i + 1));
    frames.push({ ts: v.ts, connection: v.connection, direction: v.direction as Direction, frame });
  }
  return { header: h as unknown as CaptureHeader, frames };
}

interface ConnectionState {
  alias: string;
  challenge?: string;
  connectId?: string;
  requestedRole?: string;
  requestedScopes?: string[];
  admitted: boolean;
  waitingForPair: boolean;
  outstanding: Map<string, { method: string; preAuth: boolean }>;
}
export function analyzeOpenClawWire(capture: OpenClawCapture): WireReport {
  const observations: WireObservation[] = [];
  const review: WireReview[] = [];
  const connections = new Map<string, ConnectionState>();
  const observe = (index: number, s: ConnectionState, kind: string, status?: string) =>
    observations.push({ index, connection: s.alias, kind, ...(status ? { status } : {}) });
  const warn = (index: number, s: ConnectionState, code: string, explanation: string) =>
    review.push({ index, connection: s.alias, code, explanation });

  capture.frames.forEach(({ connection, direction, frame }, index) => {
    let state = connections.get(connection);
    if (!state) {
      state = { alias: "c" + (connections.size + 1), admitted: false, waitingForPair: false, outstanding: new Map() };
      connections.set(connection, state);
    }
    const s = state;
    const type = frame.type;
    if ((direction === "client->gateway" && type !== "req") ||
        (direction === "gateway->client" && type === "req"))
      warn(index, s, "DIRECTION_UNEXPECTED", "The frame direction differs from the reference WS request/response/event transport.");
    if (type === "event") {
      const event = str(frame.event);
      const kind = event ? (knownEvents[event] ?? "other.event") : "other.event";
      if (event === "connect.challenge") {
        const payload = object(frame.payload);
        s.challenge = str(payload?.nonce);
        if (!s.challenge) warn(index, s, "CHALLENGE_INCOMPLETE", "Challenge nonce was not observable.");
      }
      if (event === "device.pair.resolved") {
        // A pre-auth pairing resolution is a notification, NOT admission.
        const payload = object(frame.payload);
        const decision = str(payload?.decision);
        observe(index, s, kind, ["approved", "rejected", "expired"].includes(decision ?? "") ? decision : "unknown");
        return;
      }
      if (event === "node.pair.resolved") {
        observe(index, s, kind, "capability_only");
        return;
      }
      observe(index, s, kind);
      return;
    }
    if (type === "req") {
      const method = str(frame.method);
      const id = str(frame.id);
      const kind = method ? (knownMethods[method] ?? "other.request") : "other.request";
      if (!id) { warn(index, s, "REQUEST_ID_MISSING", "Cannot correlate request without id."); return; }
      if (s.outstanding.has(id)) warn(index, s, "REQUEST_ID_REUSED", "Request id reused while outstanding.");
      s.outstanding.set(id, { method: kind, preAuth: !s.admitted });
      if (method === "connect") {
        const params = object(frame.params);
        const device = object(params?.device);
        s.connectId = id;
        s.requestedRole = str(params?.role);
        s.requestedScopes = strings(params?.scopes);
        if (!s.challenge) {
          warn(index, s, "CHALLENGE_NOT_OBSERVED", "Missing preceding challenge in the capture; a capture gap is possible.");
        } else if (str(device?.nonce) !== s.challenge) {
          warn(index, s, "CHALLENGE_NONCE_MISMATCH", "Captured connect nonce differs from server challenge; no cryptographic signature verification performed.");
        }
        observe(index, s, kind, device ? "device_identity_claimed" : "device_identity_absent");
      } else if (!s.admitted) {
        warn(index, s, "REQUEST_BEFORE_ADMISSION", "A non-connect RPC was observed before successful hello; server acceptance is unknown.");
        observe(index, s, kind, "pre_admission");
      } else {
        observe(index, s, kind);
      }
      return;
    }
    const id = str(frame.id);
    const req = id ? s.outstanding.get(id) : undefined;
    const payload = object(frame.payload);
    const isHello = frame.ok === true && payload?.type === "hello-ok";
    if (!req) {
      if (isHello) warn(index, s, "UNCORRELATED_HELLO", "Successful hello has no captured matching request.");
      observe(index, s, isHello ? "connect.hello" : "other.response", "uncorrelated");
      return;
    }
    s.outstanding.delete(id!);
    if (req.method === "connect.request") {
      if (isHello) {
        const auth = object(payload?.auth);
        const grantedRole = str(auth?.role);
        const effectiveScopes = strings(auth?.scopes);
        if (!auth || !grantedRole || !effectiveScopes)
          warn(index, s, "HELLO_AUTH_INCOMPLETE", "Successful hello lacks expected negotiated authorization metadata.");
        if (s.requestedRole && grantedRole && s.requestedRole !== grantedRole)
          warn(index, s, "NEGOTIATED_ROLE_DIFFERS", "Server effective role differs from client's requested role; review policy.");
        if (s.requestedScopes && effectiveScopes && effectiveScopes.some((v) => !s.requestedScopes!.includes(v)))
          warn(index, s, "NEGOTIATED_SCOPE_DIFFERS", "Server effective scopes extend beyond client's declared scopes; review server semantics.");
        s.admitted = true;
        s.waitingForPair = false;
        observe(index, s, "connect.hello", "admitted_by_gateway");
      } else {
        const error = object(frame.error);
        const details = object(error?.details);
        const code = str(details?.code);
        s.admitted = false;
        s.waitingForPair = failures.has(code ?? "") && code === "PAIRING_REQUIRED" && details?.waitForResolution === true;
        observe(index, s, "connect.rejected", knownErrorCodes.has(code ?? "") ? code! : "other_error");
      }
    } else {
      observe(index, s, "rpc.response", frame.ok === true ? "accepted_response" : "rejected_response");
      if (req.preAuth && frame.ok === true)
        warn(index, s, "PREAUTH_RPC_RESPONSE", "Gateway returned ok for an RPC observed before session admission; requires end-to-end verification.");
    }
  });
  return {
    schema: "OpenClaw " + OPENCLAW_SOURCE.tag,
    origin: capture.header.origin,
    observer: capture.header.observer,
    frames: capture.frames.length,
    observations,
    review,
    limitations: [
      "Capture frames may be incomplete or asserted by a client; pair this with gateway-side evidence.",
      "Signatures, device keys, Token validity, RPC side effects, tool execution and revocation propagation are NOT verified.",
      "Server-accepted hello is handshake authorization evidence, not proof of arbitrary tool permissions.",
      "Node capability approvals are separate from device pairing; RPC ok is not execution proof.",
      "Review flags are capture/policy discrepancies and are NOT vulnerability findings."
    ]
  };
}
