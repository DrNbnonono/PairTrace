import type { Event } from "./types.ts";

const fields: Record<string, string[]> = {
  "pair.requested": ["userId", "deviceId", "requestId", "nonce", "requestedScopes", "expiresAt"],
  "pair.approved": ["userId", "deviceId", "requestId", "nonce", "approverId", "approvedScopes"],
  "session.opened": ["userId", "deviceId", "sessionId", "scopes"],
  "session.closed": ["sessionId"],
  "action.requested": ["actionId", "sessionId", "tool", "argsDigest", "requiredScope"],
  "action.approved": ["actionId", "sessionId", "approverId", "tool", "argsDigest"],
  "action.executed": ["actionId", "sessionId", "tool", "argsDigest"],
  "device.revoked": ["deviceId"]
};
const arrayFields = new Set(["requestedScopes", "approvedScopes", "scopes"]);

export function parseJsonl(input: string): Event[] {
  const out: Event[] = [];
  for (const [lineNo, line] of input.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    let record: unknown;
    try { record = JSON.parse(trimmed); }
    catch { throw new Error("Invalid JSON at line " + (lineNo + 1)); }
    if (record === null || typeof record !== "object" || Array.isArray(record))
      throw new Error("Expected object at line " + (lineNo + 1));
    const r = record as Record<string, unknown>;
    if (typeof r.type !== "string" || !(r.type in fields))
      throw new Error("Unknown event type at line " + (lineNo + 1));
    if (typeof r.ts !== "number" || !Number.isFinite(r.ts))
      throw new Error("Invalid ts at line " + (lineNo + 1));
    for (const key of fields[r.type]!) {
      const value = r[key];
      if (arrayFields.has(key)) {
        if (!Array.isArray(value) || !value.every((v) => typeof v === "string"))
          throw new Error("Invalid " + key + " at line " + (lineNo + 1));
      } else if (key === "expiresAt") {
        if (typeof value !== "number" || !Number.isFinite(value))
          throw new Error("Invalid expiresAt at line " + (lineNo + 1));
      } else if (typeof value !== "string" || value.length === 0) {
        throw new Error("Invalid " + key + " at line " + (lineNo + 1));
      }
    }
    out.push(r as unknown as Event);
  }
  return out;
}
