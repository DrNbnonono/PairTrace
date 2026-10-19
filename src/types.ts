/** Canonical normalized events. These are NOT wire frames from any named vendor. */
export interface BaseEvent { type: string; ts: number; }
export interface PairRequested extends BaseEvent {
  type: "pair.requested"; userId: string; deviceId: string; requestId: string;
  nonce: string; requestedScopes: string[]; expiresAt: number;
}
export interface PairApproved extends BaseEvent {
  type: "pair.approved"; userId: string; deviceId: string; requestId: string;
  nonce: string; approverId: string; approvedScopes: string[];
}
export interface SessionOpened extends BaseEvent {
  type: "session.opened"; userId: string; deviceId: string;
  sessionId: string; scopes: string[];
}
export interface SessionClosed extends BaseEvent {
  type: "session.closed"; sessionId: string;
}
export interface ActionRequested extends BaseEvent {
  type: "action.requested"; actionId: string; sessionId: string;
  tool: string; argsDigest: string; requiredScope: string;
}
export interface ActionApproved extends BaseEvent {
  type: "action.approved"; actionId: string; sessionId: string;
  approverId: string; tool: string; argsDigest: string;
}
export interface ActionExecuted extends BaseEvent {
  type: "action.executed"; actionId: string; sessionId: string;
  tool: string; argsDigest: string;
}
export interface DeviceRevoked extends BaseEvent {
  type: "device.revoked"; deviceId: string;
}
export type Event = PairRequested | PairApproved | SessionOpened | SessionClosed
  | ActionRequested | ActionApproved | ActionExecuted | DeviceRevoked;
export interface Finding {
  index: number;
  ts: number;
  rule: string;
  severity: "policy_violation" | "needs_review";
  message: string;
}
