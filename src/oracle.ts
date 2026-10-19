import type { Event, Finding, PairRequested, ActionRequested } from "./types.ts";

/**
 * Reference policy for normalized, trusted-observer timestamps.
 * Reports mismatches in offline traces; does not assert a real product vulnerability.
 */
export function analyze(events: readonly Event[]): Finding[] {
  const findings: Finding[] = [];
  const requests = new Map<string, PairRequested>();
  const usedNonces = new Set<string>();
  const devices = new Map<string, { userId: string; scopes: Set<string>; epoch: number; revoked: boolean }>();
  const sessions = new Map<string, { deviceId: string; userId: string; scopes: Set<string>; epoch: number; closed: boolean }>();
  const actions = new Map<string, { request: ActionRequested; approved: boolean }>();
  const emit = (index: number, event: Event, rule: string, message: string, severity: Finding["severity"] = "policy_violation") => {
    findings.push({ index, ts: event.ts, rule, severity, message });
  };
  const subset = (candidate: string[], allowed: ReadonlySet<string>) => candidate.every((s) => allowed.has(s));

  events.forEach((e, i) => {
    switch (e.type) {
      case "pair.requested": {
        if (requests.has(e.requestId)) {
          emit(i, e, "DUPLICATE_PAIR_REQUEST", "Reused requestId: " + e.requestId);
          break;
        }
        requests.set(e.requestId, e);
        break;
      }
      case "pair.approved": {
        const request = requests.get(e.requestId);
        if (!request) {
          emit(i, e, "PAIR_REQUEST_MISSING", "Approval has no preceding request"); break;
        }
        let ok = true;
        if (request.userId !== e.userId || request.deviceId !== e.deviceId || request.nonce !== e.nonce) {
          emit(i, e, "PAIR_BINDING_MISMATCH", "Approval does not bind the original user/device/nonce"); ok = false;
        }
        if (e.approverId !== request.userId) {
          emit(i, e, "PAIR_APPROVER_MISMATCH", "Approver is not the owner under the strict reference policy"); ok = false;
        }
        if (e.ts > request.expiresAt) {
          emit(i, e, "PAIR_EXPIRED", "Approval occurs after request expiry"); ok = false;
        }
        if (usedNonces.has(e.nonce)) {
          emit(i, e, "PAIR_NONCE_REPLAY", "Previously approved nonce was reused"); ok = false;
        }
        if (!subset(e.approvedScopes, new Set(request.requestedScopes))) {
          emit(i, e, "PAIR_SCOPE_ESCALATION", "Approved scopes exceed requested scopes"); ok = false;
        }
        if (ok) {
          const previous = devices.get(e.deviceId);
          devices.set(e.deviceId, {
            userId: e.userId, scopes: new Set(e.approvedScopes),
            epoch: (previous?.epoch ?? 0) + 1, revoked: false
          });
          usedNonces.add(e.nonce);
          requests.delete(e.requestId);
        }
        break;
      }
      case "session.opened": {
        if (sessions.has(e.sessionId)) {
          emit(i, e, "DUPLICATE_SESSION_ID", "sessionId already exists"); break;
        }
        const device = devices.get(e.deviceId);
        if (!device || device.revoked) {
          emit(i, e, "SESSION_WITHOUT_ACTIVE_PAIR", "Session opened without active device pairing"); break;
        }
        if (device.userId !== e.userId) {
          emit(i, e, "SESSION_OWNER_MISMATCH", "Session user differs from paired user"); break;
        }
        if (!subset(e.scopes, device.scopes)) {
          emit(i, e, "SESSION_SCOPE_ESCALATION", "Session scopes exceed device grant"); break;
        }
        sessions.set(e.sessionId, {
          deviceId: e.deviceId, userId: e.userId, scopes: new Set(e.scopes), epoch: device.epoch, closed: false
        });
        break;
      }
      case "session.closed": {
        const session = sessions.get(e.sessionId);
        if (!session) emit(i, e, "UNKNOWN_SESSION", "Close refers to unknown session", "needs_review");
        else session.closed = true;
        break;
      }
      case "action.requested": {
        if (actions.has(e.actionId)) {
          emit(i, e, "DUPLICATE_ACTION_ID", "actionId already exists"); break;
        }
        const session = sessions.get(e.sessionId);
        if (!session) {
          emit(i, e, "UNKNOWN_SESSION", "Action request refers to unknown session"); break;
        }
        const device = devices.get(session.deviceId);
        if (session.closed || !device || device.revoked || device.epoch !== session.epoch)
          emit(i, e, "STALE_ACTION_REQUEST", "Action requested on closed/revoked/stale session");
        if (!session.scopes.has(e.requiredScope))
          emit(i, e, "ACTION_SCOPE_NOT_GRANTED", "Requested tool scope is absent from session");
        actions.set(e.actionId, { request: e, approved: false });
        break;
      }
      case "action.approved": {
        const action = actions.get(e.actionId);
        if (!action) {
          emit(i, e, "APPROVAL_WITHOUT_ACTION", "Approval has no known action"); break;
        }
        const session = sessions.get(action.request.sessionId);
        let ok = true;
        if (action.request.sessionId !== e.sessionId || action.request.tool !== e.tool || action.request.argsDigest !== e.argsDigest) {
          emit(i, e, "APPROVAL_BINDING_MISMATCH", "Approval does not match session/tool/arguments"); ok = false;
        }
        if (!session || e.approverId !== session.userId) {
          emit(i, e, "ACTION_APPROVER_MISMATCH", "Approver does not match session owner"); ok = false;
        }
        if (action.approved) {
          emit(i, e, "DUPLICATE_APPROVAL", "Action already approved"); ok = false;
        }
        if (ok) action.approved = true;
        break;
      }
      case "action.executed": {
        const action = actions.get(e.actionId);
        if (!action) {
          emit(i, e, "EXECUTION_WITHOUT_ACTION", "Execution has no known action"); break;
        }
        const session = sessions.get(action.request.sessionId);
        if (action.request.sessionId !== e.sessionId || action.request.tool !== e.tool || action.request.argsDigest !== e.argsDigest)
          emit(i, e, "EXECUTION_BINDING_MISMATCH", "Executed session/tool/arguments differ from the requested action");
        if (!action.approved)
          emit(i, e, "EXECUTION_WITHOUT_APPROVAL", "No matching owner approval precedes execution");
        if (session) {
          const device = devices.get(session.deviceId);
          if (session.closed) emit(i, e, "EXECUTION_AFTER_CLOSE", "Executed after session closed");
          if (!device || device.revoked) emit(i, e, "EXECUTION_AFTER_REVOCATION", "Executed after device grant revoked");
          else if (device.epoch !== session.epoch)
            emit(i, e, "STALE_SESSION_EPOCH", "Old session reused after re-pairing");
          if (!session.scopes.has(action.request.requiredScope))
            emit(i, e, "EXECUTION_SCOPE_NOT_GRANTED", "Execution requires a scope absent from the session");
        }
        break;
      }
      case "device.revoked": {
        const device = devices.get(e.deviceId);
        if (!device) emit(i, e, "UNKNOWN_DEVICE", "Revocation refers to unknown device", "needs_review");
        else device.revoked = true;
        break;
      }
    }
  });
  return findings;
}
