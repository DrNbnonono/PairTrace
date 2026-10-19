# PairTrace research plan (2026-10-19)

## Research framing

**Working title:** PairTrace: Towards Stateful Authorization-Integrity Analysis of Cross-Device AI Agent Control Planes.

**Central question:** When a person controls a long-running local AI agent from another device, do authentication, device grants, approvals and actual tool execution preserve the intended authority across transitions?

**Null hypothesis:** Common remote-control implementations already enforce lifecycle binding adequately; reported issues are configuration mistakes or familiar bugs. We must allow research to falsify our thesis.

## Candidate research questions

- **RQ1 / Measurement:** Which trust boundaries and authorization models are documented by each product? Local gateway vs cloud relay vs IM bridge.
- **RQ2 / Security:** Can differences between device grants, live session scope, user approval, and actual execution be triggered by lifecycle transitions?
- **RQ3 / Method:** Does causality-aware sequence generation outperform naive message mutation or random stateful testing at finding *new classes* of errors?
- **RQ4 / Mitigation:** Can authorization provenance and epoch-bound approval reduce errors without disrupting legitimate resumed work?

## Distinctiveness requirements

AgentThread (arXiv:2606.28690) already combines specification-linked invariants, formal models and executable replay against SDKs. QRLogin (USENIX Security 2025) already develops cross-device QR login flaws. A project that only imports these methods or reproduces OpenClaw CVEs is **not** a sufficient research contribution.

A viable differentiation needs at least one: temporal authorization provenance across real task execution; reusable high-fidelity adapters across *independently designed* systems; a new sequence-generation/oracle technique; or a validated mitigation for the cross-device/Agent-specific lifecycle.

## Milestones / go-no-go

| Phase | Deliverable | Gate |
| --- | --- | --- |
| M0 | Evidence ledger, consent/ethics rules, initial simulator | No unsupported vulnerability claims |
| M1 | Protocol/state mapping for >=2 systems | Explicit user/device/session/scope semantics |
| M2 | Independent historical-bug reproduction in isolated versions | Accurate ground truth and baseline |
| M3 | Adapter + stateful generation + differential baseline | Reproducible advantage over random/event fuzz |
| M4 | New root cause(s) across products OR a strong generalizable result | Novelty independently assessed |
| M5 | Fix/mitigation and ablation/performance evaluation | Actionable and measurable contributions |

**Stop or pivot** if M1/M2 show no material lifecycle gap, if M3 provides no advantage, or if related work already directly covers the claim.

## Evaluation checklist

Protocol diversity, deployment/version pinning, oracle false positives, ground-truth handling, missing events, concurrent controllers, clock skew, cancellation semantics, security disclosures, benchmark reproducibility, negative results, and cost per discovered unique root cause.

Target datasets must be collected **only** from owned or explicitly authorized systems.
