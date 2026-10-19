# PairTrace

**Tracing Trust Across Devices** · 跨设备 AI Agent 控制平面的安全研究框架

PairTrace is an early-stage, research-oriented framework for **cross-device AI agent control-plane security**. It studies how device pairing, delegation, human approval, session recovery, and revocation interact with the authority to execute actions on a host computer.

> **Status (2026-10-19):** v0 research scaffold with an **offline, synthetic JSONL trace checker**. No real product adapters, active scanning, exploited vulnerabilities, or formal proof are claimed.

## Research question / 研究问题

Can remote AI agent systems preserve **authorization integrity** through pairing, asynchronous execution, reconnects, and device revocation?

Three boundaries matter: **identity** (who/which device), **authority** (what was granted/approved), and **execution** (what actually ran, where, and when). A transport channel secured by TLS is not, by itself, an end-to-end authorization guarantee.

## Quick start / 快速开始

Requires **Node.js >= 22.16**. The prototype uses the built-in experimental TypeScript type stripper; no npm dependencies, cloud credentials, or target Agent installation are required.

```bash
git clone https://github.com/DrNbnonono/PairTrace.git
cd PairTrace
npm test
npm run demo
node --experimental-strip-types src/cli.ts fixtures/approval-mismatch.jsonl --json
```

The demo uses **synthetic data**. `--strict` causes the CLI to exit with code 2 when an offline policy violation is found.

## Architecture

```text
[Real agent / relay / IM channel]
          |  (future: approved, read-only, local adapters)
          v
  Canonical event JSONL  --->  Trace parser / validation
                                  |
                                  v
                          Stateful security oracle
                                  |
                                  v
                        JSON findings + provenance
```

### Implemented

- Canonical event schema: pairing request/approval, session open/close, action request/approval/execution, device revocation
- Stateful policy checks: request/nonce/expiry/scope binding, owner/approver binding, stale pairing generations, post-revocation actions, execution-to-approval binding
- Command-line offline analysis, small reproducible fixtures, unit tests and CI
- Threat model, evidence ledger, scope boundaries, adapter contract and experiment roadmap

### Not implemented

- OpenClaw/OpenCode/Hermes/Codex/Claude network adapters or real protocol message parsing
- Remote scanning, credential handling, exploitation or live Agent commands
- TLA+ specification, differential fuzzing, causal scheduler, benchmark baselines
- Assertions that any vendor has the demonstrated synthetic vulnerabilities

## Research materials

- [Research questions, falsifiable hypotheses and milestones](docs/RESEARCH_PLAN.md)
- [Threat model and normative assumptions](docs/THREAT_MODEL.md)
- [Related work and evidence confidence](docs/RELATED_WORK.md)
- [Agent comparison and verification ledger](docs/EVIDENCE_LEDGER.md)
- [Adapter specification](docs/PROTOCOL_ADAPTERS.md)
- [Experiment protocol and result criteria](docs/EXPERIMENTS.md)
- [Ethics and disclosure policy](docs/ETHICS.md)

## Scope and research integrity

Findings are **policy violations in supplied traces**, not proof of a security vulnerability in a real product. A violation becomes a vendor finding only after version-specific reproduction, documentation review, accurate trust-boundary modeling, and responsible disclosure.

Remote-access systems may intentionally allow persistent grants, administrator override or in-flight work after revocation. PairTrace's **strict immediate-revocation policy is a hypothesis**, not a universal industry requirement.

Contributions welcome through reproducible tests and reviewed documentation. No license has been selected yet; do not assume permission to reuse beyond applicable law.
