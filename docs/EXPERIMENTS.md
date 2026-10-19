# Experiment protocol

## Seed trials

- **E0: valid baseline** — fixture `valid.jsonl` must produce zero findings.
- **E1: revoked controller** — `revoked.jsonl` must trigger `EXECUTION_AFTER_REVOCATION` under strict immediate-revocation baseline.
- **E2: authorization-to-execution binding** — `approval-mismatch.jsonl` must trigger `EXECUTION_BINDING_MISMATCH`.

These are **synthetic conformance cases**, *not* demonstrated vendor defects.\n\n## E3: source-pinned OpenClaw wire observer\n\n- `fixtures/openclaw/handshake.jsonl`: challenge, claimed connect and authoritative hello; no secrets leave the report.\n- `fixtures/openclaw/pending-pair.jsonl`: pairing resolution notice does not create admission.\n- `fixtures/openclaw/node-capability.jsonl`: node capability approval and device pairing are distinct.\n\nThese records mirror documented frame shapes but are **not live captures** and omit some fields required by the full upstream schema. They test the observer's behavior and inability to overclaim.

## Future controlled experiment format

Each run: experiment ID; tested product + exact version/commit; configuration; host OS; account/role matrix; hypothesis/property ID; complete intended event order; network conditions; observer points; JSONL trace; raw evidence hash; adapter version; outcome; false-positive review; issue/report reference.

## Evaluation metrics

- **Confirmed distinct root causes**, separately from raw anomaly count
- **Recall on reproduced historical advisories**, with revision boundaries and patches
- **Reproducibility**, measured by independent repeated controlled runs
- **Test efficiency**, trace sequences and time per confirmed root cause
- **False positive rate** under documented legitimate behavior
- **Cross-product transfer** of a test property, not blindly copied message syntax
- **Overhead** for mitigation and event-correlation instrumentation

Suggested baselines: random event-order mutation, grammar-aware protocol fuzzer, model-based sequence generator and AgentThread-style invariant replay **when a comparable implementation is available**.

## Evidence classification

`synthetic` != `reproduced historical bug` != `new candidate` != `vendor confirmed`. Preserve negative results and all rejected candidates; never count documentation ambiguity as an exploit.
