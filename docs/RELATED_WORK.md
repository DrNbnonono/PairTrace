# Related work — initial reading map

Provenance: starting list from the user's attached Claude research report (2026-10-19), supplemented by three directly checked public sources below. **A** = direct paper/official document inspected for relevant claims; **B** = supplied report's secondary/unverified lead. No completeness claim.

| Work | Relevance | Evidence | Link |
| --- | --- | --- | --- |
| AgentThread — Formal Security Analysis of Agent Protocol Composition (2026) | specification-linked invariants, TLA+ and SDK replay; **direct method competitor** | A (abstract) | https://arxiv.org/abs/2606.28690 |
| Demystifying the (In)Security of QR Code-based Login (USENIX 2025) | QR pairing taxonomy, 6 design flaw classes, real-world deployment study | A (publisher page) | https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-xin |
| OpenClaw Gateway protocol / pairing | actual WS control-plane terminology, roles and device pairing | A (official docs) | https://docs.openclaw.ai/gateway/protocol |
| AgentRFC (2026) | principled conformance testing for agent protocols | B | https://arxiv.org/abs/2603.23801 |
| Loopjacking (2026) | approval-to-execution integrity hypothesis | B | https://arxiv.org/abs/2609.21081 |
| Your IoTs Are (Not) Mine (DSN 2019) | analogous remote device binding failures | B | search primary venue |
| BeyondTrust: WHAM, Bam (2026) | agent relay abuse case study; verify official source | B in this repo | search primary vendor blog |
| OpenClaw vulnerability taxonomy (2026) | taxonomy, not substitute for protocol-level mechanism | B | https://arxiv.org/abs/2603.27517 |

**Required before writing a related-work section:** read full original methods, identify exact analyzed protocol versions and security properties, assess overlap/novelty, and verify all numerical claims at primary sources. Search results or a pasted report alone do not establish nonexistence of competing work.
