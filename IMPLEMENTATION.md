# Securing Agentic AI Workflows on Azure + Kubernetes

Implementation plan for hardening AI agent workloads deployed on Azure and Kubernetes (AKS or self-managed). Options given per phase where architecture choice depends on team maturity, budget, existing platform.

Repo cross-refs use tool/framework names from [README.md](README.md).

---

## Phase 0 — Analyze & Select Frameworks

Before building controls, pick the governance/threat-model stack. Don't skip — later phases map controls back to these.

| Purpose | Framework | Why |
|---|---|---|
| Risk taxonomy (attack categories) | **OWASP Top 10 for Agentic Applications (ASI01-10)** | Maps directly to concrete controls in Phase 2-5 below |
| Governance lifecycle (Govern/Map/Measure/Manage) | **NIST AI RMF** (+ CSA AAGATE as K8s-native implementation of it) | Gives audit-ready structure, matches AAGATE's design |
| Adversary technique catalog | **MITRE ATLAS** | Use for red-team scenario design in Phase 6 |
| Multi-agent/layered threat modeling | **CSA MAESTRO** | Use if deploying multi-agent / swarm topologies |
| Controls checklist | **CSA AI Controls Matrix (AICM)** or **AIUC-1** | Pick one as the actual audit checklist — AICM if no certification needed, AIUC-1 if external certification/insurance wanted |
| Runtime control standard | **Agent Control Standard** (OWASP GenAI Security Project) | Reference for declarative hook/policy shape in Phase 3 |

**Deliverable:** one-page control-mapping doc: for each ASI0x risk, name the specific Azure/K8s control from Phases 1-6 that mitigates it. This becomes the audit artifact.

**Decision point:** if org already has NIST AI RMF or ISO 42001 program running — bolt onto that rather than starting fresh. Don't run parallel governance frameworks.

---

## Phase 1 — Inventory & Identity Baseline

Goal: know every agent that exists and give each one a governed identity before granting any tool access.

**Options:**

1. **Azure-native (recommended if AKS + Azure-hosted models):**
   - Register every agent as a **Microsoft Entra Agent ID** (GA since May 2026) — service-principal-like identity, no standing credentials, short-lived tokens via OAuth 2.0/MCP/A2A.
   - Requires Microsoft Agent 365 (M365 E7 or E5 add-on) for full Zero Trust coverage (Conditional Access, PIM, Identity Protection) — budget/licensing gate to flag early.
2. **K8s-native / cloud-agnostic:**
   - **SPIFFE/SPIRE** for workload identity (X.509-SVID per agent pod), enforced via **Istio mTLS** or **Cilium** service mesh — this is the pattern **AAGATE** documents.
   - No Microsoft licensing dependency; works across AKS, on-prem, multi-cloud. More build effort.
3. **Third-party overlay (if multi-cloud identity fabric needed):**
   - **Okta for AI Agents** (Cross App Access / XAA) or **CyberArk Secure AI Agents** on top of either option above — adds cross-app policy enforcement and privileged session monitoring.

**Recommendation:** Entra Agent ID if Azure-committed and licensing already covers E5/E7. SPIFFE/SPIRE + Istio if K8s must stay cloud-portable or licensing is a blocker.

**Deliverable:** agent registry (owner, scopes, credential type) for every agent, no exceptions — treat unregistered agent as Sev-1 finding (per README ASI03 / ASI10 mapping).

---

## Phase 2 — Least Privilege & Credential Scoping

- No shared service accounts across agents. Each agent gets its own scoped, short-lived token.
- Azure: **Workload Identity Federation** (AKS pods → Entra ID, no secrets in cluster) + per-agent **Key Vault** access policies scoped to exact secrets needed.
- Secrets never in prompts, env vars checked into manifests, or logs — pull at runtime via Workload Identity, not injected as static K8s Secrets where avoidable.
- Map to OWASP **ASI03 (Identity & Privilege Abuse)**.

---

## Phase 3 — Runtime Isolation / Sandboxing

Goal: an agent that's manipulated can act, but action is contained.

**Options (pick by risk tier — can mix per agent class):**

| Isolation level | Azure/K8s implementation | Use for |
|---|---|---|
| Namespace + NetworkPolicy only | K8s NetworkPolicy + PodSecurity admission (restricted profile) | Low-risk read-only agents |
| Container sandbox (syscall filtering) | **gVisor** or **Kata Containers** runtimeClass on AKS nodepool | Agents with code-exec tools |
| MicroVM per session | **AWS-style microVM isolation not native to Azure** — closest equivalent: dedicated AKS nodepool + Kata Containers, or **Azure Container Instances (ACI)** confidential containers per agent session | High-risk / code-interpreter agents |
| Confidential computing | **Azure confidential AKS nodepools (AMD SEV-SNP)** | Agents handling regulated data (finance, health) |

Open-source options catalogued in repo: **OpenSandbox** (Alibaba, gVisor/Kata/Firecracker, K8s runtimes), **microsandbox** (lightweight microVM), **Agent Safehouse** pattern (deny-first).

**Baseline non-negotiable:** every agent pod runs `runAsNonRoot`, read-only root filesystem, `seccompProfile: RuntimeDefault`, no `NET_RAW`/`SYS_ADMIN` caps, egress NetworkPolicy default-deny with explicit allow-list per agent.

Maps to OWASP **ASI05 (Unexpected Code Execution)**.

---

## Phase 4 — Tool & MCP Security

- Put every tool/MCP call through a gateway, don't let agents call MCP servers directly.
- Options: **MCPProxy** (SHA-256 tool-poisoning quarantine, Docker sandbox isolation, OAuth 2.1) — self-hosted, or **Palo Alto Prisma AIRS AI Agent Gateway** — managed, adds inline prompt/response inspection.
- Run **MCP-Scan** (Invariant Labs) in CI against any MCP server definition before deployment — catch tool-poisoning/rug-pull before it reaches prod.
- Pin MCP server versions/hashes; treat an MCP server upgrade like a supply-chain event (ASI04), not a routine bump.
- On AKS: run each MCP server in its own pod, no shared filesystem with the agent runtime, NetworkPolicy restricting agent→MCP to the gateway only (no direct pod-to-pod).

Maps to OWASP **ASI02 (Tool Misuse)**, **ASI04 (Supply Chain)**.

---

## Phase 5 — Guardrails & Human-in-the-Loop Gates

- Input/output screening: **Azure AI Content Safety** (native, if using Azure OpenAI) or **Palo Alto Prisma AIRS** / **Lasso Security (LEAP)** for provider-agnostic inline guardrails.
- Deterministic gate — in code, not prompt — for irreversible actions: deletes, prod config changes, payments, external sends. Implement as an admission-style check in the tool-call path (Phase 4 gateway is the right place), not as a system-prompt instruction.
- Design against "consent fatigue": use confidence thresholds + intent verification, not raw click-through approval, for high-frequency prompts.

Maps to OWASP **ASI01 (Goal Hijack)**, **ASI09 (Human-Agent Trust Exploitation)**.

---

## Phase 6 — Observability, Audit, Kill Switch

- Log every tool call: initiating agent identity, credential used, tool, parameters, result — not just chat transcript. Export via OpenTelemetry.
- Azure: **Azure Monitor + Log Analytics** for cluster/agent telemetry, **Microsoft Sentinel** for correlation/detection rules.
- K8s-native alternative/complement: **Cilium eBPF** flow logs + **Kafka pipeline** + UEBA, the pattern AAGATE documents.
- Kill switch: revoke agent's Entra Agent ID / SPIFFE SVID immediately revokes all active sessions — verify this works before go-live, don't assume.
- Target: monitoring coverage on 100% of production agents before autonomy is expanded past pilot tier (industry mean is ~50% — don't be that stat).

---

## Phase 7 — Continuous Validation

- Recurring agentic red-teaming against **MITRE ATLAS** techniques + OWASP ASI0x scenarios — score on tool-calls/data-egress, not task completion.
- Gate promotion from pilot → production on: monitoring coverage ≥ 80%, red-team pass, Phase 0 control-mapping doc signed off.
- Re-run Phase 0 framework mapping whenever adding a new agent class or new MCP integration — not a one-time exercise.

---

## Open Decisions (need input before build starts)

- Entra Agent ID + Agent 365 licensing cost vs. self-built SPIFFE/SPIRE — depends on existing M365 tier.
- AKS confidential nodepools (cost premium) vs. standard nodepools + Kata Containers — depends on data sensitivity.
- Managed gateway (Prisma AIRS) vs. self-hosted (MCPProxy) — depends on team's appetite for running/patching another service.
- Certification track: AICM (internal use) vs. AIUC-1 (external cert + insurance) — depends on whether customers/regulators demand third-party attestation.
