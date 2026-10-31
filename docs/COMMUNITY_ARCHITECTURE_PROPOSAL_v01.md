# NASA cFS Community Architecture Proposal v0.1
## Technical Specification & Qualification Methodology (Independent Research)

**Document Identifier:** `CFS-COMM-ARCH-PROP-TECH-v0.1`  
**Normative Baseline Anchor:** `Exploidus/cfs-adversarial-testbed@cc63eb1` (`CFS-SEC-CONTRACT-v0.1`)  
**Lead Technical Contributor:** Rahad Bhuiya ([@rahadbhuiya](https://github.com/rahadbhuiya))
**Co-Author & Review Lead:** Thales Rangel ([@bonushora](https://github.com/bonushora))
**Status:** DRAFT / WORKING BASELINE FOR COLLABORATIVE REVIEW  
**Classification:** Independent Collaborative Research (Non-NASA Endorsement)  

---

## 1. Executive Summary & Architectural Motivation

Modern spaceflight architectures increasingly evaluate multi-tenant payloads, in-flight machine learning integration, and complex inter-app communication on the NASA Core Flight Executive (cFE) / Core Flight System (cFS). Historically, portable cFS assumed a cooperative, static, fully trusted execution environment.

This proposal introduces an **independent, non-invasive community architecture concept** aimed at defining platform-neutral security invariants, decoupling trusted observation boundaries, and establishing an evidence-driven qualification framework for cFS deployments. 

In strict adherence to our frozen documentary baseline (`CFS-SEC-CONTRACT-v0.1` at commit `cc63eb1`), this proposal does not advocate modifying the portable cFS core. Instead, it proposes clear architectural responsibility boundaries between mission flight code, platform security adapters, and independent verification harnesses.

```
+-----------------------------------------------------------------------+
|                 Mission Applications & Payloads (cFS Apps)            |
|       [Guidance & Nav]     [Science Workload]     [Third-Party App]   |
+-----------------------------------------------------------------------+
                                   |
                     (Standard cFS Software Bus API)
                                   v
+-----------------------------------------------------------------------+
|                    Portable cFS Core Executive                        |
|        Executive Services (ES)        Software Bus (SB Core)          |
|        Event Services (EVS)           Table Services (TBL)            |
+-----------------------------------------------------------------------+
                                   |
                (Proposed Security Adapter Boundary)
                                   v
+-----------------------------------------------------------------------+
|         Platform Security Adapter Layer (PSAL) [Proposed Concept]     |
|   - Executor Identity & Instance Verification                         |
|   - Authorization Token Evaluation Prior to Dispatch                  |
|   - Replay & Unauthorized Bypass Prevention                           |
+-----------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         v                                                   v
+-----------------------------+             +---------------------------+
| OS/Kernel Enclave (Linux)   |             | RTOS / Embedded Target    |
| (eBPF Probes & Tracepoints) |             | (RTEMS / Microkernel)     |
+-----------------------------+             +---------------------------+
                                   |
                     (Non-Intrusive Observation Ring)
                                   v
+-----------------------------------------------------------------------+
|           Independent Effect Verification & Accounting Harness         |
|   - 4-Level Effect Progression Audit (Invocation -> Physical State)   |
|   - 4-Mechanism Observation-Loss Accounting                           |
|   - Fail-Closed Qualification Engine (Default NOT_QUALIFIED)          |
+-----------------------------------------------------------------------+
```

---

## 2. Operational Threat Model & Adversarial Posture

To ground the architectural requirements, the proposal analyzes five representative attack vectors targeting mission flight software:

| Vector ID | Threat Classification | Attack Description | Architectural Vulnerability in Legacy Deployments |
| :--- | :--- | :--- | :--- |
| **TV-01** | Compromised Payload Application | Untrusted payload application attempts unauthorized command dispatch to critical spacecraft actuators. | Unsegmented Software Bus routing without cryptographic task origin verification. |
| **TV-02** | Stale / Replayed Command Injection | Attacker captures valid flight telecommands and replays them during unauthorized orbital mission phases. | Absence of temporal nonces, monotonic epoch counters, or instance-bound execution tokens. |
| **TV-03** | Executor Impersonation & Inheritance | Terminated or crashed executor task restarts with a recycled PID and inherits stale access rights. | Authorization tied to transient operating system PIDs rather than persistent cryptographic instance tokens. |
| **TV-04** | Telemetry & Effect Spoofing | Subverted thread generates false software return codes while the physical actuator command fails or is silently dropped. | Verification assumes syscall return equates to actual physical actuator state change. |
| **TV-05** | Silent Observation Blindspotting | High-rate command flooding saturates monitoring queues, causing security probes to drop frames without reporting audit loss. | Lack of explicit observation-loss accounting and fail-closed qualification enforcement. |

---

## 3. Platform-Neutral Security Invariants (Normative Baseline)

The architecture is anchored to the six platform-neutral security invariants defined in frozen contract `CFS-SEC-CONTRACT-v0.1` (`cc63eb1`). In strict accordance with the baseline, **all six invariants retain their normative status as DRAFT / NOT_QUALIFIED** until cross-platform flight qualification is independently proven.

### 3.1 SEC-INV-01: Authorization Before Dispatch
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** No command shall be dispatched to an executor unless two independent conditions are satisfied in sequence: first, the executor's identity has been verified by an independently trusted mechanism; second, an explicit authorization token matching the command transaction has been validated prior to release.

### 3.2 SEC-INV-02: Executor Identity and Instance Binding
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** Each command transaction must be bound to a specific, independently verified executor instance. A restarted or replaced executor instance must not inherit authorization from a previous instance. Instance identity is defined independently of operating-system-specific process or thread identifiers.

### 3.3 SEC-INV-03: Replay and Bypass Resistance
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** The system must provide both preventive controls against replay and unauthorized bypass, and independent detective controls that identify when such events occur. These two control classes are distinct and must each be independently verified.

### 3.4 SEC-INV-04: Independently Verified Effect Completion
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** Syscall invocation (entry), successful syscall return, sink-side byte absorption, and the intended physical or logical destination state transition are distinct observations. Each represents a different level of effect completion. An observation at level $N$ must not be taken as evidence that level $N+1$ occurred.

### 3.5 SEC-INV-05: Observation-Loss Accounting
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** Any gap in the observation record must be explicitly detected, quantified, attributed to a specific loss mechanism, and reported. Four distinct observation-loss mechanisms must be independently accounted for: probe buffer overflow, tracepoint detachment, transport congestion, and monitoring harness saturation.

### 3.6 SEC-INV-06: Fail-Closed Qualification
- **Status:** `DRAFT / NOT_QUALIFIED`
- **Specification:** The qualification harness must default to a `NOT_QUALIFIED` verdict in the absence of sufficient independently trusted evidence for the declared evidence level. Absence of a failure observation must never be interpreted as evidence of compliance.

---

## 4. Responsibility Demarcation Matrix (Proposed Boundaries)

To ensure non-invasive integration, architectural responsibilities are partitioned into distinct operational tiers:

| Operational Tier | Defined Scope & Responsibilities | Explicit Exclusions & Prohibitions |
| :--- | :--- | :--- |
| **cFS Core Executive** | Deterministic scheduling, table management, standard CCSDS packet dispatch, EVS logging. | Strictly portable; zero platform-specific syscalls or security enforcement logic. |
| **Platform Security Adapter (PSAL)** | Evaluates tokens before dispatch, verifies executor instance binding, rejects unauthorized commands. | Proposed conceptual adapter; must not alter portable cFS APIs or introduce breaking core changes. |
| **Platform Enforcement Layer** | OS kernel / RTOS enforcement (futex primitives, eBPF probes, MMU access permissions). | Generic platform mechanism; decoupled from flight mission logic. |
| **Independent Verification Harness** | Out-of-band effect confirmation, loss accounting, adversarial injection, qualification metrics. | Non-intrusive observation; must not introduce unbounded jitter into flight loops. |

---

## 5. Linux Reference Qualification Methodology & Prototype Feasibility

To evaluate whether the six invariants can be enforced and verified without modifying cFS core logic, a **Linux Reference Qualification Testbed** was constructed as an independent proof of concept.

### 5.1 Prototype Implementation Mechanisms
- **Non-Intrusive Kernel Observation:** Uses freestanding eBPF tracepoint probes on `sys_enter` / `sys_exit` to verify invocation boundaries without task preemption.
- **Ringbuffer Telemetry Decoupling:** Implements a decoupled kernel ringbuffer (`bpf_ringbuf`) to ensure trace logging cannot induce backpressure or lock contention on real-time task queues.
- **Tracepoint Decoupling (REQ-03.4):** Implemented in `cc63eb1`, ensuring that test harness monitors observe raw kernel state transitions independently of userspace report framing.

### 5.2 Reference Feasibility Matrix (Prototype Observation)

| Invariant Reference | Target Verification Mechanism | Demonstrated Reference Evidence (Linux Prototype) | Normative Qualification Status |
| :--- | :--- | :--- | :--- |
| **SEC-INV-01** | Token check prior to dispatch | Unauthorized SB transmit rejected with access denied | `DRAFT / NOT_QUALIFIED` |
| **SEC-INV-02** | Instance identifier verification | Recycled task IDs rejected upon executor restart | `DRAFT / NOT_QUALIFIED` |
| **SEC-INV-03** | Replay & nonce evaluation | Replayed command buffers detected by sequence check | `DRAFT / NOT_QUALIFIED` |
| **SEC-INV-04** | 4-tier effect completion probe | Level 1 (invocation) separated from Level 4 (actuator state) | `DRAFT / NOT_QUALIFIED` |
| **SEC-INV-05** | Loss mechanism accounting | Dropped ringbuffer entries quantified via counter map | `DRAFT / NOT_QUALIFIED` |
| **SEC-INV-06** | Fail-closed evaluation logic | Missing or inconclusive traces default to `NOT_QUALIFIED` | `DRAFT / NOT_QUALIFIED` |

---

## 6. Proposed Future Research Directions (Outside v0.1 Baseline)

While the v0.1 community proposal is strictly bounded to the six core invariants, ongoing experimental implementations in native environments (such as the Exploidus OS capability microkernel port) suggest several promising avenues for future secondary research contracts:

- **Spatial & Temporal Memory Enclaves:** Hardware MMU-enforced process isolation preventing lateral memory inspection across distinct flight application pools.
- **Forward-Secure Event Audit Chaining:** Cryptographic hash chains (e.g. BLAKE3 chaining) applied to cFE Event Services (EVS) logs to ensure forensic tamper-evidence.
- **Physical Actuator Gatekeeping:** Microkernel capability tickets gating direct hardware effector MMIO/DMA lines.
- **Autonomous Radiation Fault Containment:** Background cyclic redundancy scans detecting Single Event Upset (SEU) bit-flips with fail-silent thread quarantining.

These extended topics are recognized as distinct architectural research areas and will be developed under separate candidate contracts, preserving the stability of the v0.1 baseline.

---

## 7. Staged Research Roadmap & Community Review Questions

### 7.1 Community Review Questions for cFS Maintainers
1. Does the proposed demarcation between portable cFS core and the Platform Security Adapter Layer (PSAL) provide an acceptable non-invasive abstraction for mission security?
2. Would the cFS community favor evaluating security invariant enforcement as a modular OSAL/PSP capability or as an external security adapter?
3. What verification artifacts and reproducibility standards would the community require before considering formal RFC review?

### 7.2 Staged Roadmap
- **Stage 1 (Community Review):** Consolidate Community Architecture Proposal v0.1, submit for architectural discussion, and gather maintainer feedback.
- **Stage 2 (Benchmark & Measurement):** Gather empirical latency and CPU overhead measurements across multi-core Linux platforms to substantiate performance claims.
- **Stage 3 (Cross-Platform Qualification):** Port adapter prototypes to RTEMS 5/6 and evaluate feasibility on flight-representative microcontrollers.
- **Stage 4 (Academic Publication):** Prepare a joint peer-reviewed conference paper summarizing the architectural model, formal invariants, and empirical qualification results.

---
## 8. Architectural Framing and cFS Integration Rationale



**Architectural Contributor:** Thales Rangel ([[@bonushora](https://github.com/bonushora)](https://github.com/bonushora))



**Contribution Type:** Architectural framing, cFS integration rationale, authority boundaries, and community review strategy.



**Normative Reference:** `CFS-SEC-CONTRACT-v0.1`, frozen documentary baseline at commit `cc63eb13cc168a7ceca52ae703367065a0228643`.



**Status:** WORKING DRAFT  -  Independent Collaborative Research.



### 8.1 Architectural Motivation: Contract-First Security



Flight-software security requires more than identifying the process executing a command.



A defensible security architecture must establish whether a specific operation was authorized, whether the intended executor instance performed it, whether unauthorized execution or replay could bypass preventive controls, and whether the intended effect was independently verified.



These properties should not depend on any particular operating system, syscall interface, instrumentation framework, or telemetry transport.



We therefore propose a **contract-first security architecture**, in which security properties and acceptance criteria are specified independently of the mechanisms used to enforce and observe them.



The objective is not to introduce a universal enforcement implementation. Instead, it is to establish a consistent set of security invariants, responsibility boundaries, threat assumptions, and evidence requirements against which different platform implementations can be evaluated.



The six normative invariants remain exactly those defined in the frozen `CFS-SEC-CONTRACT-v0.1` baseline.



### 8.2 cFS Integration Rationale



The NASA Core Flight System (cFS) provides reusable flight-software services supported by portability abstractions, including the Operating System Abstraction Layer (OSAL) and Platform Support Package (PSP).



A proposed security architecture should respect these existing abstractions rather than assume equivalent enforcement capabilities across different operating environments.



In particular, the availability of Linux kernel instrumentation does not establish the availability of equivalent mechanisms on RTEMS, VxWorks, or other target platforms.



We propose that potential integration be evaluated through four conceptual responsibility domains.



**A. Portable Framework Boundary**



The portable framework may provide abstract integration interfaces or extension points through which security requirements can be expressed.



This proposal does not prescribe changes to the portable cFS core during the documentary phase.



Whether additional interfaces belong in the framework, OSAL, PSP, or an external integration component remains a question for community architectural review.



**B. Mission Authority Boundary**



Mission-specific policy defines the authorized command types, protected targets, payload restrictions, execution constraints, recovery procedures, and required effect-completion semantics.



Authentication of an executor must remain distinct from authorization of a particular operation.



Authorization decisions must be bound to the exact protected action and relevant execution context.



**C. Platform Enforcement and Observation Boundary**



Each platform may implement the required preventive and detective controls using mechanisms appropriate to its operating environment.



Such mechanisms may include operating-system facilities, trusted monitors, hypervisor mechanisms, or hardware-enforced isolation where available and justified.



The proposed Platform Security Adapter Layer (PSAL) is a candidate architectural abstraction, not an established cFS component.



Its authority, bypass resistance, timing impact, and relationship to existing portability interfaces require separate evaluation.



**D. Independent Qualification Boundary**



Qualification tooling evaluates whether a specific implementation satisfies the declared security requirements.



The required evidence must be independently trustworthy, reproducible, and traceable to a specific implementation, configuration, qualification window, and threat model.



Successful automated execution does not by itself establish full security qualification.



These four domains are proposed architectural responsibility boundaries rather than obligations currently imposed by the official cFS framework.



### 8.3 Integration Without Premature Core Modification



The initial architectural investigation should avoid making modifications to the portable cFS core a prerequisite.



Instead, community review should determine whether the security properties can be expressed and evaluated through existing extension mechanisms, external mediation, platform adapters, or mission-controlled integration points.



Any future integration proposal should explicitly address:



- Whether every protected execution path passes through the intended authorization boundary.

- Whether alternative APIs, privileged processes, or direct hardware access could bypass enforcement.

- Whether authorization remains bound to the actual executor instance and exact action.

- Whether observation remains independent of the component being evaluated.

- Whether the required evidence can be obtained without violating mission timing or resource constraints.

- Whether the proposed implementation preserves established portability expectations.



An architectural interface must not be described as an effective security boundary until its enforcement properties and bypass resistance have been demonstrated.



### 8.4 Evidence and Qualification Principles



The qualification process should preserve the distinction between:



- Documentary completeness and demonstrated implementation behavior.

- Authentication and authorization.

- Preventive enforcement and subsequent detection.

- Command dispatch and independently witnessed effect completion.

- Transaction sequence discontinuities and confirmed observation-channel loss.

- Successful CI execution and independently reviewed security qualification.



Every qualification verdict should be traceable through:



**Normative Requirement → Test Case → Independent Evidence → Qualification Verdict**



Evidence must also identify the implementation and execution environment to which the verdict applies.



The Linux/eBPF testbed serves as the initial reference environment. Its demonstrated prototype capabilities and remaining gaps are documented separately in the frozen contract.



No equivalent guarantees are claimed for other platforms until independently demonstrated.



Missing, contradictory, incomplete, or untrusted evidence must not result in an unsupported positive qualification verdict.



### 8.5 Community Architectural Review Objectives



The initial interaction with cFS maintainers should seek architectural feedback rather than immediate adoption.



The principal questions are:



1. Which proposed security contracts could usefully complement existing cFS architectural responsibilities?

2. Which enforcement and observation responsibilities should remain mission-specific?

3. Are existing cFS, OSAL, or PSP extension mechanisms suitable for expressing any of these integration requirements?

4. Would an external security adapter provide a cleaner separation than modifying the portable framework?

5. What evidence would maintainers require before considering any integration proposal?

6. What review process would be appropriate for independently developed architectural research?



These questions should be presented without claiming NASA endorsement, flight certification, completed cross-platform qualification, or production readiness.



### 8.6 Proposed Community Engagement Sequence



The next stages should follow an evidence-driven progression:



**Documentary consolidation:** Cross-review the complete Community Architecture Proposal, preserve the frozen security contract reference, and identify the exact contributions and unresolved questions.



**Preliminary community feedback:** Seek guidance from cFS maintainers regarding architectural relevance and the appropriate review channel.



**Reference implementation evidence:** Continue independently evaluating Linux reference capabilities against the frozen requirements, without promoting unverified properties.



**Cross-platform feasibility:** Investigate additional platform adapters only after their trust boundaries, enforcement mechanisms, and evidence requirements have been defined.



**Scientific dissemination:** Consider a joint academic or aerospace publication when the architecture, experimental methodology, results, and reproducibility evidence support a defensible research contribution.



This sequence complements the staged technical roadmap already described in Section 7.



### 8.7 Collaboration, Attribution, and Governance



This proposal represents independent collaborative research.



Rahad Bhuiya contributes the operational threat model, technical invariant analysis, adapter isolation design, and Linux reference qualification methodology.



Thales Rangel contributes the architectural framing, cFS integration rationale, proposed authority boundaries, and community review strategy.



Both contributors participate in cross-review and in the consolidation of the complete proposal.



Contributor attribution does not imply that either participant has independently verified every technical claim made by the other.



External submission, changes to frozen normative requirements, and any future joint publication should be subject to explicit mutual review and agreement.



The frozen `CFS-SEC-CONTRACT-v0.1` baseline must remain distinguishable from subsequent research extensions or implementation changes.



**Documentary Contribution Status:** DRAFT  -  PENDING JOINT REVIEW



**Community Submission Status:** NOT_SUBMITTED



**Platform Qualification Status:** NOT_QUALIFIED



**NASA Endorsement:** NOT_CLAIMED

---
**End of Community Architecture Proposal v0.1 Working Draft**
