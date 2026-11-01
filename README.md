# NASA cFS Adversarial Security & Kernel Observability Testbed

An isolated, minimal C and eBPF testbed designed to qualify process identity, execution freshness, and independent effect verification for NASA Core Flight System (cFS) components on Linux without modifying baseline cFS code.

Developed by **Rahad Bhuiya** ([@rahadbhuiya](https://github.com/rahadbhuiya), Exploidus Labs) in collaboration with **Thales Rangel** ([@bonushora](https://github.com/bonushora)).

---

## Status

| Document | Status |
|---|---|
| [Security Contract v0.1](docs/SECURITY_CONTRACT_v01.md) | FROZEN DOCUMENTARY BASELINE |
| [Community Architecture Proposal v0.1](docs/COMMUNITY_ARCHITECTURE_PROPOSAL_v01.md) | DRAFT — PENDING JOINT REVIEW |
| [Threat Model](docs/THREAT_MODEL.md) | Stable Reference |
| Platform Qualification | NOT_QUALIFIED (Partial QL-2 / Partial QL-3) |
| NASA Endorsement | NOT_CLAIMED |
| Community Submission | NOT_SUBMITTED |

---

## Context & Origin

This reference testbed was formulated and developed to evaluate the adversarial security qualification boundaries and kernel observability requirements discussed in [NASA cFS Discussion #1168](https://github.com/nasa/cFS/discussions/1168). It serves as an independent experimental reference to qualify flight software components on Linux without perturbing upstream cFS baselines.

---

## Documentation

### [`docs/SECURITY_CONTRACT_v01.md`](docs/SECURITY_CONTRACT_v01.md) — Normative Baseline (Frozen)

The platform-independent security qualification contract. Defines six normative security invariants (SEC-INV-01 through SEC-INV-06) with formal requirement, evidence, acceptance, and failure criteria. Frozen at commit `cc63eb1` as the v0.1 documentary baseline.

> All six invariants carry status **DRAFT / NOT_QUALIFIED** until independently evaluated
> against the acceptance criteria on the target platform.

### [`docs/COMMUNITY_ARCHITECTURE_PROPOSAL_v01.md`](docs/COMMUNITY_ARCHITECTURE_PROPOSAL_v01.md) — Architecture Proposal (Working Draft)

A collaborative community architecture proposal for non-invasive cFS security integration:
- **Sections 1–7** (Rahad Bhuiya): Threat model, platform-neutral security invariants, responsibility demarcation, Linux qualification methodology, research roadmap, and community review questions.
- **Section 8** (Thales Rangel): Architectural framing, cFS integration rationale, proposed authority boundaries, evidence and qualification principles, and community engagement strategy.

### [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — Threat Boundary Analysis

Specifies four concrete adversarial threat vectors (A–D) with Linux-specific defense mechanisms and analysis of `memfd_create` sealing semantics.

---

## Background & Objective

Flight software executing on Linux platforms requires robust adversarial boundaries against compromised peer processes sharing the same UID, descriptor inheritance leaks, and falsified userland self-reports.

This testbed provides concrete, falsifiable tests for five core properties:
1. **Same-UID Isolation:** Blocking memory snooping and ptrace attachment from peer processes via `prctl(PR_SET_DUMPABLE, 0)` and `SO_PEERCRED`.
2. **Anonymous IPC Binding:** Eliminating filesystem-visible queues and inherited descriptor leaks using anonymous `socketpair` with `SOCK_CLOEXEC`.
3. **Independent Effector Telemetry:** Capturing physical effector events via in-kernel eBPF tracepoints rather than trusting executor self-reporting.
4. **Effect-Side Witness:** Distinguishing syscall invocation (`sys_enter_write`) from genuine physical effect completion and payload absorption at the destination target.
5. **Isolated Ringbuffer Backpressure & Sequence Accounting:** Decoupling telemetry buffer exhaustion from monotonic transaction sequence discontinuity.

---

## Architecture

```
   [ Coordinator / Dispatcher ]
                |
                |  Anonymous socketpair(SOCK_SEQPACKET | SOCK_CLOEXEC)
                |  + prctl(PR_SET_DUMPABLE, 0)
                |  + SO_PEERCRED credential qualification
                v
       [ Authorized Executor ]
                |
                |  Physical Effect Syscall (write / ioctl)
                v
       [ Hardware / Effector ] <----+ [ In-Kernel eBPF Probe ]
           (Target Sink)             |   - sys_enter_write tracepoint
                |                    |   - Monotonic 64-bit sequence check
                |                    |   - Instance start-time tracking
                |                    |   - Ringbuffer drop telemetry
                v                    v
       [ Effect-Side Witness ] <---> [ Independent Observer ]
                - Physical byte & state absorption verification
                - Zero userland fallback in live-kernel mode
```

---

## Repository Structure

| Path | Description |
|---|---|
| `docs/SECURITY_CONTRACT_v01.md` | Frozen normative security contract (6 invariants, qualification ladder) |
| `docs/COMMUNITY_ARCHITECTURE_PROPOSAL_v01.md` | Collaborative community architecture proposal (working draft) |
| `docs/THREAT_MODEL.md` | Threat boundary specifications and `memfd_create` sealing analysis |
| `include/common.h` | Shared wire packet structures, monotonic sequence headers, eBPF event definitions |
| `src/coordinator.c` | Channel setup, peer credential verification, monotonic command dispatching |
| `src/executor.c` | Authorized command execution and effector syscall generation |
| `src/adversary.c` | Adversarial test suite (same-UID ptrace, sequence loss, falsified reports, effect witness) |
| `src/observer.c` | Testbed coordinator, observer logic, automated qualification harness |
| `bpf/effect_monitor.bpf.c` | In-kernel eBPF effector and sequence accounting probe |

---

## Prerequisites

- Linux Kernel 5.8+ (with BPF ringbuffer support enabled)
- GCC or Clang
- Make
- `libbpf-dev` (for compiling the in-kernel eBPF probe)

---

## Quick Start & Running Tests

Clone and run the automated test suite directly:

```bash
git clone https://github.com/Exploidus/cfs-adversarial-testbed.git
cd cfs-adversarial-testbed
chmod +x run_tests.sh
./run_tests.sh
```

Or build manually via Make:

```bash
make clean
make all
make test
```

To compile the in-kernel eBPF probe:

```bash
make bpf
```

---

## Test Output & Qualification Matrix

When executed, the testbed runs five automated qualification scenarios:

| Step | Scenario | Expected Result |
|---|---|---|
| Step 1 | `SO_PEERCRED` validation on anonymous socketpair | PASS: Identity verified |
| Step 2 | Legitimate transaction seq=1 dispatched to effector | PASS: Corroborated by kernel probe |
| Scenario 1 | Same-UID `ptrace(PTRACE_ATTACH)` attack simulation | PASS: Blocked by `EPERM` |
| Scenario 2 | Sequence discontinuity across monotonic gap | PASS: Flagged as `UNQUALIFIED: SEQUENCE_LOSS` |
| Scenario 3 | Falsified executor self-report without kernel effect | PASS: Falsification confirmed by eBPF |
| Scenario 4 | Syscall entry vs. effect completion with paired witness | PASS: L1/L3 independently qualified |
| Scenario 5 | Ringbuffer backpressure decoupled from sequence gaps | PASS: PROD-DROP isolated from TXN-GAP |

> **Qualification Note:** The Linux/eBPF reference implementation demonstrates **Partial QL-2 coverage**
> and **Partial QL-3 capability**. Full qualification remains open — see
> [`docs/SECURITY_CONTRACT_v01.md`](docs/SECURITY_CONTRACT_v01.md) Section 6 for the complete
> open requirement gap list.

---

## License

Dual BSD/GPL or Apache 2.0 (standard for NASA cFS and Linux eBPF tools).
