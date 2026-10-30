# Platform-Independent Security Qualification Contract

**Document ID:** CFS-SEC-CONTRACT-v0.1  
**Status:** DRAFT  
**Reference Implementation:** [cfs-adversarial-testbed](https://github.com/Exploidus/cfs-adversarial-testbed) (Linux/eBPF)  
**Discussion:** [nasa/cFS #1168](https://github.com/nasa/cFS/discussions/1168)  
**Authors:** Rahad Bhuiya (Exploidus Labs)  
**Reviewers:** Thales (bonushora)

---

> [!IMPORTANT]
> Every invariant in this document carries status **DRAFT / NOT_QUALIFIED** until independently
> evaluated against the acceptance criteria on the target platform. This document does not imply
> certification or endorsement by NASA. It does not modify the portable cFS core.

---

## Purpose and Scope

This contract defines a set of platform-independent security invariants for flight software
built on NASA cFS. It separates two distinct concerns:

1. **Platform-Independent Security Contracts** — normative properties that must hold on any
   target platform, expressed without reference to OS-specific mechanisms.
2. **Platform-Specific Enforcement Adapters** — OS-native mechanisms that implement and
   demonstrate those properties on a given platform (e.g. Linux/eBPF, RTEMS, VxWorks).

The Linux/eBPF testbed (`cfs-adversarial-testbed`) serves as the **initial reference
implementation and adversarial qualification harness** for this contract. Equivalent guarantees
on other platforms are explicitly **NOT_QUALIFIED** until independently demonstrated.

---

## Requirement Notation

| Tag | Meaning |
|-----|---------|
| `[REQ]` | Normative requirement |
| `[ASSUM]` | Explicit assumption that must hold for the property to be valid |
| `[EVID]` | Required independent evidence |
| `[PASS]` | Positive acceptance criterion |
| `[ADV-PASS]` | Adversarial acceptance criterion |
| `[FAIL]` | Explicit failure or non-qualification condition |
| `[RESP-FW]` | Responsibility of the portable cFS framework |
| `[RESP-MISSION]` | Responsibility of the mission or application |
| `[RESP-ADAPTER]` | Responsibility of the platform adapter |
| `[RESP-HARNESS]` | Responsibility of the qualification harness |

---

## Invariant 1: Authorization Before Dispatch

**ID:** SEC-INV-01  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

No command shall be dispatched to an authorized executor unless the caller's identity has been
verified by an independent, kernel-enforced mechanism prior to the dispatch operation.
Userland self-attestation is not sufficient.

### Normative Requirements

- `[REQ-01.1]` The dispatcher must verify executor identity via a kernel-provided credential
  mechanism before issuing any command.
- `[REQ-01.2]` The identity verification result must be obtained from a source that cannot be
  forged or spoofed by a process sharing the same UID as the executor.
- `[REQ-01.3]` If identity verification fails, dispatch must be rejected and the channel closed.

### Threat Model and Trust Assumptions

- `[ASSUM-01.1]` A compromised peer process may share the same UID as the authorized executor.
- `[ASSUM-01.2]` A compromised peer process cannot forge kernel-stamped credentials
  (e.g. `SO_PEERCRED` / `SCM_CREDENTIALS`).
- `[ASSUM-01.3]` The kernel itself is trusted. Kernel credential APIs are not spoofable from
  userland.

### Required Evidence

- `[EVID-01.1]` Captured kernel credential record showing UID and PID matching the authorized
  executor at the time of channel establishment.
- `[EVID-01.2]` Demonstration that a peer with an incorrect UID or PID is rejected before
  any command is dispatched.

### Acceptance Criteria

- `[PASS-01.1]` The dispatcher receives a kernel-stamped credential containing the correct
  UID and PID of the executor. Dispatch proceeds.
- `[ADV-PASS-01.1]` A spoofed or mismatched credential causes the dispatcher to reject the
  channel without issuing any command.

### Failure and Non-Qualification Conditions

- `[FAIL-01.1]` Any command is dispatched before credential verification completes.
- `[FAIL-01.2]` Credential verification relies on userland self-report rather than
  kernel-provided data.
- `[FAIL-01.3]` A process with a mismatched identity successfully receives a dispatched command.

### Responsibility Boundaries

- `[RESP-FW]` Define the abstract authorization interface. Prohibit dispatch without prior
  identity verification.
- `[RESP-ADAPTER]` Implement the identity verification mechanism using OS-native kernel APIs
  (e.g. `SO_PEERCRED` on Linux, equivalent IPC credential mechanisms on RTEMS/VxWorks).
- `[RESP-HARNESS]` Demonstrate both positive and adversarial acceptance criteria and produce
  independent evidence records.
- `[RESP-MISSION]` Configure the set of authorized executor identities.

---

## Invariant 2: Executor Identity and Instance Binding

**ID:** SEC-INV-02  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

Each command transaction must be bound to a specific, kernel-verifiable executor instance.
A restarted or replaced executor instance must not inherit authorization from a previous instance.

### Normative Requirements

- `[REQ-02.1]` Each executor instance must carry a unique, unforgeable instance identifier
  derived from kernel-provided process lifecycle data.
- `[REQ-02.2]` Command transactions must embed the instance identifier. A mismatch between
  the embedded identifier and the current executor instance must cause rejection.
- `[REQ-02.3]` The instance identifier must not be reusable across restarts within the same
  qualification window.

### Threat Model and Trust Assumptions

- `[ASSUM-02.1]` An adversary may restart a crashed executor and attempt to inherit its
  previous authorization context.
- `[ASSUM-02.2]` Process start times or equivalent kernel lifecycle stamps are not forgeable
  from userland.

### Required Evidence

- `[EVID-02.1]` Captured kernel-provided instance identifier (e.g. process start time in
  nanoseconds) embedded in the transaction header and matched by the observer.
- `[EVID-02.2]` Demonstration that a transaction carrying a stale or mismatched instance
  identifier is rejected.

### Acceptance Criteria

- `[PASS-02.1]` A transaction carrying the current executor's instance identifier is accepted
  and the kernel evidence record contains a matching identifier.
- `[ADV-PASS-02.1]` A transaction carrying a previous or forged instance identifier is flagged
  as an instance discontinuity and rejected.

### Failure and Non-Qualification Conditions

- `[FAIL-02.1]` A restarted executor inherits authorization from its predecessor without
  re-verification.
- `[FAIL-02.2]` Instance identifiers are assigned by userland rather than derived from
  kernel-provided lifecycle data.

### Responsibility Boundaries

- `[RESP-FW]` Define the instance identifier field in the transaction header. Specify the
  rejection policy for instance mismatches.
- `[RESP-ADAPTER]` Derive the instance identifier from OS-native kernel APIs
  (e.g. `clock_gettime(CLOCK_BOOTTIME)` on Linux).
- `[RESP-HARNESS]` Inject instance discontinuity and verify rejection.
- `[RESP-MISSION]` Define the re-authorization procedure following an executor restart.

---

## Invariant 3: Replay and Bypass Resistance

**ID:** SEC-INV-03  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

No previously observed command transaction may be replayed to produce an unauthorized effect.
A compromised executor must not be able to suppress a kernel-visible effect while claiming
success in its userland self-report.

### Normative Requirements

- `[REQ-03.1]` Every command transaction must carry a monotonically increasing 64-bit sequence
  number scoped to the executor instance. The observer must reject non-monotonic sequences.
- `[REQ-03.2]` Effect observation must be performed by an independent mechanism that is not
  under the control of the executor process.
- `[REQ-03.3]` A discrepancy between executor self-report and independent effect observation
  must be flagged as a qualification failure.

### Threat Model and Trust Assumptions

- `[ASSUM-03.1]` A compromised executor may replay a previously captured transaction.
- `[ASSUM-03.2]` A compromised executor may claim to have executed a command while suppressing
  the actual kernel-visible operation.
- `[ASSUM-03.3]` The independent observer mechanism (e.g. in-kernel eBPF probe) cannot be
  disabled or spoofed by a userland process.

### Required Evidence

- `[EVID-03.1]` A kernel-side event record for each accepted transaction containing the
  sequence number, timestamp, and payload digest.
- `[EVID-03.2]` Demonstration that a replayed transaction is detected via sequence comparison.
- `[EVID-03.3]` Demonstration that a tampered executor self-report is rejected when the
  independent observer finds no corresponding kernel event.

### Acceptance Criteria

- `[PASS-03.1]` A legitimate transaction is accepted. The observer records a matching
  kernel-side event with a non-zero timestamp and correct payload digest.
- `[ADV-PASS-03.1]` A replayed transaction is detected by sequence number comparison and
  flagged as a replay event.
- `[ADV-PASS-03.2]` A compromised executor that claims success without issuing the
  kernel-visible operation is detected. The independent observer records zero events for
  the transaction. The self-report is rejected.

### Failure and Non-Qualification Conditions

- `[FAIL-03.1]` A replayed transaction is accepted and produces an effect.
- `[FAIL-03.2]` The observer relies on the executor's self-report to determine whether an
  effect occurred.
- `[FAIL-03.3]` A compromised self-report is accepted as ground truth in the absence of
  independent kernel evidence.

### Responsibility Boundaries

- `[RESP-FW]` Define the monotonic sequence field and the replay detection policy.
- `[RESP-ADAPTER]` Implement the independent in-kernel observer (e.g. eBPF tracepoint on
  Linux). Ensure the observer cannot be disabled by a userland process.
- `[RESP-HARNESS]` Inject replayed and suppressed transactions and verify detection.
- `[RESP-MISSION]` Define the recovery procedure following a detected replay or suppression.

---

## Invariant 4: Independently Verified Effect Completion

**ID:** SEC-INV-04  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

Syscall invocation (entry) must be distinguished from genuine physical effect completion.
A command is considered qualified only when both the kernel-side syscall entry and the
physical effect absorption at the destination sink have been independently witnessed and
corroborated.

### Normative Requirements

- `[REQ-04.1]` The observer must record the syscall entry event from an independent in-kernel
  source, including the timestamp, target PID, and payload digest.
- `[REQ-04.2]` The destination sink must independently confirm full byte absorption of the
  payload, producing a witness record that includes the absorbed byte count.
- `[REQ-04.3]` The qualification verdict must require both records to be present and
  corroborated. A syscall entry without a corresponding sink witness is insufficient.

### Threat Model and Trust Assumptions

- `[ASSUM-04.1]` A syscall may be interrupted or produce a partial write. Syscall entry alone
  does not imply successful effect delivery.
- `[ASSUM-04.2]` The destination sink witness is obtained from the receiving end of the
  effector channel and is independent of the executor's self-report.

### Required Evidence

- `[EVID-04.1]` In-kernel event record capturing syscall entry with timestamp, PID, and
  payload digest.
- `[EVID-04.2]` Effector sink record confirming absorbed byte count equal to or greater than
  the expected payload size.
- `[EVID-04.3]` Explicit pairing of the kernel entry record and the sink record, traceable
  to the same transaction sequence number and payload digest.

### Acceptance Criteria

- `[PASS-04.1]` Both the in-kernel entry event and the sink witness are present for the
  transaction. The absorbed byte count meets or exceeds the expected size. The payload
  digest matches. The qualification verdict is COMPLETED.
- `[ADV-PASS-04.1]` A transaction with a kernel entry event but no corresponding sink witness
  is flagged as UNQUALIFIED. A partial absorption is flagged as INCOMPLETE.

### Failure and Non-Qualification Conditions

- `[FAIL-04.1]` A transaction is considered complete based on syscall entry alone without
  a sink witness.
- `[FAIL-04.2]` The sink witness is obtained from the executor process rather than from the
  receiving end of the effector channel.
- `[FAIL-04.3]` The absorbed byte count is less than the expected payload size and the
  transaction is nevertheless marked COMPLETED.

### Responsibility Boundaries

- `[RESP-FW]` Define the paired witness interface. Specify the qualification verdict rules.
- `[RESP-ADAPTER]` Implement the in-kernel entry observer (e.g. `sys_enter_write` tracepoint
  on Linux) and the effector sink witness mechanism.
- `[RESP-HARNESS]` Demonstrate both positive and adversarial acceptance criteria, including
  partial write injection.
- `[RESP-MISSION]` Define the physical effector interface and the expected payload size for
  each command type.

---

## Invariant 5: Observation-Loss Accounting

**ID:** SEC-INV-05  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

Any gap in the observation record must be explicitly detected, quantified, and reported.
Telemetry buffer exhaustion and transaction sequence discontinuity must be accounted for
as distinct failure modes and must not be conflated.

### Normative Requirements

- `[REQ-05.1]` The observer must maintain a monotonic sequence counter in kernel space.
  Any gap between the last observed sequence number and the current sequence number must
  be recorded as a lost-event count.
- `[REQ-05.2]` Ringbuffer or telemetry channel backpressure drops must be counted and
  reported independently of transaction sequence gaps.
- `[REQ-05.3]` A qualification window containing unresolved observation gaps must be
  reported as UNQUALIFIED until the gap is accounted for.

### Threat Model and Trust Assumptions

- `[ASSUM-05.1]` Bursty event production may exhaust the telemetry buffer, causing in-kernel
  drops that are independent of transaction-level sequence numbering.
- `[ASSUM-05.2]` A compromised component may intentionally generate events at a rate designed
  to exhaust the observer's telemetry buffer.

### Required Evidence

- `[EVID-05.1]` In-kernel lost-event counter value for each observed sequence gap, derived
  from the kernel-side sequence state map.
- `[EVID-05.2]` In-kernel backpressure drop counter value for the qualification window,
  derived from the telemetry buffer accounting mechanism.
- `[EVID-05.3]` Explicit separation of the two counters in the qualification report.

### Acceptance Criteria

- `[PASS-05.1]` A deliberate sequence gap is detected. The lost-event counter reflects the
  correct number of missing transactions. The backpressure counter is unaffected.
- `[PASS-05.2]` Deliberate telemetry buffer saturation is detected. The backpressure counter
  reflects the correct number of dropped events. The sequence gap counter is unaffected.
- `[ADV-PASS-05.1]` Both failure modes occur simultaneously. Each counter independently
  reflects only its own contribution to the total observation loss.

### Failure and Non-Qualification Conditions

- `[FAIL-05.1]` A sequence gap is not detected or is attributed to backpressure without
  independent evidence.
- `[FAIL-05.2]` Backpressure drops are attributed to sequence gaps without independent
  evidence.
- `[FAIL-05.3]` An observation gap is silently ignored or suppressed in the qualification
  report.

### Responsibility Boundaries

- `[RESP-FW]` Define the observation-loss reporting interface and the qualification window
  rules.
- `[RESP-ADAPTER]` Implement the in-kernel sequence state map and backpressure counter
  (e.g. eBPF array maps on Linux).
- `[RESP-HARNESS]` Inject deliberate sequence gaps and telemetry saturation events and
  verify independent accounting.
- `[RESP-MISSION]` Define the acceptable observation-loss budget for each mission profile.

---

## Invariant 6: Fail-Closed Qualification

**ID:** SEC-INV-06  
**Status:** DRAFT / NOT_QUALIFIED

### Security Property

The qualification harness must default to a NOT_QUALIFIED verdict in the absence of
sufficient independent evidence. Absence of a failure observation must not be interpreted
as evidence of correct operation. Userland fallback is prohibited in live-kernel mode.

### Normative Requirements

- `[REQ-06.1]` The qualification harness must operate in one of two strictly separated modes:
  live-kernel mode (independent kernel evidence required) or unprivileged mode (no
  kernel evidence available, verdict explicitly degraded).
- `[REQ-06.2]` In live-kernel mode, a missing or zero-valued kernel evidence record must
  cause an immediate NOT_QUALIFIED verdict. Userland fallback is prohibited.
- `[REQ-06.3]` Every qualification verdict must be traceable to an explicit evidence record.
  A verdict produced without a traceable evidence record is invalid.

### Threat Model and Trust Assumptions

- `[ASSUM-06.1]` An observer operating without kernel privileges cannot produce independent
  ground truth. Its verdicts must be explicitly marked as unverified.
- `[ASSUM-06.2]` A misconfigured or degraded kernel observer may silently fail to produce
  evidence. Silence must not be treated as a positive result.

### Required Evidence

- `[EVID-06.1]` Explicit mode indicator in the qualification report (live-kernel or
  unprivileged).
- `[EVID-06.2]` In live-kernel mode: at least one non-zero kernel evidence record per
  qualified transaction.
- `[EVID-06.3]` Demonstration that a missing kernel evidence record causes an immediate
  NOT_QUALIFIED verdict with no userland fallback.

### Acceptance Criteria

- `[PASS-06.1]` In live-kernel mode, all qualified transactions have a corresponding
  non-zero kernel evidence record. The final verdict is QUALIFIED.
- `[ADV-PASS-06.1]` The kernel observer is degraded or disabled. The harness detects the
  absence of evidence and immediately reports NOT_QUALIFIED without falling back to
  userland verification.
- `[ADV-PASS-06.2]` The harness is run without kernel privileges. The mode is explicitly
  reported as unprivileged. No QUALIFIED verdict is issued for transactions that lack
  independent evidence.

### Failure and Non-Qualification Conditions

- `[FAIL-06.1]` A QUALIFIED verdict is issued without a traceable kernel evidence record.
- `[FAIL-06.2]` The harness falls back to userland verification when kernel evidence is
  unavailable in live-kernel mode.
- `[FAIL-06.3]` The qualification mode is not explicitly reported.

### Responsibility Boundaries

- `[RESP-FW]` Define the qualification mode interface and the verdict reporting structure.
- `[RESP-ADAPTER]` Implement the kernel observer and expose the live/degraded status to the
  harness.
- `[RESP-HARNESS]` Detect and report observer degradation. Enforce fail-closed behavior.
- `[RESP-MISSION]` Define the minimum qualification mode required for each mission phase.

---

## Reference Implementation Status

The following table records the qualification status of each invariant against the
Linux/eBPF reference implementation (`cfs-adversarial-testbed`, commit `6c6e0e4`).

| Invariant | ID | Linux/eBPF Status | CI Evidence |
|---|---|---|---|
| Authorization Before Dispatch | SEC-INV-01 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |
| Executor Identity and Instance Binding | SEC-INV-02 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |
| Replay and Bypass Resistance | SEC-INV-03 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |
| Independently Verified Effect Completion | SEC-INV-04 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |
| Observation-Loss Accounting | SEC-INV-05 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |
| Fail-Closed Qualification | SEC-INV-06 | PASS | [Run 41050876794](https://github.com/Exploidus/cfs-adversarial-testbed/actions/runs/41050876794) |

All other platforms: **NOT_QUALIFIED** (no independent evaluation performed).

---

## Change Log

| Version | Date | Author | Description |
|---|---|---|---|
| v0.1-draft | 2026-10-30 | Rahad Bhuiya (Exploidus Labs) | Initial draft of six invariants |
