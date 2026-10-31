# Platform-Independent Security Qualification Contract

**Document ID:** CFS-SEC-CONTRACT-v0.1  
**Status:** DRAFT / NOT_QUALIFIED  
**Reference Implementation:** [cfs-adversarial-testbed](https://github.com/Exploidus/cfs-adversarial-testbed) (Linux/eBPF)  
**Discussion:** [nasa/cFS #1168](https://github.com/nasa/cFS/discussions/1168)  
**Authors:** Rahad Bhuiya (Exploidus Labs)  
**Reviewers:** Thales (bonushora)

---

> [!IMPORTANT]
> Every invariant in this document carries status **DRAFT / NOT_QUALIFIED** until independently
> evaluated against the acceptance criteria on the target platform through the full
> requirement-to-test-to-evidence traceability process defined in Section 4.
> This document does not imply certification or endorsement by NASA.
> It does not modify the portable cFS core.

> [!NOTE]
> The responsibility assignments in Section 3 (RESP-FW, RESP-MISSION, RESP-ADAPTER, RESP-HARNESS)
> represent proposed architectural boundaries for discussion and review. They are not obligations
> already established by the official cFS framework.

---

## Table of Contents

1. Purpose and Scope
2. Glossary
3. Security Invariants (SEC-INV-01 through SEC-INV-06)
4. Qualification Ladder and Evidence Traceability
5. Requirement-to-Test-to-Evidence Matrix
6. Reference Implementation Status
7. Known Implementation Boundaries
8. Scope Exclusions
9. Change Log

---

## 1. Purpose and Scope

This contract defines a set of platform-independent security invariants for flight software
built on NASA cFS. It separates two distinct concerns:

1. **Platform-Independent Security Contracts** — normative properties that must hold on any
   target platform, expressed without reference to OS-specific mechanisms or APIs.
2. **Platform-Specific Enforcement Adapters** — OS-native mechanisms that implement and
   demonstrate those properties on a given platform (e.g. Linux/eBPF, RTEMS, VxWorks).

The Linux/eBPF testbed (`cfs-adversarial-testbed`) serves as the **initial reference
implementation and adversarial qualification harness** for this contract. It demonstrates
how these invariants can be empirically evaluated without coupling the portable cFS core
to Linux-specific primitives.

Equivalent guarantees on other platforms are explicitly **NOT_QUALIFIED** until independently
demonstrated against the acceptance criteria defined here.

---

## 2. Glossary

| Term | Definition |
|------|-----------|
| **Authentication** | The act of verifying the identity of a process or entity using an independently trusted mechanism. Authentication establishes WHO is making a request. |
| **Authorization** | The act of verifying that a specific, identified entity is permitted to perform a specific action on a specific target with a specific payload, under a specific policy version. Authorization establishes WHAT is permitted. |
| **Independent Evidence** | Observation produced by a mechanism that is architecturally separated from the component under observation, such that a compromised component cannot forge or suppress the evidence without being detected. |
| **Executor Instance** | A single lifecycle of an executor process, uniquely identified by a platform-native, non-reusable binding that is invalidated upon process termination or restart. |
| **Effect Completion** | The condition in which a command has produced its intended physical or logical state transition at the declared destination, as independently witnessed. |
| **Observation Loss** | Any condition in which an event that occurred within the system is not represented in the observer's record, regardless of cause. |
| **Fail-Closed** | A qualification posture in which absence of sufficient independent evidence causes a NOT_QUALIFIED verdict, never a QUALIFIED one. |
| **Qualification Window** | A bounded time interval during which the observer's coverage and completeness have been established and within which qualification verdicts are valid. |
| **Preventive Control** | A mechanism that makes an unauthorized operation impossible to complete, independent of detection. |
| **Detective Control** | A mechanism that identifies that an unauthorized operation occurred or was attempted, after the fact. |
| **Traceability** | The property that every qualification verdict is traceable to a specific requirement, a specific test, and a specific independently produced evidence record. |

---

## 3. Security Invariants

### Requirement Notation

| Tag | Meaning |
|-----|---------|
| `[REQ]` | Normative requirement |
| `[ASSUM]` | Explicit assumption that must hold for the property to be valid |
| `[EVID]` | Required independent evidence |
| `[PASS]` | Positive acceptance criterion |
| `[ADV-PASS]` | Adversarial acceptance criterion |
| `[FAIL]` | Explicit failure or non-qualification condition |
| `[RESP-FW]` | Proposed responsibility of the portable cFS framework |
| `[RESP-MISSION]` | Proposed responsibility of the mission or application |
| `[RESP-ADAPTER]` | Proposed responsibility of the platform adapter |
| `[RESP-HARNESS]` | Proposed responsibility of the qualification harness |

---

### SEC-INV-01: Authorization Before Dispatch

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

No command shall be dispatched to an executor unless two independent conditions are
satisfied in sequence: first, the executor's identity has been verified by an
independently trusted mechanism; second, an explicit authorization decision has been
made binding the verified identity to the exact action, target, payload, policy version,
and dispatch context. Identity verification is a necessary prerequisite for authorization
but does not independently constitute authorization.

#### Normative Requirements

- `[REQ-01.1]` The dispatcher must verify executor identity via an independently trusted
  mechanism before any authorization decision is made. Userland self-attestation is not
  sufficient.
- `[REQ-01.2]` The identity verification result must be obtained from a source that cannot
  be forged by a process sharing the same UID or privilege level as the executor.
- `[REQ-01.3]` Following successful identity verification, an explicit authorization
  decision must be made and recorded. The authorization decision must be bound to the
  verified executor identity, the specific command type, the specific target, the payload
  content or digest, the active policy version, and the dispatch context.
- `[REQ-01.4]` If either identity verification or the authorization decision fails,
  dispatch must be rejected and the channel closed. No command may be dispatched in a
  partially verified state.
- `[REQ-01.5]` The authorization decision record must be independently auditable and
  must not be modifiable by the executor after the fact.

#### Threat Model and Trust Assumptions

- `[ASSUM-01.1]` A compromised peer process may share the same UID as the authorized
  executor.
- `[ASSUM-01.2]` A compromised peer process cannot forge credentials produced by an
  independently trusted identity mechanism.
- `[ASSUM-01.3]` The independently trusted identity mechanism is not under the control
  of any process sharing the executor's privilege domain.
- `[ASSUM-01.4]` An adversary may possess a valid identity credential but attempt to
  dispatch a command outside the scope of their authorization.

#### Required Evidence

- `[EVID-01.1]` Captured identity credential record produced by an independently trusted
  mechanism, showing the executor identity at the time of channel establishment.
- `[EVID-01.2]` Captured authorization decision record bound to the verified identity,
  command, target, payload digest, and policy version.
- `[EVID-01.3]` Demonstration that a peer with an incorrect identity is rejected before
  any authorization decision is made.
- `[EVID-01.4]` Demonstration that a peer with a valid identity but an unauthorized
  command, target, or payload is rejected at the authorization stage.

#### Acceptance Criteria

- `[PASS-01.1]` The dispatcher receives a valid identity credential from an independently
  trusted source. A subsequent authorization decision permits the specific command.
  Dispatch proceeds and is recorded.
- `[ADV-PASS-01.1]` A peer with a mismatched identity credential is rejected before
  any authorization decision is made. No command is dispatched.
- `[ADV-PASS-01.2]` A peer with a valid identity credential attempts to dispatch a
  command outside their authorization scope. The authorization decision rejects the
  request. No command is dispatched.

#### Failure and Non-Qualification Conditions

- `[FAIL-01.1]` Any command is dispatched before identity verification completes.
- `[FAIL-01.2]` Identity verification and authorization are conflated into a single
  undifferentiated check.
- `[FAIL-01.3]` The authorization decision is not bound to the specific command, target,
  payload, or policy version.
- `[FAIL-01.4]` A process with a valid identity but unauthorized scope successfully
  dispatches a command.
- `[FAIL-01.5]` The identity credential is produced by a userland mechanism rather than
  an independently trusted source.

#### Responsibility Boundaries

- `[RESP-FW]` Define the abstract two-stage authorization interface. Prohibit dispatch
  without prior identity verification and authorization.
- `[RESP-ADAPTER]` Implement the identity verification mechanism using platform-native
  independently trusted APIs. Implement the authorization decision and its audit record.
- `[RESP-HARNESS]` Demonstrate positive and adversarial acceptance criteria including
  both identity mismatch and scope-exceeded scenarios.
- `[RESP-MISSION]` Define the authorization policy: permitted command types, targets,
  and payload constraints for each authorized executor identity.

---

### SEC-INV-02: Executor Identity and Instance Binding

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

Each command transaction must be bound to a specific, independently verified executor
instance. A restarted or replaced executor instance must not inherit authorization from
a previous instance. The instance binding must be derived from a platform-native,
non-reusable lifecycle property that cannot be forged or replicated by a userland
process within a qualification window.

#### Normative Requirements

- `[REQ-02.1]` Each executor instance must carry a unique instance identifier derived
  from a platform-native, independently verifiable lifecycle property. The identifier
  must be non-reusable across distinct process lifecycles within any qualification window.
- `[REQ-02.2]` The instance identifier must not be derived solely from a userland-assigned
  value such as a PID, thread ID, or application-level counter, as these may be reused
  by the OS.
- `[REQ-02.3]` Command transactions must embed the current instance identifier. A
  mismatch between the embedded identifier and the current executor instance must cause
  rejection without dispatching the command.
- `[REQ-02.4]` Following an executor restart, a new instance identifier must be
  established. Prior authorization context must not be inherited without explicit
  re-verification.

#### Threat Model and Trust Assumptions

- `[ASSUM-02.1]` An adversary may restart a crashed executor and attempt to replay
  transactions bearing the previous instance's identifier.
- `[ASSUM-02.2]` The platform provides a mechanism to derive a lifecycle binding that is
  non-reusable within the qualification window and not forgeable from userland.
- `[ASSUM-02.3]` PID values alone are not sufficient as instance identifiers because
  they may be reused by the OS after process termination.

#### Required Evidence

- `[EVID-02.1]` A captured instance identifier for the executor, derived from a
  platform-native lifecycle property, embedded in each transaction header.
- `[EVID-02.2]` Demonstration that a transaction carrying a stale or mismatched instance
  identifier is rejected.
- `[EVID-02.3]` Demonstration that following a simulated executor restart, the new
  instance identifier differs from the previous one and transactions with the old
  identifier are rejected.

#### Acceptance Criteria

- `[PASS-02.1]` A transaction carrying the current instance identifier is accepted.
  The independently verified evidence record contains a matching identifier.
- `[ADV-PASS-02.1]` A transaction carrying a previous or forged instance identifier
  is detected and rejected as an instance discontinuity.
- `[ADV-PASS-02.2]` Following a simulated restart, the new executor instance receives
  a new identifier. Transactions bearing the old identifier are rejected.

#### Failure and Non-Qualification Conditions

- `[FAIL-02.1]` A restarted executor inherits the authorization context of its
  predecessor without re-verification.
- `[FAIL-02.2]` The instance identifier is derived solely from a userland-assigned
  or OS-reusable value.
- `[FAIL-02.3]` Transactions with stale instance identifiers are accepted.

#### Responsibility Boundaries

- `[RESP-FW]` Define the instance identifier field in the transaction header and the
  rejection policy for instance mismatches.
- `[RESP-ADAPTER]` Derive the instance identifier from a platform-native lifecycle
  property appropriate to the target OS (e.g. process start time on Linux, task creation
  timestamp on RTEMS, or an equivalent non-reusable binding on other platforms).
- `[RESP-HARNESS]` Inject stale and mismatched instance identifiers and verify rejection.
  Simulate executor restart and verify new instance assignment.
- `[RESP-MISSION]` Define the re-authorization procedure following an executor restart.

---

### SEC-INV-03: Replay and Bypass Resistance

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

The system must provide both preventive controls against replay and unauthorized bypass,
and independent detective controls that identify when such events occur. These two control
classes are distinct and must each be independently specified and evaluated.

A preventive control makes an unauthorized operation impossible to complete regardless of
whether it is detected. A detective control identifies that an unauthorized operation
occurred or was attempted. Replay detection alone does not constitute replay prevention.

#### Normative Requirements

**Preventive Controls:**

- `[REQ-03.1]` The channel must enforce monotonically increasing 64-bit sequence numbers
  scoped to the executor instance. A non-monotonic or out-of-order sequence must cause
  the channel to reject the transaction before any effect is produced.
- `[REQ-03.2]` The sequence enforcement mechanism must be implemented by a component
  that is not under the control of the executor process.
- `[REQ-03.3]` Protected operations (those with irreversible physical effects) must
  require a valid, non-replayed authorization credential before the operation is initiated.

**Detective Controls:**

- `[REQ-03.4]` An independent observer must record each transaction at or below the
  kernel system call boundary, in a manner that cannot be suppressed by a compromised
  executor process.
- `[REQ-03.5]` A discrepancy between executor self-report and independent observer record
  must be detected and flagged as a qualification failure.
- `[REQ-03.6]` A replayed transaction that reaches the detection boundary must be
  identified by sequence comparison and flagged, even if it was not prevented.

#### Threat Model and Trust Assumptions

- `[ASSUM-03.1]` A compromised executor may replay a previously captured transaction.
- `[ASSUM-03.2]` A compromised executor may claim to have executed a command while
  suppressing the actual operation.
- `[ASSUM-03.3]` The independent observer mechanism cannot be disabled or suppressed
  by a userland process.
- `[ASSUM-03.4]` The sequence enforcement mechanism is not bypassed by privilege
  escalation within the executor's domain.

#### Required Evidence

- `[EVID-03.1]` A record of the independent observer event for each accepted transaction,
  including sequence number, timestamp, and payload digest.
- `[EVID-03.2]` Demonstration that a replayed transaction is rejected at the preventive
  control boundary before any effect is produced.
- `[EVID-03.3]` Demonstration that a suppressed execution (executor claims success,
  operation not performed) is detected by the independent observer within the
  qualification window.
- `[EVID-03.4]` Explicit separation of the preventive and detective control evidence
  in the qualification report.

#### Acceptance Criteria

- `[PASS-03.1]` A legitimate transaction is accepted. The independent observer records
  a matching event with a non-zero timestamp and correct payload digest.
- `[ADV-PASS-03.1]` A replayed transaction is rejected by the preventive control
  before any effect is produced. The rejection is recorded.
- `[ADV-PASS-03.2]` A suppressed execution is detected by the independent observer.
  The executor self-report is rejected as inconsistent with the observer record.
- `[ADV-PASS-03.3]` A replayed transaction that evades the preventive control is
  detected by the detective control and flagged, demonstrating the detective layer
  independently of the preventive layer.

#### Failure and Non-Qualification Conditions

- `[FAIL-03.1]` A replayed transaction produces an effect at the destination.
- `[FAIL-03.2]` The observer relies on the executor's self-report as the primary
  evidence of whether an effect occurred.
- `[FAIL-03.3]` Preventive and detective controls are not independently evaluated.
- `[FAIL-03.4]` A suppressed execution is not detected within the qualification window.

#### Responsibility Boundaries

- `[RESP-FW]` Define the monotonic sequence field, the rejection policy for
  non-monotonic sequences, and the distinction between preventive and detective controls.
- `[RESP-ADAPTER]` Implement both the preventive sequence enforcement and the
  independent detective observer. Ensure the observer cannot be suppressed by the executor.
- `[RESP-HARNESS]` Inject replayed transactions, suppressed executions, and out-of-order
  sequences. Verify both preventive rejection and detective detection independently.
- `[RESP-MISSION]` Define which operations require preventive controls and which are
  covered by detective controls alone.

---

### SEC-INV-04: Independently Verified Effect Completion

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

Syscall invocation (entry), successful syscall return, sink-side byte absorption, and
the intended physical or logical destination state transition are distinct observations.
Each represents a different level of effect completion evidence. The required completion
evidence for a given command must depend on the declared effect semantics of that command
type.

A command is considered fully qualified only when all evidence levels required by its
declared effect semantics have been independently witnessed and corroborated.

#### Effect Completion Levels

| Level | Observable | Example |
|-------|-----------|---------|
| L1 | Syscall entry (requested parameters visible to the kernel) | `sys_enter_write` tracepoint |
| L2 | Syscall return (kernel reports completion, byte count returned) | `sys_exit_write` with `ret == expected_bytes` |
| L3 | Sink-side byte absorption (receiver confirms full payload received) | Pipe reader confirms N bytes absorbed |
| L4 | Destination state transition (intended physical/logical state achieved) | Actuator state confirmed, register read-back |

#### Normative Requirements

- `[REQ-04.1]` The observer must record the syscall entry event from an independently
  trusted source, including the timestamp, target PID, and payload digest (L1 evidence).
- `[REQ-04.2]` For commands requiring L2 evidence, the syscall return value and
  returned byte count must be independently captured.
- `[REQ-04.3]` For commands requiring L3 evidence, the destination sink must
  independently confirm full byte absorption, producing a witness record that includes
  the absorbed byte count and a binding to the originating transaction.
- `[REQ-04.4]` For commands requiring L4 evidence (physical actuator or state-critical
  operations), an independent destination state witness must confirm the intended state
  transition. Byte absorption alone (L3) is not sufficient for L4 qualification.
- `[REQ-04.5]` The declared required evidence level for each command type must be
  specified in the mission adapter and must not be altered by the executor after dispatch.
- `[REQ-04.6]` A qualification verdict must not be issued for an evidence level higher
  than that independently demonstrated.

#### Threat Model and Trust Assumptions

- `[ASSUM-04.1]` A syscall may be interrupted or produce a partial write. Syscall entry
  alone (L1) does not imply successful data delivery.
- `[ASSUM-04.2]` A successful syscall return (L2) does not imply the destination device
  or actuator received or acted on the payload.
- `[ASSUM-04.3]` For physical actuators, byte delivery at the interface (L3) does not
  imply the actuator achieved the intended physical state (L4).
- `[ASSUM-04.4]` The destination sink witness is independent of the executor's
  self-report.

#### Required Evidence

- `[EVID-04.1]` L1: In-kernel event record with syscall entry timestamp, PID, and
  payload digest.
- `[EVID-04.2]` L2 (where declared): Independent syscall return value and byte count.
- `[EVID-04.3]` L3 (where declared): Effector sink record confirming absorbed byte
  count and transaction binding.
- `[EVID-04.4]` L4 (where declared): Destination state witness confirming the intended
  physical or logical state transition.
- `[EVID-04.5]` Explicit pairing of all required evidence records for the same
  transaction, traceable to the same sequence number and payload digest.

#### Acceptance Criteria

- `[PASS-04.1]` All evidence levels declared for the command type are present and
  corroborated. Byte counts and payload digests match across all levels. Verdict: QUALIFIED
  at the declared level.
- `[ADV-PASS-04.1]` L1 is present but L3 is absent (partial delivery). The verdict
  is QUALIFIED at L1 only and UNQUALIFIED at L3. The partial delivery is recorded.
- `[ADV-PASS-04.2]` L3 is present but the absorbed byte count is less than the expected
  payload size. The verdict is INCOMPLETE at L3. No higher-level verdict is issued.
- `[ADV-PASS-04.3]` For a physical actuator scenario, L3 is present but L4 state
  confirmation is absent. The verdict is UNQUALIFIED at L4.

#### Failure and Non-Qualification Conditions

- `[FAIL-04.1]` A transaction is marked COMPLETED based on L1 evidence alone when L3
  or L4 is declared required.
- `[FAIL-04.2]` The sink witness is obtained from the executor process rather than from
  the receiving end of the effector channel.
- `[FAIL-04.3]` The absorbed byte count is less than the expected payload size and the
  transaction is nevertheless marked COMPLETED.
- `[FAIL-04.4]` A physical actuator command is qualified without L4 state confirmation
  when L4 is declared required.

#### Responsibility Boundaries

- `[RESP-FW]` Define the evidence level interface and the verdict rules for each level.
- `[RESP-ADAPTER]` Implement observers at each required evidence level using
  platform-native mechanisms.
- `[RESP-HARNESS]` Demonstrate each evidence level independently. Inject partial delivery
  and incomplete absorption scenarios.
- `[RESP-MISSION]` Declare the required evidence level for each command type. Define
  the L4 state witness for physical actuator commands.

---

### SEC-INV-05: Observation-Loss Accounting

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

Any gap in the observation record must be explicitly detected, quantified, attributed
to a specific loss mechanism, and reported. Four distinct observation-loss mechanisms
must be independently accounted for and must not be conflated with one another.

The absence of an observation must not be treated as evidence that a forbidden effect
did not occur unless the observer's coverage and completeness for the relevant
qualification window have been independently established.

#### Observation-Loss Mechanisms

Observation loss must be categorized into distinct, non-conflated mechanisms reflecting where in the telemetry pipeline the gap occurred:

| Mechanism | Pipeline Boundary | Description | Reference / Example |
|---|---|---|---|
| **TXN-GAP** | Channel Ingress | Transaction sequence discontinuity: observed sequence is not the expected successor of the last verified sequence number. | Ingress sequence jumps from 3 to 7 (gap of 3). |
| **PROD-DROP** | Observation Producer | Discard of an observation event at the producer boundary before entering the transport channel (e.g. buffer exhaustion or rate-limit saturation). | eBPF ringbuffer reservation fails under burst; drop counter increments. |
| **CONS-DELAY** | Observation Consumer | Delayed delivery: event is not retrieved within the nominal polling interval or read deadline, but remains queued in the transport channel and is subsequently retrieved and verified intact before window evaluation. | Reader scheduling latency where event arrives after read timeout but before window close. |
| **CONS-LOSS** | Observation Consumer | Confirmed consumer loss: event was successfully placed into the transport channel by the producer, but was irrevocably lost before consumption due to verified transport overwrite, reader overrun, or queue corruption. | Consumer channel overrun counter increments, or consumer-side sequence skip confirmed against producer sequence. |
| **CONS-UNRESOLVED** | Observation Consumer | Unresolved consumer status: a read deadline expired without confirmation from the transport channel whether the event was dropped or remains pending. Must transition to `EOW-UNRESOLVED` if not resolved prior to window closure. | Reader timeout where channel state is indeterminate at evaluation time. |
| **EOW-UNRESOLVED** | Window Boundary | End-of-window unresolved event: an event remained in-flight or in an unconfirmed status at the close of the qualification window and its outcome cannot be definitively determined. | Observer shutdown or window close while in-flight transactions remain uncorroborated. |

#### Normative Requirements

- `[REQ-05.1]` The observer must maintain an independently trusted monotonic sequence
  accounting mechanism that cannot be manipulated by the component under observation.
  Any sequence discontinuity must be attributed to TXN-GAP and recorded separately from
  other loss mechanisms. Kernel-side accounting (e.g. an in-kernel state map or eBPF
  array counter on Linux) represents a platform-specific reference implementation; on
  hypervisor, RTOS, or bare-metal targets, equivalent independently trusted accounting
  (such as hypervisor memory pages or hardware register counters) must be provided.
- `[REQ-05.2]` The observation producer must maintain an independent drop counter for
  events discarded before entering the transport channel (PROD-DROP). This counter must
  be readable independently of the sequence gap counter.
- `[REQ-05.3]` The observation consumer must explicitly distinguish between delayed
  delivery (`CONS-DELAY`), confirmed channel loss (`CONS-LOSS`), and unresolved observation
  status (`CONS-UNRESOLVED`). A simple read timeout must not be treated as confirmed loss
  without corroborating transport channel evidence (e.g. consumer overrun counter increment
  or transport sequence skip). Any unresolved consumer status remaining at window evaluation
  must transition to `EOW-UNRESOLVED`.
- `[REQ-05.4]` At the close of each qualification window, in-flight events that were
  not resolved must be recorded as EOW-UNRESOLVED.
- `[REQ-05.5]` A qualification window containing any unresolved observation gap of any
  type must be reported as UNQUALIFIED for the affected transactions until the gap is
  attributed to a specific mechanism and accounted for.
- `[REQ-05.6]` Demonstrating zero PROD-DROP in a baseline test does not qualify the
  system's ability to detect and account for deliberate saturation. Saturation detection
  requires a separate adversarial test producing non-zero PROD-DROP events.

#### Threat Model and Trust Assumptions

- `[ASSUM-05.1]` Bursty event production may exhaust the transport channel, causing
  PROD-DROP events independent of transaction sequence numbering.
- `[ASSUM-05.2]` A compromised component may intentionally generate events at a rate
  designed to exhaust the observer's transport channel, causing PROD-DROP events that
  mask the original transaction sequence.
- `[ASSUM-05.3]` Absence of an observation event does not prove absence of the
  underlying effect, unless the observer's coverage for the window has been established.

#### Required Evidence

- `[EVID-05.1]` TXN-GAP: Independently trusted sequence discontinuity counter per sequence
  gap, derived from the platform-specific trusted sequence state mechanism (e.g. kernel-side
  sequence state map in Linux/eBPF reference adapter).
- `[EVID-05.2]` PROD-DROP: Independent producer-side drop counter for the qualification
  window, derived from the observation producer's accounting mechanism.
- `[EVID-05.3]` Consumer observation record documenting: (a) confirmed consumer drops
  corroborated by transport-layer drop/overrun metrics (`CONS-LOSS`), (b) delayed delivery
  timestamps where events arrived after nominal deadline (`CONS-DELAY`), and (c) explicit
  identification of unresolved observation timeouts (`CONS-UNRESOLVED`).
- `[EVID-05.4]` EOW-UNRESOLVED: Explicit record of unresolved in-flight events at
  window close.
- `[EVID-05.5]` A baseline test demonstrating zero PROD-DROP under normal load.
- `[EVID-05.6]` A separate adversarial saturation test demonstrating non-zero PROD-DROP
  under deliberate saturation, with the drop counter correctly reflecting the saturation.

#### Acceptance Criteria

- `[PASS-05.1]` A deliberate TXN-GAP is detected. The independently trusted lost-event
  counter reflects the exact number of missing transactions. PROD-DROP, consumer-side
  loss mechanisms, and EOW-UNRESOLVED counters are unaffected.
- `[PASS-05.2]` Deliberate PROD-DROP saturation is demonstrated. The producer-side
  drop counter reflects the correct number of dropped events. TXN-GAP counter is
  unaffected.
- `[ADV-PASS-05.1]` Both TXN-GAP and PROD-DROP occur simultaneously. Each counter
  independently reflects only its own contribution.
- `[ADV-PASS-05.2]` Observer coverage is established for a qualification window.
  Absence of an event in the record is correctly attributed to a specific mechanism
  rather than treated as evidence of absence of effect.

#### Failure and Non-Qualification Conditions

- `[FAIL-05.1]` A TXN-GAP is attributed to PROD-DROP without independent evidence.
- `[FAIL-05.2]` PROD-DROP events are attributed to TXN-GAP without independent evidence.
- `[FAIL-05.3]` Any observation gap is silently ignored or suppressed.
- `[FAIL-05.4]` Zero PROD-DROP in a baseline test is used to qualify saturation
  detection capability without a separate adversarial saturation test.
- `[FAIL-05.5]` Absence of observation is treated as proof of absence of effect without
  establishing observer coverage for the window.
- `[FAIL-05.6]` Treating a consumer read timeout as confirmed loss (`CONS-LOSS`) without
  corroborating transport channel evidence.

#### Responsibility Boundaries

- `[RESP-FW]` Define the four-mechanism observation-loss reporting interface and the
  qualification window rules.
- `[RESP-ADAPTER]` Implement independent counters for each mechanism using
  platform-native accounting (e.g. eBPF array maps on Linux for TXN-GAP and PROD-DROP).
- `[RESP-HARNESS]` Inject each loss mechanism independently and verify correct
  attribution. Run baseline and adversarial saturation tests separately.
- `[RESP-MISSION]` Define the acceptable observation-loss budget for each mechanism
  in each mission profile.

---

### SEC-INV-06: Fail-Closed Qualification

**Status:** DRAFT / NOT_QUALIFIED

#### Security Property

The qualification harness must default to a NOT_QUALIFIED verdict in the absence of
sufficient independently trusted evidence for the declared evidence level. Absence of
a failure observation must not be interpreted as evidence of correct operation unless
the observer's coverage and completeness for the relevant qualification window have
been independently established.

The requirement for independence is platform-neutral: it does not universally mandate
kernel-level evidence. Different platforms may establish independence through different
trusted mechanisms appropriate to their architecture. What must be guaranteed is that
the evidence cannot be forged or suppressed by the component under evaluation.

#### Operating Modes

| Mode | Independent Evidence Source | Default Verdict Without Evidence |
|------|-----------------------------|----------------------------------|
| **Live-Kernel** | In-kernel observer (e.g. eBPF tracepoint on Linux) | NOT_QUALIFIED |
| **Hypervisor** | Hypervisor-level monitor | NOT_QUALIFIED |
| **RTOS-Native** | OS-provided task monitoring API | NOT_QUALIFIED |
| **Unprivileged** | No independent evidence available | EXPLICITLY UNVERIFIED (not QUALIFIED) |

#### Normative Requirements

- `[REQ-06.1]` The qualification harness must operate in an explicitly declared mode,
  with the mode identifier included in the qualification report.
- `[REQ-06.2]` In any mode with an available independent evidence source, a missing or
  invalid evidence record for a transaction must cause an immediate NOT_QUALIFIED verdict.
  Fallback to userland self-report is prohibited.
- `[REQ-06.3]` Every qualification verdict must be traceable to an explicit evidence
  record produced by the declared independent source.
- `[REQ-06.4]` A verdict produced without a traceable evidence record is invalid,
  regardless of the operating mode.
- `[REQ-06.5]` Observer degradation (independent evidence source unavailable or
  producing no events) must be detected and reported. Silence from the observer must
  not be treated as a positive result.
- `[REQ-06.6]` Absence of a failure observation must not be treated as proof that a
  forbidden effect did not occur unless the observer's coverage for the qualification
  window has been independently established.

#### Threat Model and Trust Assumptions

- `[ASSUM-06.1]` A misconfigured or degraded independent observer may silently fail to
  produce evidence. Silence must not be treated as a positive result.
- `[ASSUM-06.2]` A compromised component may attempt to suppress evidence from the
  independent observer without disabling the observer entirely.
- `[ASSUM-06.3]` In unprivileged mode, no independent evidence is available. Verdicts
  in this mode are explicitly UNVERIFIED and must not be elevated to QUALIFIED status.

#### Required Evidence

- `[EVID-06.1]` Explicit mode indicator in the qualification report (Live-Kernel,
  Hypervisor, RTOS-Native, or Unprivileged).
- `[EVID-06.2]` In any mode with an independent evidence source: at least one valid
  evidence record per qualified transaction, produced by the declared source.
- `[EVID-06.3]` Demonstration that a missing evidence record causes an immediate
  NOT_QUALIFIED verdict with no fallback.
- `[EVID-06.4]` Demonstration that observer degradation is detected and reported.
- `[EVID-06.5]` Established observer coverage record for the qualification window.

#### Acceptance Criteria

- `[PASS-06.1]` All qualified transactions have a corresponding valid evidence record
  from the declared independent source. The mode is correctly reported. Verdict: QUALIFIED.
- `[ADV-PASS-06.1]` The independent observer is degraded or disabled. The harness
  detects the absence of evidence and immediately reports NOT_QUALIFIED. No fallback
  to userland verification occurs.
- `[ADV-PASS-06.2]` The harness operates in unprivileged mode. The mode is explicitly
  reported as UNVERIFIED. No QUALIFIED verdict is issued.
- `[ADV-PASS-06.3]` Observer coverage is not established for a qualification window.
  Absence of failure observations is not treated as proof of correct operation.

#### Failure and Non-Qualification Conditions

- `[FAIL-06.1]` A QUALIFIED verdict is issued without a traceable evidence record from
  the declared independent source.
- `[FAIL-06.2]` Fallback to userland verification occurs when independent evidence is
  unavailable in a mode that requires it.
- `[FAIL-06.3]` The qualification mode is not explicitly reported.
- `[FAIL-06.4]` Observer silence is treated as a positive result.
- `[FAIL-06.5]` Absence of failure observation is treated as proof of correct operation
  without established observer coverage.

#### Responsibility Boundaries

- `[RESP-FW]` Define the qualification mode interface and the verdict reporting structure.
- `[RESP-ADAPTER]` Implement the independent observer for the target platform and expose
  the live/degraded status and coverage record to the harness.
- `[RESP-HARNESS]` Detect and report observer degradation. Enforce fail-closed behavior.
  Establish and record observer coverage for each qualification window.
- `[RESP-MISSION]` Define the minimum required operating mode for each mission phase.

---

## 4. Qualification Ladder and Evidence Traceability

### Qualification Ladder

The following ladder defines four levels of assurance. A higher level subsumes all lower-level requirements.

| Level | Name | Description |
|---|---|---|
| **QL-1** | Structural | The specification compiles, deploys, and executes without runtime or configuration faults. |
| **QL-2** | Functional | Positive acceptance criteria pass for requirements in the declared operating mode.<br><br>- **Partial QL-2 Coverage**: Positive acceptance criteria demonstrated for an evaluated subset of normative requirements across one or more invariants, with all remaining capabilities explicitly tracked and flagged as `NOT_QUALIFIED`.<br>- **Full QL-2 Achievement**: Positive acceptance criteria independently demonstrated across **all 33 normative requirements for all six invariants** in the declared operating mode, with zero open requirement gaps. |
| **QL-3** | Adversarial | Adversarial acceptance criteria pass for evaluated invariants. Preventive and detective controls are independently evaluated.<br><br>- **Partial QL-3 Capability**: Demonstrated adversarial rejection and tamper-evident detection for specific implemented threat scenarios.<br>- **Full QL-3 Achievement**: All adversarial acceptance criteria across all six invariants pass under both isolated and concurrent stress conditions. |
| **QL-4** | Independently Reviewed | A qualified, independent reviewer has audited the full requirement-to-test-to-evidence traceability chain and verified that all normative requirements and open items have been satisfied. |

As of commit `07a1959`, the Linux/eBPF reference implementation demonstrates **Partial QL-2 coverage** and **Partial QL-3 capability** across evaluated requirements. **Full QL-2 achievement** and **Full QL-3 achievement** remain **NOT_QUALIFIED** because several required capabilities (e.g., REQ-01.3 per-command authorization decisions, REQ-02.4 post-restart re-binding, REQ-03.3 pre-effect replay prevention, REQ-04.4 physical actuator state witness, REQ-05.2/05.6 adversarial ringbuffer saturation, and REQ-06.5 observer degradation detection) remain open.

**QL-4 is IN PROGRESS** via the peer review process in this Draft PR.

### Evidence Traceability Process

Every qualification verdict must be traceable through the following chain:

```
[NORMATIVE REQUIREMENT] --> [TEST CASE] --> [EVIDENCE RECORD] --> [VERDICT]
```

A verdict without a complete chain is invalid. The requirement-to-test-to-evidence matrix in Section 5 covers all 33 normative requirements defined in this specification.

---

## 5. Requirement-to-Test-to-Evidence Traceability Matrix

The following matrix maps every normative requirement across all six invariants to its corresponding qualification test case, independent evidence record, demonstration status on the Linux/eBPF reference implementation, and qualification verdict.

| Requirement ID | Normative Requirement Summary | Test Case | Independent Evidence Record | Demonstrated (Linux/eBPF) | Qualification Verdict |
|---|---|---|---|---|---|
| **REQ-01.1** | Independent executor identity verification before dispatch | TC-01-AUTH-POS | EVID-01.1: Kernel `SO_PEERCRED` record (UID=0, PID=executor) | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-01.2** | Identity verification derived from tamper-evident source | TC-01-AUTH-FORGE | EVID-01.1: Kernel socket credentials immutable by unprivileged peer | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-01.3** | Per-command authorization decision bound to identity & payload | TC-01-AUTHZ-POS | EVID-01.2: Independent authorization decision record | PARTIAL (identity verified; per-command ACL not implemented) | **NOT_QUALIFIED** at QL-2 |
| **REQ-01.4** | Immediate channel closure on authentication/authorization failure | TC-01-ADV-ID | EVID-01.3: Rejection of mismatched identity / unverified dispatch | YES (CI run 41100184733) | PASS at Partial QL-3 |
| **REQ-01.5** | Immutable, independently auditable authorization decision record | TC-01-AUDIT-IMMUT | EVID-01.2: Audit log maintained outside executor address space | PARTIAL (coordinator log isolated; cryptographic audit chain open) | **NOT_QUALIFIED** at QL-2 |
| **REQ-02.1** | Non-reusable platform-native instance identifier | TC-02-INST-POS | EVID-02.1: Lifecycle identifier embedded in transaction header | YES (CLOCK_BOOTTIME boot_ns bound) | PASS at Partial QL-2 |
| **REQ-02.2** | Instance identifier independent of reusable userland PID/TID | TC-02-INST-DERIV | EVID-02.1: Nanosecond boot timestamp bound to kernel process creation | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-02.3** | Channel rejects commands with mismatched instance identifier | TC-02-INST-VERIFY | EVID-02.2: Channel rejection record on stale instance ID | PARTIAL (instance header embedded; rejection logic baseline only) | **NOT_QUALIFIED** at QL-2 |
| **REQ-02.4** | Mandatory re-authorization and new instance identifier on restart | TC-02-RESTART | EVID-02.3: Invalidation of prior instance credentials following restart | NOT DEMONSTRATED | **NOT_QUALIFIED** |
| **REQ-03.1** | Channel enforces monotonic 64-bit sequence numbers | TC-03-SEQ-POS | EVID-03.1: Monotonic sequence verified in observer record | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-03.2** | Sequence enforcement implemented outside executor control | TC-03-SEQ-BOUND | EVID-03.4: Channel state machine isolated in coordinator socketpair | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-03.3** | Pre-effect preventive rejection of replayed/unauthorized commands | TC-03-PREVENT | EVID-03.2: Replayed transaction rejected prior to physical effect | NOT INDEPENDENTLY DEMONSTRATED | **NOT_QUALIFIED** |
| **REQ-03.4** | Independent observer records each transaction at/below syscall level | TC-03-OBS-SYS | EVID-04.1: In-kernel eBPF tracepoint probe on `raw_tracepoint/sys_enter` | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-03.5** | Discrepancy between executor self-report and observer detected | TC-03-ADV-SUPPRESS | EVID-03.3: Executor ack=1 detected as discrepant against zero kernel probe events | YES (CI run 41100184733) | PASS at Partial QL-3 |
| **REQ-03.6** | Replayed transaction reaching detection boundary flagged | TC-03-ADV-REPLAY-DET | EVID-03.1: Out-of-order/replayed sequence comparison flags transaction | YES (CI run 41100184733) | PASS at Partial QL-3 |
| **REQ-04.1** | L1: Syscall entry event recorded from independently trusted source | TC-04-L1 | EVID-04.1: `raw_tracepoint/sys_enter` event with PID, ktime, CRC32 | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-04.2** | L2: Syscall return value and byte count independently captured | TC-04-L2 | EVID-04.2: `sys_exit` tracepoint capturing return value and bytes written | NOT DEMONSTRATED (sys_enter entry count proxy only) | **NOT_QUALIFIED** at QL-2 |
| **REQ-04.3** | L3: Effector sink independently confirms full byte absorption | TC-04-L3 | EVID-04.3: Effector pipe reader confirms absorbed bytes bound to transaction | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-04.4** | L4: Independent destination physical/logical state witness | TC-04-L4 | EVID-04.4: Independent physical actuator state transition witness | NOT APPLICABLE (pipe effector testbed; no physical actuator) | **NOT_QUALIFIED** for physical actuators |
| **REQ-04.5** | Declared evidence level fixed in adapter, immutable by executor | TC-04-LEVEL-DECL | EVID-04.5: Harness configuration enforces declared L1+L3 level | YES (testbed configuration immutable by executor) | PASS at Partial QL-2 |
| **REQ-04.6** | Qualification verdict bounded to independently demonstrated level | TC-04-LEVEL-ENFORCE | EVID-04.5: Strict qualification harness enforces L1+L3 ceiling | YES (zero claim of L4 in harness reports) | PASS at Partial QL-2 |
| **REQ-05.1** | Independently trusted sequence discontinuity accounting (TXN-GAP) | TC-05-TXN-GAP | EVID-05.1: Independent sequence gap counter detects discontinuity | YES (CI run 41100184733, seq gap of 3 detected) | PASS at Partial QL-3 |
| **REQ-05.2** | Independent producer drop counter for buffer saturation (PROD-DROP) | TC-05-PROD-DROP | EVID-05.2: Producer drop counter (eBPF ringbuf reserve failure) | NOT DEMONSTRATED (zero-drop baseline only) | **NOT_QUALIFIED** |
| **REQ-05.3** | 3-state consumer observation accounting (DELAY, LOSS, UNRESOLVED) | TC-05-CONS-LOSS | EVID-05.3: Separation of CONS-DELAY, CONS-LOSS, and CONS-UNRESOLVED | NOT DEMONSTRATED (read timeout treated uniformly) | **NOT_QUALIFIED** |
| **REQ-05.4** | In-flight transactions recorded as EOW-UNRESOLVED at window close | TC-05-EOW-UNRESOLVED | EVID-05.4: Formal EOW accounting ledger at qualification window boundary | NOT DEMONSTRATED | **NOT_QUALIFIED** |
| **REQ-05.5** | Unclassified observation gap causes immediate UNQUALIFIED verdict | TC-05-GAP-UNQUAL | EVID-05.5: Fail-closed verdict on unclassified observation gap | YES (strict mode rejects unclassified missing events) | PASS at Partial QL-3 |
| **REQ-05.6** | Adversarial saturation test producing non-zero PROD-DROP | TC-05-SAT-ADV | EVID-05.6: Deliberate producer saturation producing non-zero drop counts | NOT DEMONSTRATED | **NOT_QUALIFIED** |
| **REQ-06.1** | Qualification harness explicitly reports operating mode | TC-06-MODE | EVID-06.1: Report explicitly indicates Live-Kernel mode | YES (Live-Kernel mode reported) | PASS at Partial QL-2 |
| **REQ-06.2** | Fail-closed NOT_QUALIFIED verdict on missing evidence | TC-06-FAILCLOSED | EVID-06.3: Immediate NOT_QUALIFIED verdict on missing kernel event | YES (strict verification mode, zero fallback) | PASS at Partial QL-3 |
| **REQ-06.3** | Every qualification verdict traceable to independent evidence source | TC-06-TRACEABLE | EVID-06.2: Every pass verdict bound to non-zero ktime_ns kernel event | YES (CI run 41100184733) | PASS at Partial QL-2 |
| **REQ-06.4** | Untraceable verdicts declared invalid across all operating modes | TC-06-INVALID-VERDICT | EVID-06.2: Rejection of verdicts lacking independent evidence record | YES (harness error exit on absent evidence) | PASS at Partial QL-2 |
| **REQ-06.5** | Observer degradation or silence during runtime detected and reported | TC-06-DEGRADE | EVID-06.4: Harness flags observer probe failure / silence as degraded | NOT DEMONSTRATED (initialization probe check only) | **NOT_QUALIFIED** |
| **REQ-06.6** | Observer coverage window verified before negative proof evaluated | TC-06-COVERAGE | EVID-06.5: Explicit observer coverage window verified before negative proof | NOT DEMONSTRATED | **NOT_QUALIFIED** |

---

## 6. Reference Implementation Status

The following table records the qualification status of each invariant against the
Linux/eBPF reference implementation as of commit `07a1959`.

> [!IMPORTANT]
> **Normative Status Declaration:** In accordance with the fail-closed qualification policy
> (SEC-INV-06) and the qualification ladder criteria (Section 4), **all six invariants retain
> normative status DRAFT / NOT_QUALIFIED** until requirement-level evidence is complete across
> all 33 normative requirements and independent review criteria (QL-4) are fully satisfied.
> The "Demonstrated Implementation Scope" column reflects partial implementation progress under
> testbed conditions, not full qualification achievement.

| Invariant | ID | CI Test Status | Demonstrated Implementation Scope | Open Normative Items | Overall Invariant Status |
|---|---|---|---|---|---|
| Authorization Before Dispatch | SEC-INV-01 | PASS | Identity verification via kernel `SO_PEERCRED` (REQ-01.1, REQ-01.2, REQ-01.4) | REQ-01.3 (per-command authorization), REQ-01.5 (immutable audit chain) | **DRAFT / NOT_QUALIFIED** |
| Executor Identity and Instance Binding | SEC-INV-02 | PASS | Platform-native instance binding via boot_ns (REQ-02.1, REQ-02.2) | REQ-02.3 (full instance verification), REQ-02.4 (post-restart invalidation) | **DRAFT / NOT_QUALIFIED** |
| Replay and Bypass Resistance | SEC-INV-03 | PASS | Monotonic sequence (REQ-03.1), boundary separation (REQ-03.2), in-kernel observation (REQ-03.4), suppressed execution detection (REQ-03.5), replay detection (REQ-03.6) | REQ-03.3 (pre-effect preventive replay rejection) | **DRAFT / NOT_QUALIFIED** |
| Independently Verified Effect Completion | SEC-INV-04 | PASS | Paired L1 syscall entry + L3 pipe sink byte absorption witness (REQ-04.1, REQ-04.3, REQ-04.5, REQ-04.6) | REQ-04.2 (L2 sys_exit witness), REQ-04.4 (L4 physical actuator state witness) | **DRAFT / NOT_QUALIFIED** |
| Observation-Loss Accounting | SEC-INV-05 | PASS | Platform-independent TXN-GAP detection (REQ-05.1), unclassified gap rejection (REQ-05.5) | REQ-05.2 (producer drop counter), REQ-05.3 (3-state consumer loss accounting), REQ-05.4 (EOW accounting), REQ-05.6 (adversarial saturation) | **DRAFT / NOT_QUALIFIED** |
| Fail-Closed Qualification | SEC-INV-06 | PASS | Explicit Live-Kernel mode (REQ-06.1), strict fail-closed rejection with zero userland fallback (REQ-06.2, REQ-06.3, REQ-06.4) | REQ-06.5 (observer degradation detection during runtime), REQ-06.6 (window coverage verification) | **DRAFT / NOT_QUALIFIED** |

All other platforms (RTEMS, VxWorks, bare-metal): **NOT_QUALIFIED** (no evaluation performed).

---

## 7. Known Implementation Boundaries

The following boundaries were identified during development and adversarial testing of
the Linux/eBPF reference implementation. They are documented here to inform future
adapter implementations and to avoid carrying hidden assumptions into the normative contract.

1. **eBPF verifier constraints:** The eBPF program verifier imposes strict loop bounds
   and stack size limits. Complex per-packet state machines must be decomposed into
   tail calls or map-based state. This is a Linux-specific constraint and must not
   appear in the platform-neutral contract.

2. **PID vs TGID in multi-threaded executors:** On Linux, `bpf_get_current_pid_tgid`
   returns both PID and TGID. In a multi-threaded executor, the TGID identifies the
   process and the PID identifies the thread. The target filter must match against TGID
   for process-level qualification.

3. **Ringbuffer event ordering:** The eBPF ringbuffer does not guarantee that events
   from concurrent CPUs are delivered in strict wall-clock order. Sequence numbers
   provide logical ordering independent of delivery order.

4. **sys_enter vs sys_exit tracepoints:** The current reference implementation uses
   `sys_enter_write` (L1 evidence) with the requested byte count as a proxy for L2.
   A true L2 witness requires a correlated `sys_exit_write` observation with the
   actual return value. This is a known gap documented in the traceability matrix.

5. **Physical state witness (L4):** The pipe-based effector in the reference testbed
   cannot demonstrate L4 physical state transition. L4 qualification requires a
   hardware-in-the-loop or hardware-simulation extension.

6. **Observer coverage in multi-CPU environments:** Under high CPU load, the eBPF
   ringbuffer may experience PROD-DROP events. Observer coverage must be explicitly
   established before treating absence of events as meaningful.

---

## 8. Scope Exclusions

The following are explicitly outside the scope of this contract:

- **Cryptographic authentication:** This contract does not specify cryptographic
  key management, certificate validation, or signature verification. These may be
  required by specific mission security policies but are not defined here.
- **Network transport security:** This contract addresses local IPC between processes
  on the same platform. Networked command distribution is out of scope.
- **Software supply chain integrity:** This contract does not address the integrity
  of the executor binary, libraries, or build toolchain.
- **Hardware fault tolerance:** This contract addresses adversarial behavior. Hardware
  faults, radiation effects, and electromagnetic interference are out of scope.
- **Certification claims:** This document is a qualification specification, not a
  certification artifact. It does not constitute or imply DO-178C, IEC 61508, or
  any other certification compliance.
- **NASA endorsement:** This document is a community research artifact. It does not
  represent an official NASA requirement, standard, or policy.

---

## 9. Change Log

| Version | Date | Author | Description |
|---|---|---|---|
| v0.1-draft | 2026-10-30 | Rahad Bhuiya (Exploidus Labs) | Initial draft of six invariants |
| v0.1-r1 | 2026-10-30 | Rahad Bhuiya (Exploidus Labs) | Addressed review comments: separated authentication from authorization (INV-01), made instance binding platform-neutral (INV-02), separated preventive from detective controls (INV-03), added four-level effect completion model (INV-04), defined four distinct observation-loss mechanisms (INV-05), made fail-closed requirement platform-neutral (INV-06), added qualification ladder, requirement-to-test-to-evidence matrix, glossary, known implementation boundaries, and scope exclusions |

