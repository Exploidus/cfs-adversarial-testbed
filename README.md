# NASA cFS Adversarial Security & Kernel Observability Testbed

An isolated, minimal C and eBPF testbed designed to qualify process identity, execution freshness, and independent effect verification for NASA core Flight System (cFS) components on Linux without modifying baseline cFS code.

Developed by Exploidus Labs in collaboration with the cFS flight software security research community.

## Context & Origin
This reference testbed was formulated and developed to evaluate the adversarial security qualification boundaries and kernel observability requirements discussed in [NASA cFS Discussion #1168](https://github.com/nasa/cFS/discussions/1168). It serves as an independent experimental reference to qualify flight software components on Linux without perturbing upstream cFS baselines.

## Background & Objective
Flight software executing on Linux platforms requires robust adversarial boundaries against compromised peer processes sharing the same UID, descriptor inheritance leaks, and falsified userland self-reports.

This testbed provides concrete, falsifiable tests for four core properties:
1. Same-UID Isolation: Blocking memory snooping and ptrace attachment from peer processes via `prctl(PR_SET_DUMPABLE, 0)` and `SO_PEERCRED`.
2. Anonymous IPC Binding: Eliminating filesystem-visible queues and inherited descriptor leaks using anonymous `socketpair` with `SOCK_CLOEXEC`.
3. Independent Effector Telemetry: Capturing physical effector events via in-kernel eBPF tracepoints rather than trusting executor self-reporting.
4. Loss & Restart Qualification: Detecting observation discontinuities across bursty event loss and crash-restart cycles via 64-bit monotonic sequence accounting and task start-time tracking.

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
                                    |   - sys_enter_write tracepoint
                                    |   - Monotonic 64-bit sequence check
                                    |   - Instance start-time tracking
                                    |   - Ringbuffer drop counter
                                    v
                            [ Independent Observer ]
                                - Validates 3-point correlation
                                - Flags unqualified loss windows
```

## Repository Structure
* `include/common.h`: Shared wire packet structures, monotonic sequence headers, and eBPF event definitions.
* `src/coordinator.c`: Channel setup, peer credential verification, and monotonic command dispatching.
* `src/executor.c`: Authorized command execution and effector syscall generation.
* `src/adversary.c`: Adversarial test suite simulating same-UID ptrace, sequence loss, and falsified reports.
* `src/observer.c`: Testbed coordinator, observer logic, and automated qualification harness.
* `bpf/effect_monitor.bpf.c`: eBPF in-kernel effector and sequence accounting probe.
* `docs/THREAT_MODEL.md`: Full threat boundary specifications and analysis of `memfd_create` sealing semantics.

## Prerequisites
* Linux Kernel 5.8+ (with BPF ringbuffer support enabled)
* GCC or Clang
* Make
* libbpf-dev (optional, for compiling in-kernel eBPF probe)

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

## Test Output & Qualification Matrix
When executed, the testbed runs four automated scenarios:
* Step 1: Validates `SO_PEERCRED` on anonymous socketpair (PASS: Identity verified).
* Step 2: Dispatches legitimate transaction seq=1 to effector (PASS: Corroborated by kernel probe).
* Step 3 / Scenario 1: Simulates same-UID `ptrace(PTRACE_ATTACH)` attack (PASS: Blocked by `EPERM`).
* Step 3 / Scenario 2: Simulates sequence discontinuity / event loss (PASS: Flagged as UNQUALIFIED).
* Step 3 / Scenario 3: Simulates falsified executor self-report without kernel effect (PASS: Falsification confirmed).
* Step 3 / Scenario 4: Verifies genuine physical effector syscall (PASS: Qualified).

## License
Dual BSD/GPL or Apache 2.0 (standard for NASA cFS and Linux eBPF tools).
