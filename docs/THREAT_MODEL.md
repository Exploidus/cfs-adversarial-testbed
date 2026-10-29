# Threat Model & Security Boundaries for cFS Linux Testbed

## 1. Overview and Objective
This testbed defines an isolated adversarial framework to evaluate process identity, execution freshness, and independent effect verification for NASA core Flight System (cFS) components running in POSIX/Linux deployments.

Baseline cFS architectures frequently assume cooperative execution across tasks. On multi-tenant or Linux-based flight payloads, unprivileged or compromised tasks may share execution contexts. This testbed qualifies four specific adversarial threat boundaries without modifying baseline cFS code.

## 2. Threat Boundaries & Adversary Capabilities

### Threat Vector A: Same-UID Compromise and Memory Inspection
* Adversary Capability: An unprivileged or compromised process shares the same Linux User ID (UID) as the authorized flight executor.
* Attack Surface: In standard Linux configurations, processes sharing a UID can attach via ptrace(2), read virtual memory via /proc/[pid]/mem, or inspect open descriptors via /proc/[pid]/fd.
* Defense Mechanism: The testbed enforces prctl(PR_SET_DUMPABLE, 0) upon initialization of all authorized processes. This blocks ptrace attachment and restricts /proc ownership to root, preventing peer same-UID inspection. Peer credentials are verified via SO_PEERCRED at the socket layer.

### Threat Vector B: File Descriptor Inheritance and Replay
* Adversary Capability: A worker or child process spawned by the system inherits open file descriptors, or attempts to reuse an existing descriptor after process replacement.
* Attack Surface: Named pipes (FIFOs) or shared memory segments can be reopened across process restarts. Raw PIDs can be recycled by the operating system, allowing an impostor process to claim a previous identity.
* Defense Mechanism: All inter-process communication is bound to anonymous socketpairs created with SOCK_CLOEXEC. Descriptors are never exposed to the filesystem namespace and close automatically across exec boundaries.

### Threat Vector C: Compromised Executor & Falsified Self-Reports
* Adversary Capability: An executor process suffers memory corruption or logic compromise, reporting that a flight critical command was executed successfully when no physical effector operation was actually carried out.
* Attack Surface: Relying on the executor to publish a telemetry message stating "Command Executed" creates a single point of failure.
* Defense Mechanism: Enforcement and observation are decoupled. The executor process emits zero verification telemetry. Instead, an independent in-kernel eBPF probe attaches directly to the effector boundary (such as the hardware ioctl or device write syscall). The kernel constructs a tamper-evident tuple: (Instance_Start_Time, Monotonic_Seq, Target_FD, Effect_Hash). Unless this kernel event is captured, the transaction remains uncommitted.

### Threat Vector D: Event Loss and Process Restart Discontinuities
* Adversary Capability: Bursty workload conditions cause ringbuffer overflow, or a process crashes and restarts between observation cycles, attempting to disguise dropped commands as an idle window.
* Attack Surface: Observers polling userland queues cannot distinguish between an idle system and a burst of lost messages without sequence accounting.
* Defense Mechanism: Every transaction is assigned an in-kernel atomic 64-bit monotonic sequence counter stored in a pinned BPF map. Any gap in the sequence stream (seq != prev_seq + 1) marks the observation window as UNQUALIFIED: SEQUENCE_LOSS. Process instances are bound to task start times (task_struct->start_time via bpf_ktime_get_boot_ns). A restarted process creates an instance discontinuity, preventing replay across restarts.

## 3. Analysis of memfd_create Sealing Semantics
While memfd_create with F_SEAL_SEAL and F_SEAL_WRITE protects against post-seal payload mutation, sealing alone is insufficient for flight integrity verification:
1. Sealing does not guarantee append-only durability.
2. Sealing does not prevent an adversarial same-UID process holding an inherited descriptor prior to sealing from reading or timing the buffer.
3. Sealing verifies data immutability, not physical effect realization.
Consequently, this testbed treats sealed memory solely as read-only payload storage, while all causality and execution authority remain bound to kernel-mediated socketpair credentials and eBPF tracepoint probes.
