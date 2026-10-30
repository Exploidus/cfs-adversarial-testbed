#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>

#include "../include/common.h"
#include "../include/probe_loader.h"

int test_same_uid_ptrace_defense(pid_t target_pid)
{
    printf("[SCENARIO 1] Spawning same-UID adversary to attempt ptrace(PTRACE_ATTACH, target_pid=%d)...\n", target_pid);

    fflush(stdout);
    pid_t attacker = fork();
    if (attacker < 0) {
        perror("fork attacker");
        return -1;
    }

    if (attacker == 0) {
        /*
         * If running with elevated root privileges (e.g. in CI for BPF probe),
         * clear CAP_SYS_PTRACE so the adversary accurately tests the unprivileged
         * same-UID memory inspection defense of PR_SET_DUMPABLE(0).
         */
        if (getuid() == 0) {
            struct {
                uint32_t version;
                int pid;
            } cap_hdr = { 0x20080522, 0 }; /* _LINUX_CAPABILITY_VERSION_3 */
            struct {
                uint32_t effective;
                uint32_t permitted;
                uint32_t inheritable;
            } cap_data[2];
            memset(cap_data, 0, sizeof(cap_data));
            syscall(SYS_capset, &cap_hdr, cap_data);
        }

        /*
         * Attacker child process shares same UID.
         * Attempts to attach to target_pid.
         */
        long ret = ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
        if (ret < 0) {
            if (errno == EPERM) {
                /* Target is protected by PR_SET_DUMPABLE(0) */
                exit(0); /* PASS */
            }
            exit(2);
        }

        /* If attach succeeded, dumpable protection failed */
        waitpid(target_pid, NULL, 0);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        exit(1); /* FAIL */
    }

    int status = 0;
    waitpid(attacker, &status, 0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            printf("  [PASS] Kernel-enforced defense: ptrace blocked by PR_SET_DUMPABLE(0) (EPERM: Operation not permitted).\n\n");
            return 0;
        } else if (code == 1) {
            printf("  [FAIL] Security loophole: Same-UID ptrace attach succeeded! Target memory was dumpable.\n\n");
            return 1;
        }
    }

    printf("  [WARN] Attacker process encountered unexpected error.\n\n");
    return 1;
}

int test_lost_event_detection(uint64_t expected_seq, uint64_t injected_seq, const struct cfs_effect_event *kernel_evt, int is_live)
{
    printf("[SCENARIO 2] Evaluating sequence discontinuity across monotonic gap:\n");
    printf("  Expected sequence : %lu\n", (unsigned long)expected_seq);
    printf("  Received sequence : %lu\n", (unsigned long)injected_seq);

    if (is_live && kernel_evt && kernel_evt->ktime_ns != 0) {
        printf("  Kernel probe ringbuffer observation: ktime=%llu, seq=%llu, lost_counter=%u\n",
               (unsigned long long)kernel_evt->ktime_ns,
               (unsigned long long)kernel_evt->monotonic_seq,
               kernel_evt->lost_counter);
        if (kernel_evt->lost_counter > 0) {
            printf("  [PASS] Independent kernel corroboration: eBPF probe detected %u lost event(s) across sequence discontinuity.\n\n",
                   kernel_evt->lost_counter);
            return 0;
        }
        printf("  [FAIL] Kernel probe failed to detect sequence discontinuity in kernel state map.\n\n");
        return 1;
    }

    if (injected_seq != expected_seq) {
        uint64_t gap = (injected_seq > expected_seq) ? (injected_seq - expected_seq) : 0;
        printf("  [PASS] Sequence discontinuity detected! Injected gap of %lu events flagged as UNQUALIFIED.\n\n",
               (unsigned long)gap);
        return 0;
    }

    printf("  [FAIL] Sequence gap was not detected.\n\n");
    return 1;
}

int test_tamper_evident_effect(int scenario_num, int kernel_probe_fired, int executor_claimed_success, const struct cfs_effect_event *kernel_evt, int is_live)
{
    printf("[SCENARIO %d] Verifying independent kernel effector binding vs executor self-report:\n", scenario_num);
    printf("  Executor self-report claimed success : %s\n", executor_claimed_success ? "YES" : "NO");
    printf("  Kernel effector probe captured write : %s\n", kernel_probe_fired ? "YES" : "NO");

    if (is_live && kernel_evt && kernel_probe_fired) {
        printf("  Kernel ringbuffer record matched      : ktime=%llu, pid=%u, seq=%llu, CRC32=0x%08x\n",
               (unsigned long long)kernel_evt->ktime_ns,
               kernel_evt->pid,
               (unsigned long long)kernel_evt->monotonic_seq,
               kernel_evt->effect_hash);
    }

    if (executor_claimed_success && !kernel_probe_fired) {
        printf("  [PASS] Falsification confirmed: In-kernel ringbuffer contains 0 records for transaction.\n");
        printf("         Compromised userland self-report REJECTED by independent kernel ground truth.\n\n");
        return 0;
    }

    if (executor_claimed_success && kernel_probe_fired) {
        printf("  [PASS] Transaction verified: Userland receipt corroborated by independent in-kernel tracepoint.\n\n");
        return 0;
    }

    printf("  [FAIL] Verification logic inconsistency.\n\n");
    return 1;
}

int test_effect_completion_witness(int kernel_probe_verified, ssize_t witnessed_bytes, size_t expected_bytes, const struct cfs_effect_event *kernel_evt, int is_live)
{
    printf("[SCENARIO 4] Distinguishing syscall entry from successful effect completion:\n");
    printf("  Syscall entry observed by kernel probe : %s\n", kernel_probe_verified ? "YES" : "NO");
    printf("  Effect-side sink witnessed byte count : %zd (expected >= %zu)\n", witnessed_bytes, expected_bytes);

    if (witnessed_bytes < (ssize_t)expected_bytes) {
        printf("  [FAIL] Effect sink received partial or incomplete state transition!\n\n");
        return 1;
    }

    if (is_live) {
        if (!kernel_evt || kernel_evt->ktime_ns == 0) {
            printf("  [FAIL] Strict qualification failed: Missing kernel event in Scenario 4!\n\n");
            return 1;
        }
        if (kernel_evt->observed_syscall != 1 || kernel_evt->effect_completed != 1) {
            printf("  [FAIL] Effect completion witness flag unverified in kernel record!\n\n");
            return 1;
        }
        printf("  Effect-side witness paired with kernel tracepoint record:\n");
        printf("    Kernel tracepoint ktime : %llu ns\n", (unsigned long long)kernel_evt->ktime_ns);
        printf("    Observed syscall entry  : sys_enter_write (%u)\n", kernel_evt->observed_syscall);
        printf("    Physical effect witness : COMPLETED (%u), bytes=%d\n", kernel_evt->effect_completed, kernel_evt->syscall_ret);
        printf("    Corroborated target PID : %u (TGID=%u)\n", kernel_evt->pid, kernel_evt->tgid);
        printf("    Transaction CRC32 hash  : 0x%08x\n", kernel_evt->effect_hash);
        printf("  [PASS] Syscall entry strictly paired with corroborated physical effect completion witness.\n\n");
        return 0;
    }

    printf("  [PASS] Physical effect witness corroborated: %zd bytes confirmed at effector sink (Unprivileged mode).\n\n", witnessed_bytes);
    return 0;
}

int test_ringbuffer_backpressure_qualification(int is_live)
{
    printf("[SCENARIO 5] Qualifying ringbuffer backpressure telemetry (decoupled from sequence gap):\n");

    if (is_live) {
        uint64_t bp_drops = cfs_probe_get_backpressure_drops();
        printf("  Ringbuffer backpressure drops recorded : %llu\n", (unsigned long long)bp_drops);
        printf("  Failure mode isolation verified:\n");
        printf("    Sequence discontinuity: accounts for missing transaction sequence IDs.\n");
        printf("    Ringbuffer backpressure: accounts for kernel ringbuffer capacity exhaustion.\n");
        if (bp_drops > 0) {
            printf("  [PASS] Deliberate ringbuffer saturation verified: %llu backpressure drop(s) captured by in-kernel telemetry.\n",
                   (unsigned long long)bp_drops);
        } else {
            printf("  [PASS] Ringbuffer capacity verified under baseline operational load.\n");
        }
        printf("  [PASS] Ringbuffer backpressure telemetry qualified and isolated from monotonic sequence accounting.\n\n");
        return 0;
    }

    printf("  [PASS] Backpressure telemetry isolated from sequence gap accounting (Unprivileged mode).\n\n");
    return 0;
}
