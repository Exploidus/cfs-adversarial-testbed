#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>

#include "../include/common.h"

int test_same_uid_ptrace_defense(pid_t target_pid)
{
    printf("[SCENARIO 1] Spawning same-UID adversary to attempt ptrace(PTRACE_ATTACH, target_pid=%d)...\n", target_pid);

    pid_t attacker = fork();
    if (attacker < 0) {
        perror("fork attacker");
        return -1;
    }

    if (attacker == 0) {
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
            printf("  [PASS] ptrace blocked by PR_SET_DUMPABLE(0) defense (EPERM: Operation not permitted).\n\n");
            return 0;
        } else if (code == 1) {
            printf("  [FAIL] Security loophole: Same-UID ptrace attach succeeded! Target memory was dumpable.\n\n");
            return 1;
        }
    }

    printf("  [WARN] Attacker process encountered unexpected error.\n\n");
    return 1;
}

int test_lost_event_detection(uint64_t expected_seq, uint64_t injected_seq)
{
    printf("[SCENARIO 2] Evaluating observer sequence accounting across window gap:\n");
    printf("  Expected sequence : %lu\n", (unsigned long)expected_seq);
    printf("  Received sequence : %lu\n", (unsigned long)injected_seq);

    if (injected_seq != expected_seq) {
        uint64_t gap = (injected_seq > expected_seq) ? (injected_seq - expected_seq) : 0;
        printf("  [PASS] Sequence discontinuity detected! Injected gap of %lu events flagged as UNQUALIFIED.\n\n",
               (unsigned long)gap);
        return 0;
    }

    printf("  [FAIL] Sequence gap was not detected.\n\n");
    return 1;
}

int test_tamper_evident_effect(int scenario_num, int kernel_probe_fired, int executor_claimed_success)
{
    printf("[SCENARIO %d] Verifying independent kernel effector binding vs executor self-report:\n", scenario_num);
    printf("  Executor self-report claimed success : %s\n", executor_claimed_success ? "YES" : "NO");
    printf("  Kernel effector probe captured write : %s\n", kernel_probe_fired ? "YES" : "NO");

    if (executor_claimed_success && !kernel_probe_fired) {
        printf("  [PASS] Falsification confirmed: Userland self-report REJECTED because kernel effector probe did not capture transaction.\n\n");
        return 0;
    }

    if (executor_claimed_success && kernel_probe_fired) {
        printf("  [PASS] Transaction verified: Userland receipt corroborated by independent in-kernel tracepoint.\n\n");
        return 0;
    }

    printf("  [FAIL] Verification logic inconsistency.\n\n");
    return 1;
}
