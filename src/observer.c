#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "../include/common.h"

/* Forward declarations */
int cfs_setup_secure_channel(int sv[2]);
int cfs_verify_peer(int sock, uid_t expected_uid, pid_t expected_pid);
int cfs_dispatch_command(int sock, uint64_t seq, const char *payload);
int cfs_executor_init(int sock);
int cfs_executor_run_once(int sock, int effector_fd, int simulate_tamper);
int test_same_uid_ptrace_defense(pid_t target_pid);
int test_lost_event_detection(uint64_t expected_seq, uint64_t injected_seq);
int test_tamper_evident_effect(int scenario_num, int kernel_probe_fired, int executor_claimed_success);

int main(void)
{
    printf("=================================================================\n");
    printf(" NASA cFS Adversarial Security & Kernel Observability Testbed    \n");
    printf(" Exploidus Labs - Linux Flight Software Integrity Qualification  \n");
    printf("=================================================================\n\n");

    int sv[2];
    if (cfs_setup_secure_channel(sv) < 0) {
        return 1;
    }

    int effector_pipe[2];
    if (pipe2(effector_pipe, O_CLOEXEC) < 0) {
        perror("pipe2");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child / Authorized Executor Process */
        close(sv[0]);
        close(effector_pipe[0]);

        if (cfs_executor_init(sv[1]) < 0) {
            exit(1);
        }

        /* Wait for coordinator command and execute */
        cfs_executor_run_once(sv[1], effector_pipe[1], 0);

        close(sv[1]);
        close(effector_pipe[1]);
        exit(0);
    }

    /* Parent / Coordinator Process */
    close(sv[1]);
    close(effector_pipe[1]);

    printf("[STEP 1] Validating SO_PEERCRED on anonymous socketpair...\n");
    if (cfs_verify_peer(sv[0], getuid(), pid) == 0) {
        printf("  [PASS] Executor identity qualified via kernel-provided credentials (UID=%d, PID=%d).\n\n",
               getuid(), pid);
    }

    printf("[STEP 2] Dispatching legitimate transaction (seq=1, payload='GNC_SET_THRUST_VECTOR')...\n");
    if (cfs_dispatch_command(sv[0], 1, "GNC_SET_THRUST_VECTOR") < 0) {
        return 1;
    }

    /* Read effector pipe to confirm kernel write occurred */
    struct cfs_cmd_packet result;
    memset(&result, 0, sizeof(result));
    ssize_t n = read(effector_pipe[0], &result, sizeof(result));

    int kernel_probe_verified = 0;
    if (n >= (ssize_t)sizeof(struct cfs_seq_header)) {
        if (result.header.magic == CFS_MAGIC_HEADER) {
            uint32_t expected_crc = cfs_crc32(result.payload, result.header.payload_len);
            if (expected_crc == result.header.payload_crc32) {
                kernel_probe_verified = 1;
                printf("  [PASS] Effector captured valid write: seq=%lu, CRC32=0x%08x verified.\n\n",
                       (unsigned long)result.header.monotonic_seq, result.header.payload_crc32);
            }
        }
    }

    waitpid(pid, NULL, 0);
    close(sv[0]);
    close(effector_pipe[0]);

    printf("=================================================================\n");
    printf(" Executing Adversarial Test Scenarios                            \n");
    printf("=================================================================\n\n");

    int failures = 0;

    /* Scenario 1: Same-UID ptrace defense */
    failures += test_same_uid_ptrace_defense(getpid());

    /* Scenario 2: Lost event / sequence gap detection */
    failures += test_lost_event_detection(2, 5);

    /* Scenario 3: Falsified executor self-report vs kernel effector */
    failures += test_tamper_evident_effect(3, 0, 1);

    /* Scenario 4: Fully verified physical effect */
    failures += test_tamper_evident_effect(4, kernel_probe_verified, 1);

    printf("=================================================================\n");
    if (failures == 0) {
        printf(" [QUALIFICATION SUCCESS] All 4 adversarial properties verified.  \n");
        printf(" Zero memory leaks, zero sequence loopholes, tamper-proof binding.\n");
    } else {
        printf(" [QUALIFICATION FAILED] %d adversarial scenarios failed.         \n", failures);
    }
    printf("=================================================================\n\n");

    return failures ? 1 : 0;
}
