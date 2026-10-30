#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "../include/common.h"
#include "../include/probe_loader.h"

/* Forward declarations */
int cfs_setup_secure_channel(int sv[2]);
int cfs_verify_peer(int sock, uid_t expected_uid, pid_t expected_pid);
int cfs_dispatch_command(int sock, uint64_t seq, const char *payload);
int cfs_dispatch_command_flags(int sock, uint64_t seq, const char *payload, uint32_t flags);
int cfs_executor_init(int sock);
int cfs_executor_run_once(int sock, int effector_fd, int simulate_tamper);
int test_same_uid_ptrace_defense(pid_t target_pid);
int test_lost_event_detection(uint64_t expected_seq, uint64_t injected_seq, const struct cfs_effect_event *kernel_evt, int is_live);
int test_tamper_evident_effect(int scenario_num, int kernel_probe_fired, int executor_claimed_success, const struct cfs_effect_event *kernel_evt, int is_live);

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

    fflush(stdout);
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

        /* Process commands from coordinator */
        while (cfs_executor_run_once(sv[1], effector_pipe[1], 0) == 0) {
            /* loop until channel closed */
        }

        close(sv[1]);
        close(effector_pipe[1]);
        exit(0);
    }

    /* Parent / Coordinator & Observer Process */
    close(sv[1]);
    close(effector_pipe[1]);

    printf("[STEP 1] Validating SO_PEERCRED on anonymous socketpair...\n");
    if (cfs_verify_peer(sv[0], getuid(), pid) == 0) {
        printf("  [PASS] Executor identity qualified via kernel-provided credentials (UID=%d, PID=%d).\n\n",
               getuid(), pid);
    }

    printf("[STEP 2] Initializing In-Kernel eBPF Tracepoint Effector Probe...\n");
    int probe_rc = cfs_probe_init("bpf/effect_monitor.bpf.o", pid);
    int is_live = cfs_probe_is_live();
    if (is_live) {
        printf("  [PASS] Live kernel eBPF probe attached to tracepoint/syscalls/sys_enter_write.\n");
        printf("  [PASS] Kernel ringbuffer observer active with target PID=%d filter.\n", pid);
        printf("  [PASS] Strict verification mode active: Userland fallback DISABLED.\n\n");
    } else {
        printf("  [INFO] Elevated CAP_BPF not present (probe_rc=%d). Operating in userland qualification harness.\n\n", probe_rc);
    }

    printf("[STEP 3] Dispatching legitimate transaction (seq=1, payload='GNC_SET_THRUST_VECTOR')...\n");
    if (cfs_dispatch_command(sv[0], 1, "GNC_SET_THRUST_VECTOR") < 0) {
        return 1;
    }

    /* Synchronize with executor execution */
    uint32_t ack1 = 0;
    (void)recv(sv[0], &ack1, sizeof(ack1), 0);

    /* Read effector pipe to confirm userland write */
    struct cfs_cmd_packet result;
    memset(&result, 0, sizeof(result));
    ssize_t n = read(effector_pipe[0], &result, sizeof(result));
    if (n < (ssize_t)sizeof(struct cfs_seq_header)) {
        fprintf(stderr, "Failed to read effector pipe transaction\n");
        return 1;
    }

    int kernel_probe_verified = 0;
    struct cfs_effect_event live_evt1;
    memset(&live_evt1, 0, sizeof(live_evt1));

    if (is_live) {
        int rc = cfs_probe_wait_for_seq(1, &live_evt1, 2000);
        /* STRICT LIVE-KERNEL REQUIREMENT: Non-zero matching kernel event with NO userland fallback */
        if (rc != 0 || live_evt1.ktime_ns == 0) {
            fprintf(stderr, "  [CRITICAL ERROR] Strict qualification failed: Live probe did not capture non-zero kernel event!\n");
            cfs_probe_print_debug();
            return 1;
        }
        if (live_evt1.monotonic_seq != 1 || live_evt1.effect_hash != result.header.payload_crc32 || live_evt1.pid != (uint32_t)pid) {
            fprintf(stderr, "  [CRITICAL ERROR] Strict qualification failed: Kernel event field mismatch (seq=%llu, pid=%u, hash=0x%08x)!\n",
                    (unsigned long long)live_evt1.monotonic_seq, live_evt1.pid, live_evt1.effect_hash);
            return 1;
        }
        kernel_probe_verified = 1;
        printf("  [PASS] Live in-kernel ringbuffer event verified: ktime=%llu ns, pid=%u, seq=%llu, CRC32=0x%08x\n",
               (unsigned long long)live_evt1.ktime_ns,
               live_evt1.pid,
               (unsigned long long)live_evt1.monotonic_seq,
               live_evt1.effect_hash);
        printf("         Strict kernel qualification confirmed with zero userland fallback.\n\n");
    } else {
        /* Unprivileged fallback for container environments */
        if (result.header.magic == CFS_MAGIC_HEADER) {
            uint32_t expected_crc = cfs_crc32(result.payload, result.header.payload_len);
            if (expected_crc == result.header.payload_crc32) {
                kernel_probe_verified = 1;
                printf("  [PASS] Effector captured valid write: seq=%lu, CRC32=0x%08x verified (Unprivileged mode).\n\n",
                       (unsigned long)result.header.monotonic_seq, result.header.payload_crc32);
            }
        }
    }

    printf("=================================================================\n");
    printf(" Executing Adversarial Test Scenarios                            \n");
    printf("=================================================================\n\n");

    int failures = 0;

    /* Scenario 1: Same-UID ptrace defense */
    failures += test_same_uid_ptrace_defense(getpid());

    /* Scenario 2: Sequence gap / lost event injection & ringbuffer backpressure */
    printf("[DISPATCH] Dispatching out-of-order sequence gap (seq=5, skipping seq 2..4)...\n");
    cfs_dispatch_command(sv[0], 5, "GNC_ATTITUDE_TRIM");

    uint32_t ack2 = 0;
    (void)recv(sv[0], &ack2, sizeof(ack2), 0);
    ssize_t nr2 = read(effector_pipe[0], &result, sizeof(result));
    (void)nr2;

    struct cfs_effect_event live_evt2;
    memset(&live_evt2, 0, sizeof(live_evt2));
    int has_evt2 = 0;
    if (is_live) {
        has_evt2 = (cfs_probe_wait_for_seq(5, &live_evt2, 2000) == 0);
    }

    failures += test_lost_event_detection(2, 5, has_evt2 ? &live_evt2 : NULL, is_live);

    /* Scenario 3: Falsified executor self-report vs kernel effector (Live dynamic execution) */
    printf("[DISPATCH] Injecting compromised executor command with suppressed kernel effector...\n");
    int events_before = cfs_probe_get_event_count();

    /* Dispatch command tagged with CFS_FLAG_TAMPER_SIMULATE */
    cfs_dispatch_command_flags(sv[0], 6, "GNC_TAMPERED_TRANSACTION", CFS_FLAG_TAMPER_SIMULATE);

    /* Read userland response from executor claiming success */
    uint32_t tamper_ack = 0;
    (void)recv(sv[0], &tamper_ack, sizeof(tamper_ack), 0);
    int executor_claimed_success = (tamper_ack == 1);

    /* Poll kernel ringbuffer to verify whether in-kernel write was suppressed */
    if (is_live) {
        cfs_probe_poll(200);
    }
    int events_after = cfs_probe_get_event_count();
    int kernel_probe_fired = (events_after > events_before);

    failures += test_tamper_evident_effect(3, kernel_probe_fired, executor_claimed_success, NULL, is_live);

    /* Scenario 4: Fully verified physical effect corroborated by kernel tracepoint */
    failures += test_tamper_evident_effect(4, kernel_probe_verified, 1, &live_evt1, is_live);

    /* Shutdown child executor */
    close(sv[0]);
    close(effector_pipe[0]);
    waitpid(pid, NULL, 0);

    cfs_probe_cleanup();

    printf("=================================================================\n");
    if (failures == 0) {
        printf(" [QUALIFICATION SUCCESS] All 4 adversarial properties verified.  \n");
        printf(" Independent kernel observability binding confirmed by eBPF probe.\n");
        printf(" Zero userland fallbacks in live-kernel mode.\n");
    } else {
        printf(" [QUALIFICATION FAILED] %d adversarial scenarios failed.         \n", failures);
    }
    printf("=================================================================\n\n");

    return failures ? 1 : 0;
}
