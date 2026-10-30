#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>

#include "../include/common.h"

int cfs_executor_init(int sock)
{
    /* Protect memory and descriptor table against same-UID inspection */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        perror("executor: prctl(PR_SET_DUMPABLE)");
        return -1;
    }

    /* Send initial qualification handshake allowing kernel to stamp SCM_CREDENTIALS */
    char ping = 0xCF;
    if (send(sock, &ping, 1, MSG_NOSIGNAL) < 0) {
        perror("executor: handshake send");
        return -1;
    }

    return 0;
}

static ssize_t write_all(int fd, const void *buf, size_t count)
{
    size_t total = 0;
    const char *p = buf;
    while (total < count) {
        ssize_t n = write(fd, p + total, count - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += n;
    }
    return total;
}

int cfs_executor_run_once(int sock, int effector_fd, int simulate_tamper)
{
    struct cfs_cmd_packet pkt;
    ssize_t n = recv(sock, &pkt, sizeof(pkt), 0);
    if (n <= 0) {
        return -1;
    }

    if (pkt.header.magic != CFS_MAGIC_HEADER) {
        fprintf(stderr, "executor: invalid magic header: 0x%08x\n", pkt.header.magic);
        return -1;
    }

    /* Verify payload integrity via CRC32 */
    uint32_t computed_crc = cfs_crc32(pkt.payload, pkt.header.payload_len);
    if (computed_crc != pkt.header.payload_crc32) {
        fprintf(stderr, "executor: CRC32 mismatch! computed=0x%08x, header=0x%08x\n",
                computed_crc, pkt.header.payload_crc32);
        return -1;
    }

    if (simulate_tamper || (pkt.header.instance_id & CFS_FLAG_TAMPER_SIMULATE)) {
        /*
         * Adversarial simulation: Executor claims success in userland
         * but maliciously drops the actual kernel effector call.
         */
        printf("  [EXPLOIT SIMULATION] Compromised executor claims success for seq=%lu but suppresses kernel effector syscall!\n",
               (unsigned long)pkt.header.monotonic_seq);
        uint32_t userland_ack = 1; /* Claims execution completed successfully */
        send(sock, &userland_ack, sizeof(userland_ack), MSG_NOSIGNAL);
        return 0;
    }

    /*
     * Legitimate path: Issue the actual kernel write to effector
     * This triggers the in-kernel eBPF tracepoint probe.
     */
    size_t write_len = sizeof(pkt.header) + pkt.header.payload_len;
    if (write_all(effector_fd, &pkt, write_len) < 0) {
        perror("executor: write to effector");
        return -1;
    }

    uint32_t userland_ack = 1;
    send(sock, &userland_ack, sizeof(userland_ack), MSG_NOSIGNAL);

    return 0;
}
