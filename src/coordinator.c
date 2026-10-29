#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <time.h>
#include <errno.h>

#include "../include/common.h"

static uint64_t get_boot_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int cfs_setup_secure_channel(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
        perror("socketpair");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(sv[0], SO_PASSCRED)");
        return -1;
    }

    /* Block same-UID ptrace and /proc/pid/mem access from unprivileged peers */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        perror("prctl(PR_SET_DUMPABLE)");
        return -1;
    }

    return 0;
}

int cfs_verify_peer(int sock, uid_t expected_uid, pid_t expected_pid)
{
    char buf[16];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    char ctrl_buf[CMSG_SPACE(sizeof(struct ucred))];
    memset(ctrl_buf, 0, sizeof(ctrl_buf));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl_buf,
        .msg_controllen = sizeof(ctrl_buf),
    };

    ssize_t n = recvmsg(sock, &msg, 0);
    if (n <= 0) {
        perror("recvmsg(credentials)");
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_CREDENTIALS) {
        fprintf(stderr, "[SECURITY ALERT] Missing SCM_CREDENTIALS in handshake message\n");
        return -1;
    }

    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
    if (cred->uid != expected_uid || cred->pid != expected_pid) {
        fprintf(stderr, "[SECURITY ALERT] Peer credentials mismatch: uid=%d, pid=%d (expected uid=%d, pid=%d)\n",
                cred->uid, cred->pid, expected_uid, expected_pid);
        return -1;
    }

    return 0;
}

int cfs_dispatch_command(int sock, uint64_t seq, const char *payload)
{
    struct cfs_cmd_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    size_t payload_len = strlen(payload);
    if (payload_len >= CFS_PAYLOAD_MAX_LEN) {
        payload_len = CFS_PAYLOAD_MAX_LEN - 1;
    }

    memcpy(pkt.payload, payload, payload_len);
    pkt.payload[payload_len] = '\0';

    pkt.header.magic = CFS_MAGIC_HEADER;
    pkt.header.instance_id = 1;
    pkt.header.monotonic_seq = seq;
    pkt.header.start_time_ns = get_boot_ns();
    pkt.header.payload_len = (uint32_t)payload_len;
    pkt.header.payload_crc32 = cfs_crc32(pkt.payload, payload_len);

    size_t total_size = sizeof(pkt.header) + payload_len;
    ssize_t sent = send(sock, &pkt, total_size, MSG_NOSIGNAL);
    if (sent < 0) {
        perror("send");
        return -1;
    }

    return 0;
}
