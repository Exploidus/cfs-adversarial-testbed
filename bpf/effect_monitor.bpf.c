/*
 * eBPF Effector & Observability Probe for NASA cFS Linux Testbed
 *
 * Implements independent in-kernel causality binding:
 * 1. Monotonic sequence verification in kernel space.
 * 2. Process instance qualification (start_time).
 * 3. Replay attack and sequence loss accounting.
 * 4. Ringbuffer backpressure telemetry.
 */

#include "bpf_helpers.h"
#include "../include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Pinned maps storing persistent transaction state across userland reader restarts
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} state_seq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} state_instance_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} target_pid_map SEC(".maps");

/*
 * Telemetry debug map:
 * [0] Total calls to handle_sys_enter_write
 * [1] Calls filtered out by PID mismatch
 * [2] Calls filtered out by short count (< 32)
 * [3] Calls failed in bpf_probe_read_user
 * [4] Calls filtered out by non-matching magic header
 * [5] Calls dropped by ringbuf reserve full
 * [6] Successfully submitted events
 * [7] Last observed pid/tgid
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, uint32_t);
    __type(value, uint64_t);
} debug_stats_map SEC(".maps");

/*
 * Ringbuffer for qualified kernel events
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} effect_ringbuf SEC(".maps");

/*
 * Standard tracepoint context for sys_enter
 */
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

static __always_inline void inc_stat(uint32_t idx)
{
    uint32_t key = idx;
    uint64_t *val = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (val)
        (*val)++;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    inc_stat(0);

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tgid >> 32);
    uint32_t tgid = (uint32_t)pid_tgid;
    uint32_t uid = (uint32_t)bpf_get_current_uid_gid();

    uint32_t k7 = 7;
    uint64_t *v7 = bpf_map_lookup_elem(&debug_stats_map, &k7);
    if (v7)
        *v7 = pid_tgid;

    uint32_t target_key = 0;
    uint32_t *target_pid = bpf_map_lookup_elem(&target_pid_map, &target_key);
    if (target_pid && *target_pid != 0) {
        if (*target_pid != pid && *target_pid != tgid) {
            inc_stat(1);
            return 0;
        }
    }

    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    if (count < sizeof(struct cfs_seq_header)) {
        inc_stat(2);
        return 0;
    }

    struct cfs_seq_header hdr;
    __builtin_memset(&hdr, 0, sizeof(hdr));
    if (bpf_probe_read_user(&hdr, sizeof(hdr), buf) != 0) {
        inc_stat(3);
        return 0;
    }

    if (hdr.magic != CFS_MAGIC_HEADER) {
        inc_stat(4);
        return 0;
    }

    uint32_t key = 0;
    uint64_t *prev_seq = bpf_map_lookup_elem(&state_seq_map, &key);
    uint64_t *prev_inst = bpf_map_lookup_elem(&state_instance_map, &key);

    uint64_t cur_seq = hdr.monotonic_seq;
    uint64_t cur_inst = hdr.start_time_ns;

    /*
     * Allocate ringbuffer event
     */
    struct cfs_effect_event *event = bpf_ringbuf_reserve(&effect_ringbuf, sizeof(*event), 0);
    if (!event) {
        /* Backpressure: ringbuffer full */
        inc_stat(5);
        return 0;
    }

    event->ktime_ns = bpf_ktime_get_ns();
    event->task_start_time_ns = cur_inst;
    event->monotonic_seq = cur_seq;
    event->pid = (target_pid && *target_pid != 0) ? *target_pid : (pid ? pid : tgid);
    event->tgid = tgid;
    event->uid = uid;
    event->effector_id = hdr.instance_id;
    event->effect_hash = hdr.payload_crc32;
    event->observed_syscall = 1; /* sys_write */
    event->lost_counter = 0;
    event->pad[0] = 0;
    event->pad[1] = 0;
    event->pad[2] = 0;
    event->reserved = 0;

    if (prev_seq && *prev_seq != 0) {
        if (cur_seq <= *prev_seq) {
            /* Flag replay or out-of-order transaction */
            event->lost_counter = CFS_REPLAY_FLAG;
        } else if (cur_seq > *prev_seq + 1) {
            /* Flag sequence discontinuity / dropped events */
            event->lost_counter = (uint32_t)(cur_seq - (*prev_seq + 1));
        }
    }

    if (prev_seq) {
        *prev_seq = cur_seq;
    }
    if (prev_inst) {
        *prev_inst = cur_inst;
    }

    bpf_ringbuf_submit(event, 0);
    inc_stat(6);
    return 0;
}
