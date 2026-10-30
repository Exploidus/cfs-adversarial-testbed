#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../include/common.h"
#include "../include/probe_loader.h"

#define MAX_SAVED_EVENTS 32
static struct bpf_object *g_bpf_obj = NULL;
static struct bpf_link *g_bpf_link = NULL;
static struct ring_buffer *g_ringbuf = NULL;
static int g_is_live = 0;
static int g_event_count = 0;
static struct cfs_effect_event g_latest_event;
static struct cfs_effect_event g_events[MAX_SAVED_EVENTS];

static int handle_ringbuf_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct cfs_effect_event)) {
        return 0;
    }

    if (g_event_count < MAX_SAVED_EVENTS) {
        memcpy(&g_events[g_event_count], data, sizeof(struct cfs_effect_event));
    }
    memcpy(&g_latest_event, data, sizeof(struct cfs_effect_event));
    g_event_count++;
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int cfs_probe_init(const char *bpf_obj_path, pid_t target_pid)
{
    libbpf_set_print(libbpf_print_fn);

    g_bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!g_bpf_obj) {
        fprintf(stderr, "  [PROBE] Note: Could not open %s (%s). Operating in userland qualification mode.\n",
                bpf_obj_path, strerror(errno));
        g_is_live = 0;
        return -1;
    }

    if (bpf_object__load(g_bpf_obj) < 0) {
        fprintf(stderr, "  [PROBE] Note: bpf_object__load failed (%s). Elevated CAP_BPF / root required for live kernel observation.\n",
                strerror(errno));
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
        g_is_live = 0;
        return -1;
    }

    /* Set target PID filter if requested */
    if (target_pid > 0) {
        int target_map_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "target_pid_map");
        if (target_map_fd >= 0) {
            uint32_t key = 0;
            uint32_t val = (uint32_t)target_pid;
            bpf_map_update_elem(target_map_fd, &key, &val, BPF_ANY);
        }
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(g_bpf_obj, "handle_sys_enter_write");
    if (!prog) {
        fprintf(stderr, "  [PROBE] Warning: Program handle_sys_enter_write not found in object.\n");
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
        g_is_live = 0;
        return -1;
    }

    g_bpf_link = bpf_program__attach(prog);
    if (!g_bpf_link) {
        fprintf(stderr, "  [PROBE] Warning: bpf_program__attach failed (%s).\n", strerror(errno));
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
        g_is_live = 0;
        return -1;
    }

    int ringbuf_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "effect_ringbuf");
    if (ringbuf_fd < 0) {
        fprintf(stderr, "  [PROBE] Warning: Map effect_ringbuf not found.\n");
        bpf_link__destroy(g_bpf_link);
        bpf_object__close(g_bpf_obj);
        g_bpf_link = NULL;
        g_bpf_obj = NULL;
        g_is_live = 0;
        return -1;
    }

    g_ringbuf = ring_buffer__new(ringbuf_fd, handle_ringbuf_event, NULL, NULL);
    if (!g_ringbuf) {
        fprintf(stderr, "  [PROBE] Warning: ring_buffer__new failed (%s).\n", strerror(errno));
        bpf_link__destroy(g_bpf_link);
        bpf_object__close(g_bpf_obj);
        g_bpf_link = NULL;
        g_bpf_obj = NULL;
        g_is_live = 0;
        return -1;
    }

    g_is_live = 1;
    return 0;
}

int cfs_probe_is_live(void)
{
    return g_is_live;
}

int cfs_probe_poll(int timeout_ms)
{
    if (!g_is_live || !g_ringbuf)
        return 0;
    int cnt = ring_buffer__consume(g_ringbuf);
    if (cnt > 0)
        return cnt;
    cnt = ring_buffer__poll(g_ringbuf, timeout_ms);
    if (cnt <= 0) {
        cnt = ring_buffer__consume(g_ringbuf);
    }
    return cnt;
}

int cfs_probe_get_event_by_seq(uint64_t seq, struct cfs_effect_event *out)
{
    if (!g_is_live || g_event_count == 0)
        return -1;
    int limit = g_event_count < MAX_SAVED_EVENTS ? g_event_count : MAX_SAVED_EVENTS;
    for (int i = 0; i < limit; i++) {
        if (g_events[i].monotonic_seq == seq) {
            if (out)
                memcpy(out, &g_events[i], sizeof(struct cfs_effect_event));
            return 0;
        }
    }
    return -1;
}

int cfs_probe_wait_for_seq(uint64_t seq, struct cfs_effect_event *out, int timeout_ms)
{
    if (!g_is_live || !g_ringbuf)
        return -1;

    ring_buffer__consume(g_ringbuf);
    if (cfs_probe_get_event_by_seq(seq, out) == 0)
        return 0;

    int remaining = timeout_ms;
    while (remaining > 0) {
        cfs_probe_poll(50);
        if (cfs_probe_get_event_by_seq(seq, out) == 0)
            return 0;
        remaining -= 50;
    }
    ring_buffer__consume(g_ringbuf);
    return cfs_probe_get_event_by_seq(seq, out);
}

int cfs_probe_wait_for_event(int expected_count, int timeout_ms)
{
    if (!g_is_live || !g_ringbuf)
        return 0;
    int remaining = timeout_ms;
    while (g_event_count < expected_count && remaining > 0) {
        cfs_probe_poll(50);
        if (g_event_count >= expected_count)
            return 1;
        remaining -= 50;
    }
    ring_buffer__consume(g_ringbuf);
    return (g_event_count >= expected_count);
}

int cfs_probe_get_event_count(void)
{
    return g_event_count;
}

int cfs_probe_get_latest_event(struct cfs_effect_event *out)
{
    if (!g_is_live || g_event_count == 0)
        return -1;
    if (out)
        memcpy(out, &g_latest_event, sizeof(struct cfs_effect_event));
    return 0;
}

void cfs_probe_print_debug(void)
{
    if (!g_bpf_obj)
        return;
    int fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "debug_stats_map");
    if (fd < 0)
        return;
    uint64_t stats[8];
    memset(stats, 0, sizeof(stats));
    for (uint32_t i = 0; i < 8; i++) {
        bpf_map_lookup_elem(fd, &i, &stats[i]);
    }
    fprintf(stderr, "  [DEBUG STATS] total=%llu, pid_mismatch=%llu, small_cnt=%llu, read_err=%llu, magic_mismatch=%llu, rb_full=%llu, submitted=%llu, last_pid=0x%llx (target_pid=%u)\n",
            (unsigned long long)stats[0],
            (unsigned long long)stats[1],
            (unsigned long long)stats[2],
            (unsigned long long)stats[3],
            (unsigned long long)stats[4],
            (unsigned long long)stats[5],
            (unsigned long long)stats[6],
            (unsigned long long)stats[7],
            g_latest_event.pid);
}

void cfs_probe_cleanup(void)
{
    if (g_ringbuf) {
        ring_buffer__free(g_ringbuf);
        g_ringbuf = NULL;
    }
    if (g_bpf_link) {
        bpf_link__destroy(g_bpf_link);
        g_bpf_link = NULL;
    }
    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
    }
    g_is_live = 0;
}
