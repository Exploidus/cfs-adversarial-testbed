#ifndef CFS_PROBE_LOADER_H
#define CFS_PROBE_LOADER_H

#include <stdint.h>
#include <sys/types.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * In-process libbpf loader and kernel ringbuffer consumer
 */
int cfs_probe_init(const char *bpf_obj_path, pid_t target_pid);
int cfs_probe_is_live(void);
int cfs_probe_poll(int timeout_ms);
int cfs_probe_wait_for_event(int expected_count, int timeout_ms);
int cfs_probe_wait_for_seq(uint64_t seq, struct cfs_effect_event *out, int timeout_ms);
int cfs_probe_get_event_by_seq(uint64_t seq, struct cfs_effect_event *out);
int cfs_probe_get_event_count(void);
int cfs_probe_get_latest_event(struct cfs_effect_event *out);
uint64_t cfs_probe_get_backpressure_drops(void);
void cfs_probe_print_debug(void);
void cfs_probe_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* CFS_PROBE_LOADER_H */
