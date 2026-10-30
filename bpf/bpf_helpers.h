#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#if defined(__bpf__) || defined(__TARGET_ARCH_x86)
#ifndef _BPF_FREESTANDING_TYPES
#define _BPF_FREESTANDING_TYPES
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long size_t;
#endif
#else
#include <stdint.h>
#include <stddef.h>
#endif

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_MAP_TYPE_ARRAY   2
#define BPF_MAP_TYPE_RINGBUF 27

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

/* BPF Helper function prototypes mapped to kernel helper IDs */
static uint64_t (*bpf_ktime_get_ns)(void) = (void *)5;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;
static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *)14;
static uint64_t (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_probe_read_user)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *)113;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, uint64_t size, uint64_t flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, uint64_t flags) = (void *)132;

#endif /* __BPF_HELPERS_H */
