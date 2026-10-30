#ifndef CFS_COMMON_H
#define CFS_COMMON_H

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

#define CFS_MAGIC_HEADER       0x43465331 /* "CFS1" */
#define CFS_PAYLOAD_MAX_LEN    256
#define CFS_REPLAY_FLAG        0xFFFFFFFFU
#define CFS_FLAG_TAMPER_SIMULATE 0x80000000U

/*
 * Verification verdicts for adversarial evaluation
 */
typedef enum
{
    CFE_VERDICT_QUALIFIED = 0,
    CFE_VERDICT_LOST_EVENT = 1,
    CFE_VERDICT_REPLAY_DETECTED = 2,
    CFE_VERDICT_UNVERIFIED_EFFECT = 3,
    CFE_VERDICT_INSTANCE_DISCONTINUITY = 4
} cfe_verdict_t;

/*
 * Transaction sequence header (32 bytes, 8-byte aligned, zero padding holes)
 */
struct cfs_seq_header
{
    uint32_t magic;
    uint32_t instance_id;
    uint64_t monotonic_seq;
    uint64_t start_time_ns;
    uint32_t payload_len;
    uint32_t payload_crc32;
};

#ifdef __cplusplus
static_assert(sizeof(struct cfs_seq_header) == 32, "cfs_seq_header size mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct cfs_seq_header) == 32, "cfs_seq_header size mismatch");
#endif

/*
 * Command packet sent across anonymous socketpair (288 bytes)
 */
struct cfs_cmd_packet
{
    struct cfs_seq_header header;
    uint8_t payload[CFS_PAYLOAD_MAX_LEN];
};

#ifdef __cplusplus
static_assert(sizeof(struct cfs_cmd_packet) == 288, "cfs_cmd_packet size mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct cfs_cmd_packet) == 288, "cfs_cmd_packet size mismatch");
#endif

/*
 * Kernel effector event emitted via eBPF ringbuffer (64 bytes, 8-byte aligned)
 * Incorporates effect-side witness and return qualification
 */
struct cfs_effect_event
{
    uint64_t ktime_ns;
    uint64_t task_start_time_ns;
    uint64_t monotonic_seq;
    uint32_t pid;
    uint32_t tgid;
    uint32_t uid;
    uint32_t effector_id;
    uint32_t effect_hash;
    uint32_t lost_counter;
    int32_t  syscall_ret;
    uint32_t duration_ns;
    uint8_t  observed_syscall;
    uint8_t  effect_completed;
    uint8_t  pad[2];
    uint32_t reserved;
};

#ifdef __cplusplus
static_assert(sizeof(struct cfs_effect_event) == 64, "cfs_effect_event size mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct cfs_effect_event) == 64, "cfs_effect_event size mismatch");
#endif

/*
 * Standard IEEE 802.3 CRC32 calculation
 */
static inline uint32_t cfs_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < length; ++i) {
        crc ^= (uint32_t)data[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320U;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

#endif /* CFS_COMMON_H */
