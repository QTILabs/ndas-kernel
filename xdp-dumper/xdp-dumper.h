#ifndef __XDP_DUMPER__
#define __XDP_DUMPER__

#include <stdint.h>
#include <assert.h>

#define BPF_KERN_PROG_NAME "xdp-dumper-kern.o"

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 2048
#endif

#ifndef MAX_CPUS
#define MAX_CPUS 128
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

static_assert(sizeof(int) == sizeof(int32_t), "Invalid architecture!");
static_assert(sizeof(long) == sizeof(int64_t), "Invalid architecture!");

#ifndef BPF_KERN_PROG
#ifdef __cplusplus
extern "C" {
#endif
#endif

#ifdef BPF_KERN_PROG

typedef struct __packed PacketSample {
    __u16 length;
    __u16 data_length;
} PacketSample;

#else

typedef struct __packed PacketSample {
    uint16_t length;
    uint16_t data_length;
    uint8_t raw[MAX_PACKET_SIZE];
} PacketSample;

#endif

#ifdef BPF_KERN_PROG
static_assert(sizeof(PacketSample) == 4, "Incorrect PacketSample definition!");
#else
static_assert(sizeof(PacketSample) == 4 + MAX_PACKET_SIZE, "Incorrect PacketSample definition!");
#endif

#ifndef BPF_KERN_PROG

#include "bpf_util.h"
#include "perf-sys.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <net/if.h>
#include "../headers/linux/if_link.h"

typedef enum LoopControlResult {
    Success = 0,
    InterfaceNotFound = -1,
    NotRunning = -2,
    DriverError = -4,
    RLimitPermissionDenied = -8,
    MapNotFound = -16,
    AlreadyRunning = -32,
    SystemError = -128,
} LoopControlResult;

typedef enum DumpSaveResult {
    DumpSaved = 0,
    DiskFull = -1,
    PathNotFound = -2,
    PermissionDenied = -4,
    UnknownError = -8,
} DumpSaveResult;

typedef enum bpf_perf_event_ret BPFPerfEventReturn;
typedef BPFPerfEventReturn (*on_perfevent_func)(void* data, int32_t size);
typedef void (*on_perfevent_missed_func)(uint64_t);

extern uint8_t perfevent_is_running();
extern LoopControlResult perfevent_loop_start(const char* interface_name, on_perfevent_func on_event_received,
                                              on_perfevent_missed_func on_event_missed);
extern LoopControlResult perfevent_loop_stop();
extern DumpSaveResult helper_pcapng_save(const char* filename, PacketSample* packet_sample);

#endif

#ifndef BPF_KERN_PROG
#ifdef __cplusplus
}
#endif
#endif

#endif
