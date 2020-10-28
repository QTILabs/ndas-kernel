#ifndef __XDP_DUMPER__
#define __XDP_DUMPER__

#include <stdint.h>
#include <assert.h>
#include <asm-generic/int-ll64.h>

#define BPF_KERN_PROG_NAME "xdp-dumper-kern.o"
#define BPF_KERN_FUNC_NAME "ndas/perf_event_pusher"
#define BPF_KERN_MAP_NAME  ndas_perf_events
#define QUOTE_IDENT(ident) #ident
#define QUOTE_MACRO(macro) QUOTE_IDENT(macro)

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 2048
#endif

#ifndef PAGE_COUNT
#define PAGE_COUNT 1024
#endif

#ifndef MAX_CPUS
#define MAX_CPUS 32
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

typedef union __packed PacketSampleHeader {
    struct __packed {
        __u16 length;
        __u16 data_length;
    } structured;
    __u8 raw[4];
} PacketSampleHeader;

static_assert(sizeof(PacketSampleHeader) == 4, "Incorrect PacketSample definition!");

#ifndef BPF_KERN_PROG

#ifndef __USE_MISC
#define __USE_MISC
#endif

#include "../headers/bpf_util.h"
#include "../headers/perf-sys.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <poll.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include "../headers/linux/if_link.h"
#include "pcapng.h"

typedef enum OperationResult {
    RESULT_OK = 0,
    RESULT_ERR_NIC_NOT_FOUND = 1,
    RESULT_ERR_DRIVER_NO_SUPPORT = 2,
    RESULT_ERR_RLIMIT_DENIED = 4,
    RESULT_ERR_MAP_NOT_FOUND = 8,
    RESULT_ERR_DISK_FULL = 16,
    RESULT_ERR_PERMISSION_DENIED = 32,
    RESULT_ERR_UNKNOWN = 64,
} OperationResult;

typedef enum bpf_perf_event_ret BPFPerfEventReturn;
typedef BPFPerfEventReturn (*on_perfevent_func)(void* data, int32_t size);
typedef void (*on_perfevent_missed_func)(uint64_t);

typedef struct PerfEventLoopConfig {
    on_perfevent_func on_event_received;
    on_perfevent_missed_func on_event_missed;
    const char* interface_name;
} PerfEventLoopConfig;

extern OperationResult perfevent_configure(PerfEventLoopConfig* source_config, uint8_t* permitted_cpu_count);
extern OperationResult perfevent_set_promiscuous_mode(uint8_t enable);
extern void perfevent_loop_tick(uint8_t cpu_index, void** temp_buffer, size_t* copy_mem_length);
extern OperationResult helper_pcapng_save(const char* filename, uint64_t drop_count_delta, int64_t timestamp,
                                          size_t count, PacketSampleHeader* packet_sample, uint8_t** data);

#endif

#ifndef BPF_KERN_PROG
#ifdef __cplusplus
}
#endif
#endif

#endif
