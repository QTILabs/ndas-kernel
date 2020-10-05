#include "xdp-dumper.h"

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#define NANOSECS_PER_USEC 1000
#define NANOSECS_PER_SEC  1000000000

typedef struct perf_event_header PerfEventHeader;
typedef struct perf_event_attr PerfEventAttribute;
typedef struct rlimit RLimit;
typedef struct bpf_prog_load_attr BPFProgramLoadAttribute;
typedef struct bpf_object BPFObject;
typedef struct bpf_map BPFMap;
typedef struct perf_event_mmap_page PerfEventMMapPage;
typedef struct pollfd PollFd;
typedef enum bpf_perf_event_ret BPFPerfEventReturn;

typedef struct PerfEventSample {
    PerfEventHeader header;
    uint32_t size;
    uint8_t data[];
} PerfEventSample;

typedef struct PerfEventLost {
    PerfEventHeader header;
    __u64 id;
    __u64 lost;
} PerfEventLost;

static volatile uint8_t stop_requested = 0;
static volatile uint8_t loop_started = 0;
static __u32 prog_id;
static int32_t page_size;
static int32_t page_cnt = 8;
static int32_t pmu_fds[MAX_CPUS];
static int32_t numcpus = -1;
static pthread_t thread_perf_event_loop;
static PerfEventMMapPage* headers[MAX_CPUS];
static on_perfevent_func on_event_callback = NULL;
static on_perfevent_missed_func on_events_missed_callback = NULL;

static int32_t do_attach(int32_t idx, int32_t fd, const char* if_name, __u32 xdp_flags) {
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int32_t err;

    err = bpf_set_link_xdp_fd(idx, fd, xdp_flags);

    if (err < 0) {
        fprintf(stderr, "Index => %d\n", idx);
        fprintf(stderr, "Fd    => %d\n", fd);
        fprintf(stderr, "Name  => %s\n", if_name);
        fprintf(stderr, "Flags => %d\n", xdp_flags);
        printf("ERROR: failed to attach program to %s\n", if_name);
        return err;
    }

    err = bpf_obj_get_info_by_fd(fd, &info, &info_len);

    if (err) {
        printf("can't get prog info - %s\n", strerror(errno));
        return err;
    }

    prog_id = info.id;
    return err;
}

static int32_t do_detach(int32_t idx, const char* if_name) {
    __u32 curr_prog_id = 0;
    int32_t err = 0;

    err = bpf_get_link_xdp_id(idx, &curr_prog_id, 0);

    if (err) {
        fprintf(stderr, "bpf_get_link_xdp_id failed\n");
        return err;
    }

    if (prog_id == curr_prog_id) {
        err = bpf_set_link_xdp_fd(idx, -1, 0);

        if (err < 0) {
            fprintf(stderr, "ERROR: failed to detach prog from %s\n", if_name);
        }
    } else if (!curr_prog_id) {
        fprintf(stderr, "couldn't find a prog id on a %s\n", if_name);
    } else {
        fprintf(stderr, "program on interface changed, not removing\n");
    }

    return err;
}

static void perf_event_open(int32_t map_fd, int32_t num) {
    PerfEventAttribute attr = {
        .sample_type = PERF_SAMPLE_RAW,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1, /* get an fd notification for every event */
    };

    for (int32_t i = 0; i < num; ++i) {
        int32_t key = i;
        pmu_fds[i] = sys_perf_event_open(&attr, -1 /*pid*/, i /*cpu*/, -1 /*group_fd*/, 0);
        assert(pmu_fds[i] >= 0);
        assert(bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY) == 0);
        ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }
}

static BPFPerfEventReturn internal_on_event_func(struct perf_event_header* hdr, void* private_data) {
    PerfEventSample* e = (PerfEventSample*)hdr;
    on_perfevent_func fn = private_data;
    int32_t ret;

    if (e->header.type == PERF_RECORD_SAMPLE) {
        ret = fn(e->data, e->size);

        if (ret != LIBBPF_PERF_EVENT_CONT) {
            return ret;
        }
    } else if (e->header.type == PERF_RECORD_LOST) {
        PerfEventLost* lost = (void*)e;
        on_events_missed_callback(lost->lost);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

static int32_t perf_event_mmap_header(int32_t fd, PerfEventMMapPage** header) {
    void* base;
    int32_t mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("mmap err\n");
        return -1;
    }

    *header = base;
    return 0;
}

static void* perf_event_loop(void* params) {
    BPFPerfEventReturn ret;
    void* buf = NULL;
    size_t len = 0;
    int32_t i;
    PollFd* pfds = (PollFd*)calloc(numcpus, sizeof(PollFd));

    if (!pfds) {
        return (void*)LIBBPF_PERF_EVENT_ERROR;
    }

    for (i = 0; i < numcpus; i++) {
        pfds[i].fd = pmu_fds[i];
        pfds[i].events = POLLIN;
    }

    while (!stop_requested) {
        poll(pfds, numcpus, 0);

        for (i = 0; i < numcpus; i++) {
            if (!pfds[i].revents) {
                continue;
            }

            ret = bpf_perf_event_read_simple(headers[i], page_cnt * page_size, page_size, &buf, &len,
                                             internal_on_event_func, on_event_callback);

            if (ret != LIBBPF_PERF_EVENT_CONT) {
                break;
            }
        }
    }

    free(buf);
    free(pfds);
    return (void*)ret;
}

static int32_t get_if_index(const char* if_name) {
    return if_nametoindex(if_name);
}

// API implementations

uint8_t perfevent_is_running() {
    return loop_started;
}

LoopControlResult perfevent_loop_start(const char* interface_name, on_perfevent_func on_event_received,
                                       on_perfevent_missed_func on_event_missed) {
    if (loop_started > 0) {
        return AlreadyRunning;
    }

    stop_requested = 0;
    on_event_callback = on_event_received;
    on_events_missed_callback = on_event_missed;
    RLimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    BPFProgramLoadAttribute prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = BPF_KERN_PROG_NAME,
    };
    int32_t prog_fd, bpf_map_fd;
    BPFObject* bpf_obj;
    BPFMap* bpf_map;
    numcpus = bpf_num_possible_cpus();
    int32_t if_index = get_if_index(interface_name);
    __u32 xdp_flags = XDP_FLAGS_DRV_MODE;

    if (if_index == -1) {
        return InterfaceNotFound;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        return RLimitPermissionDenied;
    }

    if (bpf_prog_load_xattr(&prog_load_attr, &bpf_obj, &prog_fd) != 0) {
        return DriverError;
    }

    if (!prog_fd) {
        return DriverError;
    }

    bpf_map = bpf_object__find_map_by_name(bpf_obj, "ndas_perf_events");

    if (!bpf_map) {
        return DriverError;
    }

    bpf_map_fd = bpf_map__fd(bpf_map);

    if (do_attach(if_index, prog_fd, interface_name, xdp_flags) != 0) {
        return DriverError;
    }

    perf_event_open(bpf_map_fd, numcpus);

    for (int32_t i = 0; i < numcpus; ++i) {
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) {
            return DriverError;
        }
    }

    if (pthread_create(&thread_perf_event_loop, NULL, perf_event_loop, NULL) != 0) {
        return SystemError;
    }

    loop_started = 1;
    return Success;
}

LoopControlResult perfevent_loop_stop() {
    if (loop_started == 0) {
        return NotRunning;
    }

    stop_requested = 1;
    void* result;
    pthread_join(thread_perf_event_loop, &result);
    loop_started = 0;
    return ((BPFPerfEventReturn)result) == LIBBPF_PERF_EVENT_DONE ? Success : DriverError;
}

DumpSaveResult helper_pcapng_save(const char* filename, PacketSample* packet_sample) {
    return DumpSaved;
}
