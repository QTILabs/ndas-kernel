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
typedef struct pcapng_dumper PCapNGDumper;
typedef struct utsname SystemIdentification;
typedef enum bpf_perf_event_ret BPFPerfEventReturn;

typedef struct IFAddress {
    char* ifname;
    int ifindex;
} IFAddress;

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
static pthread_t thread_perf_event_loop;
static PerfEventMMapPage* headers[MAX_CPUS];
static PerfEventLoopConfig config = {0};
static PollFd pfds[MAX_CPUS];
static uint8_t cpu_count = 0;

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
        config.on_event_missed(lost->lost);
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

static int32_t get_if_index(const char* interface_name) {
    return if_nametoindex(interface_name);
}

static uint64_t get_if_speed(const char* interface_name) {
#define MAX_MODE_MASKS 10
    int32_t fd;
    struct ifreq ifr;
    struct {
        struct ethtool_link_settings req;
        uint32_t modes[3 * MAX_MODE_MASKS];
    } ereq;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        return 0;
    }

    memset(&ereq, 0, sizeof(ereq));
    ereq.req.cmd = ETHTOOL_GLINKSETTINGS;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (void*)&ereq;

    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        goto error_exit;
    }

    if (ereq.req.link_mode_masks_nwords >= 0 || ereq.req.link_mode_masks_nwords < -MAX_MODE_MASKS
        || ereq.req.cmd != ETHTOOL_GLINKSETTINGS) {
        goto error_exit;
    }

    ereq.req.link_mode_masks_nwords = -ereq.req.link_mode_masks_nwords;

    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        goto error_exit;
    }

    if (ereq.req.speed == -1) {
        ereq.req.speed = 0;
    }

    close(fd);
    return ereq.req.speed * 1000000ULL;

error_exit:
    close(fd);
    return 0;
}

static char* get_if_drv_info(const char* interface_name, char* buffer, size_t len) {
    int32_t fd;
    char* r_buffer = NULL;
    struct ifreq ifr;
    struct ethtool_drvinfo info;

    if (buffer == NULL || len == 0) {
        return NULL;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        return NULL;
    }

    memset(&info, 0, sizeof(info));
    info.cmd = ETHTOOL_GDRVINFO;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (void*)&info;

    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        goto exit;
    }

    snprintf(buffer, len,
             "driver: \"%s\", version: \"%s\", "
             "fw-version: \"%s\", rom-version: \"%s\", "
             "bus-info: \"%s\"",
             info.driver, info.version, info.fw_version, info.erom_version, info.bus_info);

    r_buffer = buffer;
exit:
    close(fd);
    return r_buffer;
}

// API implementations

void perfevent_loop_tick(uint8_t cpu_index, void** temp_buffer, size_t* copy_mem_length) {
    poll(&pfds[cpu_index], 1, 1);

    if (!pfds[cpu_index].revents) {
        return;
    }

    bpf_perf_event_read_simple(headers[cpu_index], page_cnt * page_size, page_size, temp_buffer, copy_mem_length,
                               internal_on_event_func, config.on_event_received);
}

OperationResult perfevent_configure(PerfEventLoopConfig* source_config, uint8_t* permitted_cpu_count) {
    config.on_event_missed = source_config->on_event_missed;
    config.on_event_received = source_config->on_event_received;
    config.interface_name = source_config->interface_name;

    RLimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    BPFProgramLoadAttribute prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = BPF_KERN_PROG_NAME,
    };
    int32_t prog_fd, bpf_map_fd;
    BPFObject* bpf_obj;
    BPFMap* bpf_map;
    __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
    cpu_count = bpf_num_possible_cpus();
    *permitted_cpu_count = cpu_count;
    int32_t if_index = get_if_index(config.interface_name);

    if (if_index == -1) {
        return RESULT_ERR_NIC_NOT_FOUND;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        return RESULT_ERR_RLIMIT_DENIED;
    }

    if (bpf_prog_load_xattr(&prog_load_attr, &bpf_obj, &prog_fd) != 0) {
        return RESULT_ERR_DRIVER_NO_SUPPORT;
    }

    if (!prog_fd) {
        return RESULT_ERR_DRIVER_NO_SUPPORT;
    }

    bpf_map = bpf_object__find_map_by_name(bpf_obj, QUOTE_MACRO(BPF_KERN_MAP_NAME));

    if (!bpf_map) {
        return RESULT_ERR_DRIVER_NO_SUPPORT;
    }

    bpf_map_fd = bpf_map__fd(bpf_map);

    if (do_attach(if_index, prog_fd, config.interface_name, xdp_flags) != 0) {
        return RESULT_ERR_DRIVER_NO_SUPPORT;
    }

    perf_event_open(bpf_map_fd, cpu_count);

    for (uint8_t i = 0; i < cpu_count; ++i) {
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) {
            return RESULT_ERR_DRIVER_NO_SUPPORT;
        }
    }

    if (!pfds) {
        return RESULT_ERR_UNKNOWN;
    }

    for (uint8_t i = 0; i < cpu_count; i++) {
        pfds[i].fd = pmu_fds[i];
        pfds[i].events = POLLIN;
    }

    return RESULT_OK;
}

OperationResult helper_pcapng_save(const char* filename, uint64_t drop_count_delta, int64_t timestamp, size_t count,
                                   PacketSample* packet_sample) {
    char if_drv[260];
    char if_name[IFNAMSIZ + 7];
    char if_descr[BPF_OBJ_NAME_LEN + IFNAMSIZ + 10];
    uint64_t if_speed;
    SystemIdentification utinfo;

    memset(&utinfo, 0, sizeof(utinfo));
    uname(&utinfo);
    if_drv[0] = 0;
    snprintf(if_drv, sizeof(if_drv), "%s %s %s %s", utinfo.sysname, utinfo.nodename, utinfo.release, utinfo.version);

    PCapNGDumper* dumper = pcapng_dump_open(filename, NULL, utinfo.machine, if_drv, "ndas-pcapng-dumper 1.0.0-alpha.0");

    if (!dumper) {
        return RESULT_ERR_PERMISSION_DENIED;
    }

    if_speed = get_if_speed(config.interface_name);
    if_drv[0] = 0;
    get_if_drv_info(config.interface_name, if_drv, sizeof(if_drv));
    snprintf(if_name, sizeof(if_name), "%s@fentry", config.interface_name);
    pcapng_dump_add_interface(dumper, MAX_PACKET_SIZE, if_name, if_descr, NULL, if_speed, 1, if_drv);
    snprintf(if_name, sizeof(if_name), "%s@fexit", config.interface_name);
    snprintf(if_descr, sizeof(if_descr), "%s:%s()@fexit", config.interface_name, BPF_KERN_FUNC_NAME);
    pcapng_dump_add_interface(dumper, MAX_PACKET_SIZE, if_name, if_descr, NULL, if_speed, 1, if_drv);

    for (size_t i = 0; i < count; ++i) {
        uint32_t packet_length = packet_sample[i].length;
        struct pcapng_epb_options_s options = {};
        options.flags = PCAPNG_EPB_FLAG_INBOUND;
        options.dropcount = drop_count_delta;
        options.packetid = NULL;
        options.queue = NULL;
        options.xdp_verdict = NULL;
        pcapng_dump_enhanced_pkt(dumper, 0, packet_sample[i].raw, packet_length, packet_length, timestamp, &options);
    }

    pcapng_dump_flush(dumper);
    pcapng_dump_close(dumper);
    return RESULT_OK;
}

OperationResult perfevent_set_promiscuous_mode(uint8_t enable) {
    struct ifreq ifr;
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    OperationResult result = RESULT_OK;

    if (fd < 0) {
        return RESULT_ERR_UNKNOWN;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, config.interface_name, sizeof(ifr.ifr_name) - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        result = RESULT_ERR_PERMISSION_DENIED;
        goto exit;
    }

    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
        result = RESULT_ERR_PERMISSION_DENIED;
        goto exit;
    }

exit:
    close(fd);
    return result;
}
