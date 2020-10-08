#include "xdp-dumper.h"
#include <signal.h>

//#define TARGET_IF "eth0"
#define TARGET_IF "enp8s0f1np1"

typedef struct PollingThreadConfig {
    uint8_t current_cpu_id;
    uint32_t sleep_span_us;
} PollingThreadConfig;

static volatile uint8_t stop_requested = 0;
static volatile uint64_t counter_missed_events = 0;
static volatile uint64_t counter_events = 0;
static volatile uint64_t bytes_captured = 0;
static volatile uint64_t last_misses = 0;
static uint8_t polling_threads_count = 0;
static pthread_t* polling_threads = NULL;
static PollingThreadConfig* polling_threads_config = NULL;

static BPFPerfEventReturn on_event_handler(void* data, int32_t size) {
    PacketSample* sample = (PacketSample*)data;
    counter_events++;
    bytes_captured += sample->length;
    return LIBBPF_PERF_EVENT_CONT;
}

static void on_missed_event_handler(uint64_t missed_event_count) {
    counter_missed_events += missed_event_count;
}

static void handler_unix_signal(int32_t signo) {
    stop_requested = 1;
}

static void* polling_thread_loop(void* params) {
    PollingThreadConfig* polling_thread_config = (PollingThreadConfig*)params;

    while (!stop_requested) {
        usleep(polling_thread_config->sleep_span_us);
        perfevent_loop_tick(polling_thread_config->current_cpu_id);
    }

    return NULL;
}

int32_t main(int32_t argc, char** argv) {
    if (signal(SIGINT, handler_unix_signal) || signal(SIGHUP, handler_unix_signal)
        || signal(SIGTERM, handler_unix_signal)) {
        fprintf(stderr, "Cannot hook Unix Signal!");
        return 1;
    }

    PerfEventLoopConfig perfevent_loop_config = {
        .on_event_missed = on_missed_event_handler,
        .on_event_received = on_event_handler,
        .interface_name = TARGET_IF,
    };

    switch (perfevent_configure(&perfevent_loop_config, &polling_threads_count)) {
        case RESULT_ERR_NIC_NOT_FOUND:
            fprintf(stderr, "Cannot find interface %s!", TARGET_IF);
            return 1;
        case RESULT_ERR_DRIVER_NO_SUPPORT:
            fprintf(stderr, "XDP driver unsupported or denied by verifier %s!", TARGET_IF);
            return 1;
        case RESULT_ERR_RLIMIT_DENIED:
            fprintf(stderr, "Cannot raise RLIMIT value!");
            return 1;
        case RESULT_ERR_MAP_NOT_FOUND:
            fprintf(stderr, "Programmatic error, PerfMap cannot be found!");
            return 1;
        case RESULT_ERR_PERMISSION_DENIED:
            fprintf(stderr, "Permission denied!");
            return 1;
        case RESULT_ERR_UNKNOWN:
            fprintf(stderr, "Unknown error!");
            return 1;
        default:
            break;
    }

    polling_threads = (pthread_t*)calloc(polling_threads_count, sizeof(pthread_t));
    polling_threads_config = (PollingThreadConfig*)calloc(polling_threads_count, sizeof(PollingThreadConfig));

    for (uint8_t i = 0; i < polling_threads_count; ++i) {
        polling_threads_config[i].current_cpu_id = i;
        polling_threads_config[i].sleep_span_us = 1;
        pthread_create(&polling_threads[i], NULL, polling_thread_loop, &polling_threads_config[i]);
    }

    while (!stop_requested) {
        sleep(1);
        printf("[STATS] => Missed count: %lu | Handled count: %lu | Handled bytes: %lu Bytes\n", counter_missed_events,
               counter_events, bytes_captured);
    }

    for (uint8_t i = 0; i < polling_threads_count; ++i) {
        pthread_join(polling_threads[i], NULL);
    }

    return 0;
}
