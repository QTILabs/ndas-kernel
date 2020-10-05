#include "xdp-dumper.h"
#include <signal.h>

static volatile uint64_t counter_missed_events = 0;
static volatile uint64_t counter_events = 0;
static volatile uint64_t bytes_captured = 0;

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
    LoopControlResult result = perfevent_loop_stop();

    switch (result) {
        case NotRunning:
            fprintf(stderr, "PerfEvent loop is not running!");
        default:
            break;
    }

    exit(0);
}

int32_t main(int32_t argc, char** argv) {
    if (signal(SIGINT, handler_unix_signal) || signal(SIGHUP, handler_unix_signal)
        || signal(SIGTERM, handler_unix_signal)) {
        fprintf(stderr, "Cannot hook Unix Signal!");
        return 1;
    }

    switch (perfevent_loop_start("eth0", on_event_handler, on_missed_event_handler)) {
        case InterfaceNotFound:
            fprintf(stderr, "Cannot find interface eth0!");
            return 1;
        case DriverError:
            fprintf(stderr, "XDP driver unsupported or denied by verifier eth0!");
            return 1;
        case RLimitPermissionDenied:
            fprintf(stderr, "Cannot raise RLIMIT value!");
            return 1;
        case MapNotFound:
            fprintf(stderr, "Programmatic error, PerfMap cannot be found!");
            return 1;
        case AlreadyRunning:
            fprintf(stderr, "XDP Dumper already running!");
            return 1;
        case SystemError:
            return 1;
        default:
            break;
    }

    while (1) {
        sleep(1);
        printf("[STATS] => Missed count: %lu | Handled count: %lu | Handled bytes: %lu Bytes\n", counter_missed_events,
               counter_events, bytes_captured);
    }

    return 0;
}
