#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#define BPF_KERN_PROG
#include "xdp-dumper.h"

typedef struct xdp_md XDPContext;

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") BPF_KERN_MAP_NAME = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

SEC(BPF_KERN_FUNC_NAME)
int32_t ndas_perf_event_pusher(XDPContext* ctx) {
    void* data_end = (void*)(int64_t)ctx->data_end;
    void* data = (void*)(int64_t)ctx->data;

    if (data < data_end) {
        __u64 flags = BPF_F_CURRENT_CPU;
        __u16 sample_size;
        PacketSample packet = {0};
        packet.length = (__u16)(data_end - data);
        packet.data_length = packet.length - (__u16)sizeof(struct ethhdr);
        sample_size = min(packet.length, MAX_PACKET_SIZE);
        flags |= ((__u64)sample_size) << 32;
        bpf_perf_event_output(ctx, &ndas_perf_events, flags, &packet, sizeof(PacketSample));
    }

    return XDP_PASS;
}

#undef BPF_KERN_PROG
