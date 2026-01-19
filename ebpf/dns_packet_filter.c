#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

// Add bool definition for BPF
#define bool _Bool
#define true 1
#define false 0

// Define network byte order conversion
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)

struct dns_event {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u16 query_length;     // Length of DNS query
    __u16 payload_size;     // Total DNS payload size
    __u8 query_type;        // Type of DNS query (A, TXT, etc.)
    __u8 subdomain_count;   // Number of subdomains in query
    __u64 timestamp;        // Timestamp for frequency analysis
    __u32 frequency;        // Renamed from packet_count to be more clear
    __u32 if_index;
};

// Modern map definitions
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10000);
} ip_frequency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10000);
} ip_timestamp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10000);
} port_frequency SEC(".maps");

SEC("xdp")
int packet_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Get UDP header
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Store ports in host byte order, ensuring they're 16-bit values
    __u16 src_port = ntohs(udp->source);
    __u16 dest_port = ntohs(udp->dest);

    // Debug print for ports
    bpf_printk("Raw ports: src=%d dst=%d\n", src_port, dest_port);

    // Check if this is DNS traffic (either source OR destination port is 53)
    if (src_port != 53 && dest_port != 53)
        return XDP_PASS;

    // Track non-standard port usage
    if (src_port != 53) {
        __u32 port_key = src_port;  // Use a register variable instead of stack
        __u32 *port_freq = bpf_map_lookup_elem(&port_frequency, &port_key);
        __u32 new_port_freq = 1;
        if (port_freq) {
            new_port_freq = *port_freq + 1;
        }
        bpf_map_update_elem(&port_frequency, &port_key, &new_port_freq, BPF_ANY);
    }

    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    // Zero initialize
    __builtin_memset(event, 0, sizeof(*event));

    // Fill event data
    event->src_ip = ip->saddr;
    event->dest_ip = ip->daddr;
    event->src_port = src_port;
    event->dest_port = dest_port;

    // Get current timestamp
    __u64 current_ts = bpf_ktime_get_ns();
    event->timestamp = current_ts;

    // Calculate payload length
    __u16 udp_len = ntohs(udp->len);
    if (udp_len > sizeof(*udp)) {
        event->query_length = udp_len - sizeof(*udp);
        event->payload_size = event->query_length;
    }

    // Update frequency tracking
    __u32 *freq = bpf_map_lookup_elem(&ip_frequency, &ip->saddr);
    __u64 *last_ts = bpf_map_lookup_elem(&ip_timestamp, &ip->saddr);

    __u32 new_freq = 1;
    if (freq && last_ts) {
        // Calculate time difference in seconds
        __u64 time_diff = (current_ts - *last_ts) / 1000000000;
        if (time_diff < 60) { // Within last minute
            new_freq = *freq + 1;
        }
    }

    // Update frequency and timestamp
    bpf_map_update_elem(&ip_frequency, &ip->saddr, &new_freq, BPF_ANY);
    bpf_map_update_elem(&ip_timestamp, &ip->saddr, &current_ts, BPF_ANY);

    // Set frequency in event
    event->frequency = new_freq;  // Just store the frequency, no direction flag

    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";