#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#define BPF_PROG_PATH "dns_packet_filter.o"
#define RINGBUF_MAP_NAME "events"
#define CLEAR_SCREEN "\033[2J\033[H"
#define LOG_FILE "dns_monitoring.log"

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
    __u32 frequency;        // Track number of packets from same source
    __u32 if_index;         // Interface index
    __u8 direction;         // Direction of the packet (0 for query, 1 for response)
};

static struct bpf_object *obj;
static struct ring_buffer *rb = NULL;
static volatile int request_count = 0; // Counter for requests
static FILE *log_file = NULL;
static int first_display = 1;
static char *program_interface;

// Add this at the start of main() before any other operations
static void init_display(void) {
    // Disable buffering
    setbuf(stdout, NULL);
    // Clear screen and hide cursor
    printf("\033[2J\033[H\033[?25l");
}

// Callback for processing events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct dns_event *event = data;
    char if_name[IF_NAMESIZE];

    // Initialize interface name to empty string
    memset(if_name, 0, IF_NAMESIZE);

    // Get interface name, with error checking
    if (!if_indextoname(event->if_index, if_name)) {
        strncpy(if_name, "unknown", IF_NAMESIZE - 1);
    }

    // Convert network byte order only for IPs
    __u32 src_ip = ntohl(event->src_ip);
    __u32 dest_ip = ntohl(event->dest_ip);

    // Ports should already be in host byte order from eBPF
    __u16 src_port = event->src_port;
    __u16 dest_port = event->dest_port;

    // Debug print for received ports
    printf("Received ports: src=%u dst=%u\n", event->src_port, event->dest_port);

    // If source port is 53, it's a response FROM DNS server
    bool is_response = (src_port == 53);

    if (first_display) {
        printf("\033[2J\033[H");
        first_display = 0;
    } else {
        printf("\033[H");
    }

    printf("=== DNS Packet Analysis ===\n");
    printf("Direction:   %s\n", is_response ? "Response ←" : "Query →");

    if (is_response) {
        // For responses: dest is client, src is server
        printf("Client:      %d.%d.%d.%d:%d\n",
               (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
               (dest_ip >> 8) & 0xFF, dest_ip & 0xFF,
               dest_port);
        printf("DNS Server:  %d.%d.%d.%d:%d\n",
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
               (src_ip >> 8) & 0xFF, src_ip & 0xFF,
               src_port);
    } else {
        // For queries: src is client, dest is server
        printf("Client:      %d.%d.%d.%d:%d\n",
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
               (src_ip >> 8) & 0xFF, src_ip & 0xFF,
               src_port);
        printf("DNS Server:  %d.%d.%d.%d:%d\n",
               (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
               (dest_ip >> 8) & 0xFF, dest_ip & 0xFF,
               dest_port);
    }

    printf("\nDetection Metrics:\n");
    printf("Query Length:     %u bytes\n", event->query_length);
    printf("Payload Size:     %u bytes\n", event->payload_size);
    printf("Subdomain Count:  %u\n", event->subdomain_count);
    printf("Requests/min:     %u\n", event->frequency);
    printf("Query Type:       %s\n", event->query_type == 1 ? "Query" : "Response");
    printf("========================\n");

    // Log to file
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[%s] IF=%s DIR=%s SRC=%d.%d.%d.%d:%u DST=%d.%d.%d.%d:%u QLEN=%u PSIZE=%u SCOUNT=%u FREQ=%u/min\n",
            timestamp,
            if_name,
            is_response ? "Response ←" : "Query →",
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF, src_ip & 0xFF,
            src_port,
            (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
            (dest_ip >> 8) & 0xFF, dest_ip & 0xFF,
            dest_port,
            event->query_length,
            event->payload_size,
            event->subdomain_count,
            event->frequency);

    fflush(log_file);

    request_count++;
    return 0;
}

// Cleanup function to detach the XDP program
void cleanup(int signum) {
    // Show cursor again and clear screen
    printf("\033[?25h\033[2J\033[H");

    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (obj) {
        int ifindex = if_nametoindex("eth0");
        if (ifindex != 0) {
            bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        }
        bpf_object__close(obj);
        obj = NULL;
    }

    if (log_file) {
        fprintf(log_file, "\n=== Summary ===\nTotal DNS requests processed: %d\n", request_count);
        fclose(log_file);
        log_file = NULL;
    }

    printf("\nMonitoring Summary:\n");
    printf("Total DNS requests processed: %d\n", request_count);
    printf("Log file: %s\n", LOG_FILE);
    printf("Program terminated.\n");

    exit(0);
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    int prog_fd;
    int err;

    // Check if at least one interface is provided
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network-interface>\n", argv[0]);
        return 1;
    }

    // Store the interface name globally
    program_interface = argv[1];

    // Initialize display before starting
    init_display();

    // Open the BPF object file
    obj = bpf_object__open_file(BPF_PROG_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF program file: %s\n", strerror(errno));
        return 1;
    }

    // Load BPF object
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    // Find the XDP program in the object
    prog = bpf_object__find_program_by_name(obj, "packet_filter");
    if (!prog) {
        fprintf(stderr, "Error finding XDP program in BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting file descriptor for BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach to both loopback and provided interface
    const char *interfaces[] = {"lo", program_interface};
    for (int i = 0; i < 2; i++) {
        int ifindex = if_nametoindex(interfaces[i]);
        if (ifindex == 0) {
            fprintf(stderr, "Warning: interface %s not found\n", interfaces[i]);
            continue;
        }

        // Detach any existing program
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

        // Attach our program
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        if (err < 0) {
            fprintf(stderr, "Error attaching XDP program to interface %s: %s\n",
                    interfaces[i], strerror(-err));
            continue;
        }
        printf("Attached XDP program to interface %s\n", interfaces[i]);
    }

    // Open the ring buffer map
    int rb_map_fd = bpf_object__find_map_fd_by_name(obj, RINGBUF_MAP_NAME);
    if (rb_map_fd < 0) {
        fprintf(stderr, "Error finding ring buffer map in BPF object\n");
        goto cleanup;
    }

    // Configure ring buffer options
    rb = ring_buffer__new(rb_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error creating ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    // Register signal handler for cleanup on Ctrl-C
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // Open log file
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
        goto cleanup;
    }

    // Poll for events
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    cleanup(0); // Call cleanup function
    return 0;
}