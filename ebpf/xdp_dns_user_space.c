#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common_defines.h"

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#define BPF_PROG_PATH "dns_packet_filter.o"
#define RINGBUF_MAP_NAME "events"
#define LOG_FILE "dns_monitoring.log"

#define MAX_DOMAINS 10000
#define HASH_MAP_SIZE 1024
#define WINDOW_SIZE 60

// Feature extraction context
typedef struct {
    char domain[256];
    int qtype;
    int rcode;
    double entropy;
    int subdomain_count;
    int numerical_chars;
    int length;
    int longest_label;
} FeatureContext;

// IP Statistics for state management
typedef struct {
    __u32 ip;
    int count;
    time_t first_seen;
    time_t last_seen;
    int unique_domains;
    time_t last_reset;
    int current_window_count;
} IpStats;

// Simple Hash Map for IP Stats
static IpStats ip_stats_map[HASH_MAP_SIZE];
static int ip_stats_count = 0;

// Helper to get or create IP stats
static IpStats* get_ip_stats(__u32 ip) {
    int index = ip % HASH_MAP_SIZE;
    // Linear probing for simplicity
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        int idx = (index + i) % HASH_MAP_SIZE;
        if (ip_stats_map[idx].ip == 0 || ip_stats_map[idx].ip == ip) {
            if (ip_stats_map[idx].ip == 0) {
                ip_stats_map[idx].ip = ip;
                ip_stats_map[idx].first_seen = time(NULL);
                ip_stats_count++;
            }
            return &ip_stats_map[idx];
        }
    }
    return NULL; // Map full
}

// Entropy calculation
static double calculate_entropy(const char *domain) {
    if (!domain || *domain == '\0') return 0.0;
    
    int len = strlen(domain);
    int counts[256] = {0};
    for (int i = 0; i < len; i++) {
        counts[(unsigned char)domain[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Parse DNS name from wire format
static void parse_dns_name(const unsigned char *payload, int payload_len, int op, char *out_name, int *out_len) {
    int i = op; // Current payload offset
    int j = 0; // Output string offset
    int jumped = 0;
    int loop_limit = 0;

    out_name[0] = '\0';
    if (i >= payload_len) return;

    while (payload[i] != 0 && loop_limit++ < 100) {
        if (i >= payload_len) break;
        
        unsigned char len = payload[i];
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (i + 1 >= payload_len) break;
            if (!jumped) {
                jumped = 1;
            }
            int offset = ((len & 0x3F) << 8) | payload[i+1];
            i = offset;
            continue; // Jump to offset
        }

        // Standard label
        i++; // Move past length byte
        
        if (j > 0 && j < 255) out_name[j++] = '.';
        
        for (int k = 0; k < len; k++) {
            if (i >= payload_len || j >= 255) break;
            char c = payload[i++];
            if (isprint(c)) {
                out_name[j++] = c;
            } else {
                out_name[j++] = '?';
            }
        }
    }
    out_name[j] = '\0';
    *out_len = j;
}

static void analyze_features(struct dns_event *event, FeatureContext *ctx) {
    memset(ctx, 0, sizeof(FeatureContext));
    
    // Parse Payload for QNAME and QTYPE
    // Header is 12 bytes. Question stats at 12.
    if (event->payload_size > 12) {
        // Simple parsing of first question
        int cursor = 12;
        int name_len = 0;
        parse_dns_name(event->payload, event->payload_size, cursor, ctx->domain, &name_len);
        ctx->length = name_len;
    }
    
    if (ctx->length > 0) {
        ctx->entropy = calculate_entropy(ctx->domain);
        
        // Count subdomains and numbers
        ctx->subdomain_count = 0;
        ctx->numerical_chars = 0;
        ctx->longest_label = 0;
        
        int current_label_len = 0;
        for (int i = 0; i < ctx->length; i++) {
            if (ctx->domain[i] == '.') {
                ctx->subdomain_count++;
                if (current_label_len > ctx->longest_label) ctx->longest_label = current_label_len;
                current_label_len = 0;
            } else {
                current_label_len++;
                if (isdigit(ctx->domain[i])) {
                    ctx->numerical_chars++;
                }
            }
        }
        if (current_label_len > ctx->longest_label) ctx->longest_label = current_label_len;
    }
}


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
static int handle_event(void *ctx_unused, void *data, size_t data_sz) {
    struct dns_event *event = data;
    FeatureContext features;
    
    // Analyze features
    analyze_features(event, &features);
    
    // Update IP State
    IpStats *stats = get_ip_stats(ntohl(event->src_ip));
    if (stats) {
        stats->count++;
        stats->last_seen = time(NULL);
        // Reset window if minute changed
        if (stats->last_seen - stats->last_reset > 60) {
            stats->current_window_count = 0;
            stats->last_reset = stats->last_seen;
        }
        stats->current_window_count++;
    }

    char if_name[IF_NAMESIZE];
    memset(if_name, 0, IF_NAMESIZE);
    if (!if_indextoname(event->if_index, if_name)) {
        strncpy(if_name, "unknown", IF_NAMESIZE - 1);
    }

    __u32 src_ip = ntohl(event->src_ip);
    
    // Display
    if (first_display) {
        printf("\033[2J\033[H");
        first_display = 0;
    } else {
        printf("\033[H");
    }

    printf("=== DNS Security Analysis ===\n");
    printf("Domain:      %s\n", features.domain);
    printf("Entropy:     %.4f\n", features.entropy);
    printf("Subdomains:  %d\n", features.subdomain_count);
    printf("Num Chars:   %d\n", features.numerical_chars);
    printf("Longest Lbl: %d\n", features.longest_label);
    if (stats) {
        printf("IP Freq/Min: %d\n", stats->current_window_count);
    }
    printf("========================\n");

    // CSV Log
    if (log_file) {
        // Header: Timestamp, SrcIP, Domain, Entropy, Subdomains, NumChars, LongestLabel, Freq, PayloadSize
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        fprintf(log_file, "%s,%u.%u.%u.%u,%s,%.4f,%d,%d,%d,%d,%d\n",
            timestamp,
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
            features.domain,
            features.entropy,
            features.subdomain_count,
            features.numerical_chars,
            features.longest_label,
            stats ? stats->current_window_count : 1,
            event->payload_size
        );
        fflush(log_file);
    }

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
    log_file = fopen("dns_features.csv", "a"); // Changed to CSV
    if (!log_file) {
        fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
        goto cleanup;
    }
    // Write Header if file is empty
    fseek(log_file, 0, SEEK_END);
    if (ftell(log_file) == 0) {
        fprintf(log_file, "Timestamp,SrcIP,Domain,Entropy,Subdomains,NumChars,LongestLabel,FreqMin,PayloadSize\n");
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