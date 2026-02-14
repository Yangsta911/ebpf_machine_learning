#ifndef COMMON_DEFINES_H
#define COMMON_DEFINES_H

#define MAX_DNS_PAYLOAD 256

struct dns_event {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u16 query_length;     // Length of DNS query
    __u16 payload_size;     // Total DNS payload size
    __u8 query_type;        // Type of DNS query (A, TXT, etc.) - extracted in user space now
    __u8 subdomain_count;   // Number of subdomains - extracted in user space now
    __u64 timestamp;        // Timestamp for frequency analysis
    __u32 frequency;        // Packet count from same source
    __u32 if_index;         // Interface index
    __u8 direction;         // 0 for query, 1 for response
    unsigned char payload[MAX_DNS_PAYLOAD]; // Raw DNS payload
};

#endif // COMMON_DEFINES_H
