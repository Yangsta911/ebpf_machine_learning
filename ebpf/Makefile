# Compiler and flags
CC = clang
CFLAGS = -O2 -g -Wall -Werror $(CFLAGS_EXTRA)
BPF_CFLAGS = -O2 -g -Wall -Werror $(BPF_CFLAGS_EXTRA)

# Include paths
INCLUDES = -I/usr/include/linux -I/usr/include/x86_64-linux-gnu

# BPF targets
BPF_TARGETS = dns_packet_filter.o

# User space targets
USER_TARGETS = xdp_dns_user_space

# Default target
all: $(BPF_TARGETS) $(USER_TARGETS)

# BPF object files
%.o: %.c
	$(CC) $(BPF_CFLAGS) -target bpf -c $< -o $@

# User space programs
xdp_dns_user_space: xdp_dns_user_space.c dns_packet_filter.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -lbpf -lelf

# Clean target
clean:
	rm -f $(BPF_TARGETS) $(USER_TARGETS)

# Docker targets
docker-build:
	docker build -t ebpf-dns-monitor .

docker-run:
	docker run --privileged -it --rm ebpf-dns-monitor

.PHONY: all clean docker-build docker-run