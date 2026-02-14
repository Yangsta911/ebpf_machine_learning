#!/usr/bin/env python3
import subprocess
import time
import random
import argparse
import sys

# List of popular domains to simulate benign traffic
TOP_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 
    'netflix.com', 'wikipedia.org', 'microsoft.com', 'twitter.com', 
    'linkedin.com', 'instagram.com', 'youtube.com', 'tiktok.com', 
    'reddit.com', 'weather.com', 'nytimes.com', 'cnn.com', 
    'twitch.tv', 'whatsapp.com', 'spotify.com', 'dropbox.com',
    'github.com', 'stackoverflow.com', 'medium.com', 'zoom.us'
]

def generate_benign(count: int, target_ip: str):
    print(f"[*] Starting BENIGN traffic generation...")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Count: {count} requests")
    
    for i in range(count):
        domain = random.choice(TOP_DOMAINS)
        
        # Simulate realistic noise: occasionally add a random subdomain (CDN-style)
        if random.random() < 0.2: # 20% chance
            sub = f"cdn-{random.randint(100, 999)}"
            domain = f"{sub}.{domain}"
            
        try:
            # Use dig to generate the query
            # stdout=subprocess.DEVNULL hides the dig output
            subprocess.run(
                ["dig", f"@{target_ip}", domain], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            # Simple progress indicator
            if (i + 1) % 10 == 0:
                print(f"    Sent {i + 1}/{count} queries...", end='\r')
                
        except Exception as e:
            print(f"[!] Error sending query: {e}")

        # Jitter: Sleep for a random interval between 0.1s and 0.5s
        time.sleep(random.uniform(0.1, 0.5))

    print(f"\n[*] Completed sending {count} benign queries.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic DNS traffic.")
    parser.add_argument("--type", choices=['benign'], default='benign', help="Type of traffic to generate")
    parser.add_argument("--count", type=int, default=50, help="Number of queries to send")
    parser.add_argument("--target", default="127.0.0.1", help="Target DNS server IP (default: 127.0.0.1)")

    args = parser.parse_args()

    if args.type == 'benign':
        generate_benign(args.count, args.target)
    else:
        print("Only 'benign' type is supported in this simple version.")
