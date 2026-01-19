import pandas as pd
import numpy as np

WINDOW = 60  # seconds

df = pd.read_csv("dns_raw.csv")

# Window by time
df["window"] = (df["ts"] // WINDOW).astype(int)

features = []

for (src, win), g in df.groupby(["src_ip", "window"]):
    timestamps = g["ts"].sort_values()

    interarrival = timestamps.diff().dropna()

    features.append({
        "src_ip": src,
        "window": win,
        "num_packets": len(g),
        "avg_payload_len": g["payload_len"].mean(),
        "max_payload_len": g["payload_len"].max(),
        "query_ratio": g["is_query"].mean(),
        "unique_dst_ips": g["dst_ip"].nunique(),
        "avg_interarrival": interarrival.mean() if len(interarrival) else 0,
        "std_interarrival": interarrival.std() if len(interarrival) else 0,
    })

feat_df = pd.DataFrame(features)
feat_df.to_csv("dns_ml_features.csv", index=False)

print(f"[+] Generated {len(feat_df)} ML feature rows")
