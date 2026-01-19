import pandas as pd

INFECTED_IPS = {
    "147.32.84.165"  # example CTU-13 bot
}

df = pd.read_csv("dns_ml_features.csv")

df["label"] = df["src_ip"].apply(
    lambda ip: 1 if ip in INFECTED_IPS else 0
)

df.to_csv("dns_ml_features_labeled.csv", index=False)
print("[+] Labeled dataset saved")
