"""
NetSentry AI - Baseline Network Dataset & Model Auto-Trainer
Generates representative baseline normal traffic samples and pre-trains the ML model.
"""

import random
import logging
import pandas as pd
from pathlib import Path
from src.ml.features import FEATURE_COLUMNS
from src.ml.model import get_detector

logger = logging.getLogger("netsentry.ml")


def generate_baseline_dataset(num_samples: int = 1200) -> pd.DataFrame:
    """
    Generates a realistic baseline dataset of typical benign network traffic.
    Simulates:
    - HTTP / HTTPS web traffic (ports 80, 443, typical sizes 150 - 1500 bytes)
    - DNS queries / responses (port 53, sizes 60 - 300 bytes)
    - NTP synchronization (port 123, size 76 - 90 bytes)
    - Routine TCP handshakes and safe client connections
    """
    records = []
    random.seed(42)

    for _ in range(num_samples):
        traffic_type = random.choices(
            ["https", "http", "dns", "ntp", "ssh_normal"],
            weights=[0.55, 0.20, 0.15, 0.05, 0.05]
        )[0]

        if traffic_type == "https":
            records.append({
                "length": float(random.randint(150, 1460)),
                "protocol_code": 6.0,
                "src_port": float(random.randint(49152, 65535)),
                "dst_port": 443.0,
                "is_well_known_dst": 1.0,
                "is_sensitive_port": 0.0,
                "is_ephemeral_src": 1.0,
                "has_syn_flag": 1.0 if random.random() < 0.15 else 0.0,
                "has_fin_or_rst_flag": 1.0 if random.random() < 0.10 else 0.0,
            })
        elif traffic_type == "http":
            records.append({
                "length": float(random.randint(200, 1400)),
                "protocol_code": 6.0,
                "src_port": float(random.randint(49152, 65535)),
                "dst_port": 80.0,
                "is_well_known_dst": 1.0,
                "is_sensitive_port": 0.0,
                "is_ephemeral_src": 1.0,
                "has_syn_flag": 1.0 if random.random() < 0.15 else 0.0,
                "has_fin_or_rst_flag": 1.0 if random.random() < 0.10 else 0.0,
            })
        elif traffic_type == "dns":
            records.append({
                "length": float(random.randint(64, 280)),
                "protocol_code": 17.0,
                "src_port": float(random.randint(49152, 65535)),
                "dst_port": 53.0,
                "is_well_known_dst": 1.0,
                "is_sensitive_port": 0.0,
                "is_ephemeral_src": 1.0,
                "has_syn_flag": 0.0,
                "has_fin_or_rst_flag": 0.0,
            })
        elif traffic_type == "ntp":
            records.append({
                "length": float(random.randint(76, 96)),
                "protocol_code": 17.0,
                "src_port": float(random.randint(49152, 65535)),
                "dst_port": 123.0,
                "is_well_known_dst": 1.0,
                "is_sensitive_port": 0.0,
                "is_ephemeral_src": 1.0,
                "has_syn_flag": 0.0,
                "has_fin_or_rst_flag": 0.0,
            })
        elif traffic_type == "ssh_normal":
            records.append({
                "length": float(random.randint(90, 800)),
                "protocol_code": 6.0,
                "src_port": float(random.randint(49152, 65535)),
                "dst_port": 22.0,
                "is_well_known_dst": 1.0,
                "is_sensitive_port": 1.0,
                "is_ephemeral_src": 1.0,
                "has_syn_flag": 1.0 if random.random() < 0.05 else 0.0,
                "has_fin_or_rst_flag": 0.0,
            })

    return pd.DataFrame(records)[FEATURE_COLUMNS]


def ensure_model_trained(model_path: Path, scaler_path: Path):
    """
    Checks if a trained model exists; if not, trains a fresh model
    on the baseline dataset and saves it to disk.
    """
    detector = get_detector()
    if detector.load(model_path, scaler_path):
        return

    logger.info("No saved Isolation Forest model found. Training fresh baseline model...")
    df_baseline = generate_baseline_dataset(num_samples=1500)
    detector.train(df_baseline)
    detector.save(model_path, scaler_path)
    logger.info("Baseline model generated and saved.")

