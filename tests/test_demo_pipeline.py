"""Testa o pipeline de ponta a ponta usando os geradores de dados sinteticos
de demo/ -- garante que treino (dataset tabular) e inferencia (pcap real)
continuam compativeis conforme o codigo evolui."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

from make_demo_dataset import PROFILES, make_class, NEUTRAL  # noqa: E402
from make_demo_pcap import build_normal_traffic, build_portscan  # noqa: E402

import numpy as np
import pandas as pd
from scapy.all import wrpcap

from siadar.capture.pcap_to_flows import extract_flows
from siadar.classification.preprocess import fit_transform, transform
from siadar.data.load_cicids import load_cicids
from sklearn.ensemble import RandomForestClassifier


def test_end_to_end_demo_pipeline(tmp_path):
    rng = np.random.default_rng(7)
    frames = [make_class(rng, label, 60, {**NEUTRAL, **profile}) for label, profile in PROFILES.items()]
    df_raw = pd.concat(frames, ignore_index=True)
    csv_path = os.path.join(tmp_path, "synthetic_cicids.csv")
    df_raw.to_csv(csv_path, index=False)

    df = load_cicids(csv_path)
    X, y, label_encoder, scaler = fit_transform(df)
    model = RandomForestClassifier(n_estimators=50, random_state=7)
    model.fit(X, y)

    base_time = 1_700_000_000.0
    normal_packets, t = build_normal_traffic(base_time, n_flows=3)
    scan_packets, _ = build_portscan(t + 1.0, n_ports=15)
    pcap_path = os.path.join(tmp_path, "demo_capture.pcap")
    wrpcap(pcap_path, normal_packets + scan_packets)

    flows_df = extract_flows(pcap_path)
    assert len(flows_df) == 3 + 15

    X_infer = transform(flows_df, scaler)
    preds = label_encoder.inverse_transform(model.predict(X_infer))
    flows_df = flows_df.assign(predicted_label=preds)

    scan_preds = flows_df[flows_df["total_fwd_packets"] == 1]["predicted_label"]
    assert (scan_preds == "PortScan").all()

    normal_preds = flows_df[flows_df["total_bwd_packets"] > 0]["predicted_label"]
    assert (normal_preds == "BENIGN").all()
