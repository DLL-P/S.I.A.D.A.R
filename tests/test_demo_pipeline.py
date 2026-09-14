"""Testa o pipeline de ponta a ponta usando os geradores de demo/ -- garante
que treino (a partir de trafego sintetico extraido via pcap_to_flows) e
inferencia (sobre um pcap real separado) continuam compativeis conforme o
codigo evolui."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

from make_demo_dataset import build_labeled_dataset, to_cicids_csv_format  # noqa: E402
from make_demo_pcap import build_normal_traffic, build_portscan  # noqa: E402

from scapy.all import wrpcap
from sklearn.ensemble import RandomForestClassifier

from siadar.capture.pcap_to_flows import extract_flows
from siadar.classification.preprocess import fit_transform, transform
from siadar.data.load_cicids import load_cicids


def test_end_to_end_demo_pipeline(tmp_path):
    train_df = build_labeled_dataset(
        seed=5, n_normal_flows=20, n_scan_ports=20, n_ddos_bursts=10,
        tmp_pcap=os.path.join(tmp_path, "_train.pcap"),
    )
    csv_path = os.path.join(tmp_path, "synthetic_cicids.csv")
    to_cicids_csv_format(train_df).to_csv(csv_path, index=False)

    df = load_cicids(csv_path)
    X, y, label_encoder, scaler = fit_transform(df)
    model = RandomForestClassifier(n_estimators=100, random_state=5)
    model.fit(X, y)

    base_time = 1_700_000_500.0
    normal_packets, t = build_normal_traffic(base_time, n_flows=3, seed=99)
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
