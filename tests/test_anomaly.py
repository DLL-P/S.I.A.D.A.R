"""Testa o Modulo 3 (deteccao de anomalias): um Isolation Forest treinado
apenas com trafego BENIGN extraido de uma captura sintetica real deve
sinalizar a maior parte dos flows de ataque (PortScan/DDoS) como anomalos,
sem disparar demais em trafego normal que ele nunca viu no treino."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

from make_demo_dataset import build_labeled_dataset  # noqa: E402

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from siadar.anomaly.preprocess import fit_scaler, transform
from siadar.features.schema import LABEL_COLUMN


def test_isolation_forest_flags_attacks_not_seen_in_training(tmp_path):
    df = build_labeled_dataset(
        seed=13, n_normal_flows=30, n_scan_ports=30, n_ddos_bursts=15,
        tmp_pcap=os.path.join(tmp_path, "_train.pcap"),
    )

    is_benign = df[LABEL_COLUMN] == "BENIGN"
    benign_train, benign_test = train_test_split(df[is_benign], test_size=0.3, random_state=13)
    attack_df = df[~is_benign]

    X_train, scaler = fit_scaler(benign_train)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=13)
    model.fit(X_train)

    attack_pred = model.predict(transform(attack_df, scaler))
    attack_detection_rate = (attack_pred == -1).mean()

    benign_pred = model.predict(transform(benign_test, scaler))
    benign_false_positive_rate = (benign_pred == -1).mean()

    assert attack_detection_rate > 0.6, f"detection rate baixo demais: {attack_detection_rate}"
    assert benign_false_positive_rate < 0.3, f"falso positivo alto demais: {benign_false_positive_rate}"
