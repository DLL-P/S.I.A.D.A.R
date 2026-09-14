"""Gera um dataset de treino a partir de trafego sintetico REAL: cria pacotes
com rotulo conhecido (normal, portscan, flood tipo DDoS), extrai os flows
com o proprio codigo do Modulo 1 (siadar.capture.pcap_to_flows) e salva como
CSV no formato bruto do CICIDS2017.

Gerar o dataset assim -- em vez de inventar numeros de feature "tipicos" a
mao -- garante que a distribuicao de treino bate exatamente com o que uma
captura real produz: nao ha descasamento de escala entre o CSV de treino e
um .pcap real, o que importa sobretudo para o Modulo 3 (deteccao de
anomalias), sensivel a distancia estatistica entre as features.

Uso:
    python demo/make_demo_dataset.py -o demo/output/synthetic_cicids.csv
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd
from scapy.all import wrpcap

from make_demo_pcap import build_ddos, build_normal_traffic, build_portscan  # noqa: E402

from siadar.capture.pcap_to_flows import extract_flows
from siadar.features.schema import CORE_FLOW_FEATURES, LABEL_COLUMN

# canonical (siadar.features.schema) -> nome bruto do CICIDS2017, para o CSV
# de saida ser lido sem alteracoes por siadar.data.load_cicids.load_cicids()
_RAW_NAMES = {
    "flow_duration": " Flow Duration",
    "total_fwd_packets": " Total Fwd Packets",
    "total_bwd_packets": " Total Backward Packets",
    "total_length_fwd_packets": "Total Length of Fwd Packets",
    "total_length_bwd_packets": " Total Length of Bwd Packets",
    "fwd_packet_length_max": " Fwd Packet Length Max",
    "fwd_packet_length_min": " Fwd Packet Length Min",
    "fwd_packet_length_mean": " Fwd Packet Length Mean",
    "fwd_packet_length_std": " Fwd Packet Length Std",
    "bwd_packet_length_max": "Bwd Packet Length Max",
    "bwd_packet_length_min": " Bwd Packet Length Min",
    "bwd_packet_length_mean": " Bwd Packet Length Mean",
    "bwd_packet_length_std": " Bwd Packet Length Std",
    "flow_bytes_per_s": "Flow Bytes/s",
    "flow_packets_per_s": " Flow Packets/s",
    "flow_iat_mean": " Flow IAT Mean",
    "flow_iat_std": " Flow IAT Std",
    "flow_iat_max": " Flow IAT Max",
    "flow_iat_min": " Flow IAT Min",
    "fin_flag_count": "FIN Flag Count",
    "syn_flag_count": " SYN Flag Count",
    "rst_flag_count": " RST Flag Count",
    "psh_flag_count": " PSH Flag Count",
    "ack_flag_count": " ACK Flag Count",
    "urg_flag_count": " URG Flag Count",
    "packet_length_mean": " Packet Length Mean",
    "packet_length_std": " Packet Length Std",
}

NORMAL_PAIR = ("10.0.0.5", "10.0.0.10")
SCAN_TARGET = "10.0.0.20"
DDOS_TARGET = "10.0.0.30"


def _label_row(row) -> str:
    pair = {row["src_ip"], row["dst_ip"]}
    if pair == set(NORMAL_PAIR):
        return "BENIGN"
    if SCAN_TARGET in pair:
        return "PortScan"
    if DDOS_TARGET in pair:
        return "DDoS"
    return "UNKNOWN"


def build_labeled_dataset(
    seed: int = 42,
    n_normal_flows: int = 80,
    n_scan_ports: int = 60,
    n_ddos_bursts: int = 40,
    tmp_pcap: str = "demo/output/_train_capture.pcap",
) -> pd.DataFrame:
    """Gera pacotes com rotulo conhecido, extrai os flows com o codigo real
    do Modulo 1 e devolve um DataFrame com as colunas canonicas + label."""
    base_time = 1_700_000_000.0
    all_packets = []

    normal_packets, t = build_normal_traffic(
        base_time, client=NORMAL_PAIR[0], server=NORMAL_PAIR[1], n_flows=n_normal_flows, seed=seed
    )
    all_packets += normal_packets

    scan_packets, t = build_portscan(t + 1.0, target=SCAN_TARGET, n_ports=n_scan_ports)
    all_packets += scan_packets
    t += 1.0

    rng = np.random.default_rng(seed)
    for i in range(n_ddos_bursts):
        n_pkts = int(rng.integers(120, 500))
        flood_packets, t = build_ddos(t + 0.2, target=DDOS_TARGET, n_packets=n_pkts, seed=seed + 1000 + i)
        all_packets += flood_packets

    os.makedirs(os.path.dirname(tmp_pcap) or ".", exist_ok=True)
    wrpcap(tmp_pcap, all_packets)
    flows = extract_flows(tmp_pcap)
    os.remove(tmp_pcap)

    flows[LABEL_COLUMN] = flows.apply(_label_row, axis=1)
    flows = flows[flows[LABEL_COLUMN] != "UNKNOWN"].reset_index(drop=True)
    return flows


def to_cicids_csv_format(df: pd.DataFrame) -> pd.DataFrame:
    """Renomeia as colunas canonicas para o formato bruto do CICIDS2017."""
    out = df[CORE_FLOW_FEATURES + [LABEL_COLUMN]].rename(columns=_RAW_NAMES)
    return out.rename(columns={LABEL_COLUMN: " Label"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera dataset de treino a partir de trafego sintetico real")
    parser.add_argument("-o", "--output", default="demo/output/synthetic_cicids.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = build_labeled_dataset(seed=args.seed)
    out = to_cicids_csv_format(df)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    out.to_csv(args.output, index=False)
    print(f"{len(out)} flows extraidos de trafego sintetico real -> {args.output}")
    print(out[" Label"].value_counts())


if __name__ == "__main__":
    main()
