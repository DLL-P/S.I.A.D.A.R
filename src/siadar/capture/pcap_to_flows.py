"""Modulo 1: captura e pre-processamento.

Le um arquivo .pcap/.pcapng e agrega os pacotes em flows usando a 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol), calculando as features
descritas no guia do projeto (duracao, bytes/pacotes fwd-bwd, IAT, flags TCP,
entropia do payload).

Uso:
    python -m siadar.capture.pcap_to_flows caminho/para/arquivo.pcap -o flows.csv
"""

from __future__ import annotations

import argparse
import math
from collections import Counter
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader, Raw

from siadar.features.schema import CORE_FLOW_FEATURES, CAPTURE_ONLY_FEATURES, IDENTIFIER_COLUMNS

# Flows inativos por mais que isso (segundos) sao fechados e um novo flow
# comeca para o mesmo par de enderecos/portas (mesma logica do CICFlowMeter).
FLOW_TIMEOUT_S = 120.0

_TCP_FLAG_LETTERS = {"F": "fin", "S": "syn", "R": "rst", "P": "psh", "A": "ack", "U": "urg"}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class _FlowAccumulator:
    first_src: tuple
    start_time: float
    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)
    timestamps: list = field(default_factory=list)
    flag_counts: Counter = field(default_factory=Counter)
    payload: bytearray = field(default_factory=bytearray)
    last_time: float = 0.0

    def add(self, pkt, src, length: int, ts: float, flags: str, payload: bytes) -> None:
        if src == self.first_src:
            self.fwd_lengths.append(length)
        else:
            self.bwd_lengths.append(length)
        self.timestamps.append(ts)
        self.last_time = ts
        for letter, name in _TCP_FLAG_LETTERS.items():
            if letter in flags:
                self.flag_counts[name] += 1
        if payload:
            self.payload.extend(payload)

    def to_row(self, key: tuple) -> dict:
        src_ip, src_port, dst_ip, dst_port, proto = key
        fwd = np.array(self.fwd_lengths, dtype=float)
        bwd = np.array(self.bwd_lengths, dtype=float)
        all_lengths = np.concatenate([fwd, bwd]) if (len(fwd) or len(bwd)) else np.array([0.0])
        ts = np.array(sorted(self.timestamps), dtype=float)
        iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])
        duration = max(self.last_time - self.start_time, 1e-6)

        def stat(arr, fn, default=0.0):
            return float(fn(arr)) if len(arr) else default

        row = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "flow_duration": duration,
            "total_fwd_packets": len(fwd),
            "total_bwd_packets": len(bwd),
            "total_length_fwd_packets": stat(fwd, np.sum),
            "total_length_bwd_packets": stat(bwd, np.sum),
            "fwd_packet_length_max": stat(fwd, np.max),
            "fwd_packet_length_min": stat(fwd, np.min),
            "fwd_packet_length_mean": stat(fwd, np.mean),
            "fwd_packet_length_std": stat(fwd, np.std),
            "bwd_packet_length_max": stat(bwd, np.max),
            "bwd_packet_length_min": stat(bwd, np.min),
            "bwd_packet_length_mean": stat(bwd, np.mean),
            "bwd_packet_length_std": stat(bwd, np.std),
            "flow_bytes_per_s": stat(all_lengths, np.sum) / duration,
            "flow_packets_per_s": (len(fwd) + len(bwd)) / duration,
            "flow_iat_mean": stat(iat, np.mean),
            "flow_iat_std": stat(iat, np.std),
            "flow_iat_max": stat(iat, np.max),
            "flow_iat_min": stat(iat, np.min),
            "fin_flag_count": self.flag_counts.get("fin", 0),
            "syn_flag_count": self.flag_counts.get("syn", 0),
            "rst_flag_count": self.flag_counts.get("rst", 0),
            "psh_flag_count": self.flag_counts.get("psh", 0),
            "ack_flag_count": self.flag_counts.get("ack", 0),
            "urg_flag_count": self.flag_counts.get("urg", 0),
            "packet_length_mean": stat(all_lengths, np.mean),
            "packet_length_std": stat(all_lengths, np.std),
            "ratio_fwd_bwd_packets": len(fwd) / (len(bwd) + 1),
            "ratio_fwd_bwd_bytes": stat(fwd, np.sum) / (stat(bwd, np.sum) + 1),
            "payload_entropy": _shannon_entropy(bytes(self.payload)),
        }
        return row


def extract_flows(pcap_path: str) -> pd.DataFrame:
    """Agrega os pacotes de um pcap em flows e retorna um DataFrame de features."""
    open_flows: dict[tuple, _FlowAccumulator] = {}
    closed_rows: list[dict] = []

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            if TCP in pkt:
                proto, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
            elif UDP in pkt:
                proto, sport, dport, flags = "UDP", pkt[UDP].sport, pkt[UDP].dport, ""
            else:
                continue

            ts = float(pkt.time)
            length = len(pkt)
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            src = (ip.src, sport)
            dst = (ip.dst, dport)
            key = tuple(sorted([src, dst])) + (proto,)

            acc = open_flows.get(key)
            if acc is not None and ts - acc.last_time > FLOW_TIMEOUT_S:
                closed_rows.append(acc.to_row(_expand_key(key)))
                acc = None

            if acc is None:
                acc = _FlowAccumulator(first_src=src, start_time=ts)
                open_flows[key] = acc

            acc.add(pkt, src, length, ts, flags, payload)

    for key, acc in open_flows.items():
        closed_rows.append(acc.to_row(_expand_key(key)))

    columns = IDENTIFIER_COLUMNS + CORE_FLOW_FEATURES + CAPTURE_ONLY_FEATURES
    return pd.DataFrame(closed_rows, columns=columns)


def _expand_key(key: tuple) -> tuple:
    (ip_a, port_a), (ip_b, port_b), proto = key
    return ip_a, port_a, ip_b, port_b, proto


def main() -> None:
    parser = argparse.ArgumentParser(description="Extrai features de flow de um arquivo pcap")
    parser.add_argument("pcap", help="Caminho para o arquivo .pcap/.pcapng")
    parser.add_argument("-o", "--output", default="flows.csv", help="CSV de saida")
    args = parser.parse_args()

    df = extract_flows(args.pcap)
    df.to_csv(args.output, index=False)
    print(f"{len(df)} flows extraidos -> {args.output}")


if __name__ == "__main__":
    main()
