"""Testa a agregacao de pacotes em flows com um pcap sintetico pequeno."""

import os

import pytest
from scapy.all import IP, TCP, Raw, wrpcap

from siadar.capture.pcap_to_flows import extract_flows


def _make_synthetic_pcap(path: str) -> None:
    packets = []
    base_time = 1_700_000_000.0

    # 3 pacotes de A -> B (forward) e 2 de B -> A (backward), mesma conexao TCP
    for i in range(3):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"x" * 100)
        pkt.time = base_time + i
        packets.append(pkt)

    for i in range(2):
        pkt = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="A") / Raw(load=b"y" * 50)
        pkt.time = base_time + 3 + i
        packets.append(pkt)

    wrpcap(path, packets)


def test_extract_flows_aggregates_single_bidirectional_flow(tmp_path):
    pcap_path = os.path.join(tmp_path, "synthetic.pcap")
    _make_synthetic_pcap(pcap_path)

    df = extract_flows(pcap_path)

    assert len(df) == 1
    row = df.iloc[0]
    assert row["total_fwd_packets"] == 3
    assert row["total_bwd_packets"] == 2
    # total_length_* conta o pacote inteiro (IP+TCP+payload), igual ao CICFlowMeter:
    # fwd = 3 pacotes de 100 bytes de payload + 40 de cabecalho IP/TCP = 140 cada
    fwd_pkt_len = len(bytes(IP() / TCP() / Raw(load=b"x" * 100)))
    bwd_pkt_len = len(bytes(IP() / TCP() / Raw(load=b"y" * 50)))
    assert row["total_length_fwd_packets"] == 3 * fwd_pkt_len
    assert row["total_length_bwd_packets"] == 2 * bwd_pkt_len
    assert row["psh_flag_count"] == 3
    assert row["ack_flag_count"] == 5
    assert row["flow_duration"] > 0
    # payload = 300 bytes 'x' + 100 bytes 'y' -> entropia de Shannon de uma
    # fonte binaria com p=0.75/0.25
    assert row["payload_entropy"] == pytest.approx(0.8113, abs=1e-3)
