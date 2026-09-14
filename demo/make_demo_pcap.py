"""Gera um .pcap sintetico com dois cenarios reais de tráfego, para exercitar
siadar.capture.pcap_to_flows.py com um arquivo de captura de verdade (nao
apenas dados tabulares simulados):

1. Trafego "normal": algumas conversas TCP bidirecionais com payload, tipo
   uma sessao HTTP simples (varios pacotes de ida e volta).
2. Um portscan: um host varrendo dezenas de portas de outro host em
   sequencia rapida, so com pacotes SYN -- a assinatura classica de
   reconhecimento de rede.

Uso:
    python demo/make_demo_pcap.py -o demo/output/demo_capture.pcap
"""

from __future__ import annotations

import argparse
import os

import numpy as np
from scapy.all import IP, TCP, Raw, wrpcap


def build_normal_traffic(base_time: float, client="10.0.0.5", server="10.0.0.10", n_flows=5, seed=123):
    """Simula sessoes HTTPS com handshake TCP e tamanhos de pacote variados
    -- realismo suficiente para as features extraidas (min/max/std de
    tamanho de pacote, contagem de SYN, IAT) se parecerem com trafego
    normal de verdade, nao com um padrao artificialmente uniforme."""
    rng = np.random.default_rng(seed)
    packets = []
    t = base_time
    for i in range(n_flows):
        cport = 40000 + i
        sport = 443

        # handshake TCP (SYN / SYN-ACK / ACK)
        for flags, src, dst, sp, dp in [
            ("S", client, server, cport, sport),
            ("SA", server, client, sport, cport),
            ("A", client, server, cport, sport),
        ]:
            pkt = IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags)
            pkt.time = t
            packets.append(pkt)
            t += rng.uniform(0.005, 0.02)

        # ida: cliente manda requisicao (tamanho variavel)
        for _ in range(rng.integers(2, 5)):
            payload = os.urandom(int(rng.integers(40, 200)))
            pkt = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="PA") / Raw(load=payload)
            pkt.time = t
            packets.append(pkt)
            t += rng.uniform(0.01, 0.05)

        # volta: servidor responde (tamanho variavel, tipicamente maior)
        for _ in range(rng.integers(3, 7)):
            payload = os.urandom(int(rng.integers(200, 900)))
            pkt = IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="PA") / Raw(load=payload)
            pkt.time = t
            packets.append(pkt)
            t += rng.uniform(0.005, 0.03)

        # encerramento
        pkt = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="FA")
        pkt.time = t
        packets.append(pkt)
        t += rng.uniform(0.3, 0.8)  # intervalo entre "sessoes"
    return packets, t


def build_portscan(base_time: float, attacker="10.0.0.99", target="10.0.0.20", n_ports=40):
    packets = []
    t = base_time
    for port in range(1, n_ports + 1):
        pkt = IP(src=attacker, dst=target) / TCP(sport=51000, dport=port, flags="S")
        pkt.time = t
        packets.append(pkt)
        t += 0.003  # varredura rapida, portas diferentes = flows diferentes
    return packets, t


def build_ddos(base_time: float, attacker="10.0.0.50", target="10.0.0.30", dport=80, n_packets=300, seed=77):
    """Simula uma inundacao SYN: muitos pacotes do mesmo par origem/destino
    em rajada, sem resposta -- um unico flow com contagem de pacotes muito
    alta e trafego quase todo em uma direcao (assinatura classica de DDoS)."""
    rng = np.random.default_rng(seed)
    packets = []
    t = base_time
    sport = int(rng.integers(20000, 60000))
    for _ in range(n_packets):
        pkt = IP(src=attacker, dst=target) / TCP(sport=sport, dport=dport, flags="S")
        pkt.time = t
        packets.append(pkt)
        t += rng.uniform(0.0005, 0.002)  # rajada rapida
    return packets, t


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera uma captura .pcap sintetica com trafego normal + portscan")
    parser.add_argument("-o", "--output", default="demo/output/demo_capture.pcap")
    args = parser.parse_args()

    base_time = 1_700_000_000.0
    normal_packets, t = build_normal_traffic(base_time)
    scan_packets, _ = build_portscan(t + 1.0)

    all_packets = normal_packets + scan_packets

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    wrpcap(args.output, all_packets)
    print(f"{len(all_packets)} pacotes ({len(normal_packets)} trafego normal + {len(scan_packets)} portscan) -> {args.output}")


if __name__ == "__main__":
    main()
