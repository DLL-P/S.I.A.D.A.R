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

from scapy.all import IP, TCP, Raw, wrpcap


def build_normal_traffic(base_time: float, client="10.0.0.5", server="10.0.0.10", n_flows=5):
    packets = []
    t = base_time
    for i in range(n_flows):
        cport = 40000 + i
        sport = 443
        # ida: cliente manda requisicao
        for j in range(3):
            pkt = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="PA") / Raw(load=b"GET /" + str(j).encode() * 20)
            pkt.time = t
            packets.append(pkt)
            t += 0.02
        # volta: servidor responde
        for j in range(4):
            pkt = IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="PA") / Raw(load=b"HTTP/1.1 200 OK" + b"x" * 300)
            pkt.time = t
            packets.append(pkt)
            t += 0.015
        t += 0.5  # intervalo entre "sessoes"
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
