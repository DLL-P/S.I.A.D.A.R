"""Gera um CSV sintetico no formato bruto do CICIDS2017 (mesmos nomes de
coluna, com os espacos irregulares originais) para treinar o classificador
sem depender do download do dataset publico completo.

As tres classes (BENIGN, PortScan, DDoS) tem distribuicoes de features
propositalmente diferentes -- o suficiente para o Random Forest aprender a
separar, mas com ruido, para nao virar um caso trivial demais.

Uso:
    python demo/make_demo_dataset.py -o demo/output/synthetic_cicids.csv -n 300
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd


def _sample(rng, mean, std, n, minimum=0.0):
    return np.clip(rng.normal(mean, std, n), minimum, None)


def make_class(rng, label: str, n: int, profile: dict) -> pd.DataFrame:
    row = {}
    for feature, (mean, std, minimum) in profile.items():
        row[feature] = _sample(rng, mean, std, n, minimum)
    row[" Label"] = label
    return pd.DataFrame(row)


# (media, desvio, minimo) por classe -- só as features que realmente
# diferenciam o comportamento; o resto é preenchido com ruído neutro depois.
PROFILES = {
    "BENIGN": {
        " Flow Duration": (2_000_000, 700_000, 50_000),
        " Total Fwd Packets": (15, 5, 1),
        " Total Backward Packets": (12, 5, 0),
        "Total Length of Fwd Packets": (9000, 3000, 100),
        " Total Length of Bwd Packets": (7000, 3000, 0),
        " Fwd Packet Length Mean": (600, 150, 40),
        "Bwd Packet Length Mean": (550, 150, 40),
        "Flow Bytes/s": (8000, 3000, 100),
        " Flow Packets/s": (15, 5, 1),
        " SYN Flag Count": (1, 0.5, 0),
        " ACK Flag Count": (18, 6, 1),
        " RST Flag Count": (0.2, 0.4, 0),
    },
    "PortScan": {
        " Flow Duration": (4_000, 2_000, 1),
        " Total Fwd Packets": (1.2, 0.4, 1),
        " Total Backward Packets": (0.1, 0.3, 0),
        "Total Length of Fwd Packets": (54, 10, 40),
        " Total Length of Bwd Packets": (2, 5, 0),
        " Fwd Packet Length Mean": (54, 8, 40),
        "Bwd Packet Length Mean": (5, 10, 0),
        "Flow Bytes/s": (15000, 6000, 500),
        " Flow Packets/s": (900, 300, 50),
        " SYN Flag Count": (1, 0.2, 0),
        " ACK Flag Count": (0.1, 0.3, 0),
        " RST Flag Count": (0.5, 0.5, 0),
    },
    "DDoS": {
        " Flow Duration": (1_500_000, 500_000, 100_000),
        " Total Fwd Packets": (800, 250, 100),
        " Total Backward Packets": (5, 5, 0),
        "Total Length of Fwd Packets": (400_000, 120_000, 5_000),
        " Total Length of Bwd Packets": (300, 400, 0),
        " Fwd Packet Length Mean": (500, 100, 40),
        "Bwd Packet Length Mean": (60, 40, 0),
        "Flow Bytes/s": (300_000, 90_000, 5_000),
        " Flow Packets/s": (600, 200, 50),
        " SYN Flag Count": (700, 220, 50),
        " ACK Flag Count": (2, 3, 0),
        " RST Flag Count": (0.3, 0.5, 0),
    },
}

# features neutras (ruido parecido entre classes) -- so pra completar o
# schema que load_cicids.py espera
NEUTRAL = {
    " Fwd Packet Length Max": (900, 200, 50),
    " Fwd Packet Length Min": (50, 20, 20),
    " Fwd Packet Length Std": (200, 60, 5),
    "Bwd Packet Length Max": (900, 200, 0),
    " Bwd Packet Length Min": (50, 20, 0),
    " Bwd Packet Length Std": (200, 60, 0),
    " Flow IAT Mean": (50_000, 20_000, 100),
    " Flow IAT Std": (20_000, 8_000, 0),
    " Flow IAT Max": (200_000, 80_000, 100),
    " Flow IAT Min": (500, 300, 0),
    "FIN Flag Count": (0.5, 0.5, 0),
    " PSH Flag Count": (5, 3, 0),
    " URG Flag Count": (0, 0.1, 0),
    " Packet Length Mean": (400, 150, 20),
    " Packet Length Std": (150, 60, 0),
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera dataset sintetico no formato CICIDS2017")
    parser.add_argument("-o", "--output", default="demo/output/synthetic_cicids.csv")
    parser.add_argument("-n", "--per-class", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    frames = []
    for label, profile in PROFILES.items():
        full_profile = {**NEUTRAL, **profile}
        frames.append(make_class(rng, label, args.per_class, full_profile))

    df = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=args.seed).reset_index(drop=True)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"{len(df)} flows sinteticos ({args.per_class} por classe) -> {args.output}")
    print(df[" Label"].value_counts())


if __name__ == "__main__":
    main()
