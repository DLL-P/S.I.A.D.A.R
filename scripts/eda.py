"""EDA rapida do CICIDS2017 ja normalizado: distribuicao de classes, nulos e
correlacao entre as features principais. Gera arquivos em outputs/eda/.

Uso:
    python scripts/eda.py data/raw/MachineLearningCVE
"""

from __future__ import annotations

import argparse
import os

import matplotlib.pyplot as plt
import seaborn as sns

from siadar.data.load_cicids import load_cicids


def run_eda(dataset_path: str, out_dir: str = "outputs/eda") -> None:
    os.makedirs(out_dir, exist_ok=True)
    df = load_cicids(dataset_path)

    print(df.describe())
    print("\nDistribuicao de classes:")
    print(df["label"].value_counts())

    fig, ax = plt.subplots(figsize=(8, 5))
    df["label"].value_counts().plot(kind="barh", ax=ax)
    ax.set_xlabel("Numero de flows")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "class_distribution.png"), dpi=150)

    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(df.drop(columns=["label"]).corr(), cmap="coolwarm", center=0, ax=ax)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "feature_correlation.png"), dpi=150)

    print(f"\nGraficos salvos em {out_dir}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EDA rapida do dataset CICIDS2017")
    parser.add_argument("dataset", help="CSV ou pasta com os CSVs do CICIDS2017")
    parser.add_argument("--out-dir", default="outputs/eda")
    args = parser.parse_args()
    run_eda(args.dataset, args.out_dir)
