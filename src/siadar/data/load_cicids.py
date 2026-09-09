"""Carrega os CSVs do dataset publico CICIDS2017 (CICFlowMeter output) e
normaliza as colunas para o schema canonico usado no projeto (siadar.features.schema).

Os CSVs originais (pasta "MachineLearningCVE") tem nomes de coluna com espacos
inconsistentes, ex: ' Flow Duration', 'Total Length of Fwd Packets'. Aqui a
gente normaliza tudo para snake_case e mapeia os apelidos conhecidos para o
nome canonico.

Uso:
    from siadar.data.load_cicids import load_cicids
    df = load_cicids("data/raw/MachineLearningCVE")
"""

from __future__ import annotations

import glob
import os
import re

import numpy as np
import pandas as pd

from siadar.features.schema import CORE_FLOW_FEATURES, LABEL_COLUMN

# nome normalizado (snake_case) -> nome canonico, so para os casos em que a
# normalizacao automatica nao bate com siadar.features.schema
_ALIASES = {
    "total_backward_packets": "total_bwd_packets",
    "total_length_of_fwd_packets": "total_length_fwd_packets",
    "total_length_of_bwd_packets": "total_length_bwd_packets",
    "class": LABEL_COLUMN,
}


def _normalize_column(col: str) -> str:
    col = col.strip().lower()
    col = col.replace("/", "_per_")
    col = re.sub(r"[^a-z0-9]+", "_", col)
    col = col.strip("_")
    return _ALIASES.get(col, col)


def _load_single_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [_normalize_column(c) for c in df.columns]
    return df


def load_cicids(source: str) -> pd.DataFrame:
    """source pode ser um CSV unico ou um diretorio com varios CSVs do CICIDS2017."""
    if os.path.isdir(source):
        paths = sorted(glob.glob(os.path.join(source, "*.csv")))
        if not paths:
            raise FileNotFoundError(f"Nenhum .csv encontrado em {source}")
    else:
        paths = [source]

    frames = [_load_single_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True)

    # features derivadas que o CICFlowMeter nao exporta diretamente
    if "ratio_fwd_bwd_packets" not in df.columns:
        df["ratio_fwd_bwd_packets"] = df["total_fwd_packets"] / (df["total_bwd_packets"] + 1)
    if "ratio_fwd_bwd_bytes" not in df.columns:
        df["ratio_fwd_bwd_bytes"] = df["total_length_fwd_packets"] / (df["total_length_bwd_packets"] + 1)

    missing = [c for c in CORE_FLOW_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(
            "Colunas esperadas ausentes apos normalizacao: "
            f"{missing}. Confira o mapeamento em _ALIASES."
        )
    if LABEL_COLUMN not in df.columns:
        raise ValueError("Coluna de label nao encontrada apos normalizacao (esperado 'label').")

    keep = CORE_FLOW_FEATURES + [LABEL_COLUMN]
    df = df[keep].copy()

    # normalizar rotulo: CICIDS2017 usa "BENIGN" para trafego normal
    df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(str).str.strip()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df.reset_index(drop=True)
