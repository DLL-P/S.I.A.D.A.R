"""Pre-processamento para deteccao de anomalias: normalizacao das features
(StandardScaler) sem encoding de label -- o Isolation Forest e nao-supervisionado,
so precisa aprender a forma do trafego normal."""

from __future__ import annotations

import pandas as pd
from sklearn.preprocessing import StandardScaler

from siadar.features.schema import CORE_FLOW_FEATURES


def fit_scaler(df: pd.DataFrame):
    """Ajusta o scaler nos dados de treino (tipicamente so trafego BENIGN)."""
    X = df[CORE_FLOW_FEATURES].copy()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler


def transform(df: pd.DataFrame, scaler: StandardScaler):
    """Aplica um scaler ja treinado a novos flows, para avaliacao ou inferencia."""
    X = df[CORE_FLOW_FEATURES].copy()
    return scaler.transform(X)
