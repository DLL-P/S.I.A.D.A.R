"""Pre-processamento comum ao treino e a inferencia: encoding do label e
normalizacao das features (StandardScaler), conforme o pipeline descrito no
guia do projeto."""

from __future__ import annotations

import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

from siadar.features.schema import CORE_FLOW_FEATURES, LABEL_COLUMN


def split_features_label(df: pd.DataFrame):
    X = df[CORE_FLOW_FEATURES].copy()
    y = df[LABEL_COLUMN].copy()
    return X, y


def fit_transform(df: pd.DataFrame):
    """Ajusta encoder/scaler nos dados de treino. Retorna X escalado, y codificado
    e os proprios encoder/scaler (para salvar e reutilizar na inferencia)."""
    X, y = split_features_label(df)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y_encoded, label_encoder, scaler


def transform(df: pd.DataFrame, scaler: StandardScaler):
    """Aplica um scaler ja treinado a novos flows (sem label), para inferencia."""
    X = df[CORE_FLOW_FEATURES].copy()
    return scaler.transform(X)
