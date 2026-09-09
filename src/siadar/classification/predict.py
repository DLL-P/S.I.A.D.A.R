"""Aplica um modelo treinado (train.py) a novos flows, tipicamente vindos de
siadar.capture.pcap_to_flows.extract_flows, para classificar trafego ao vivo.

Uso:
    python -m siadar.classification.predict models/rf_classifier.joblib flows.csv
"""

from __future__ import annotations

import argparse

import joblib
import pandas as pd

from siadar.classification.preprocess import transform


def predict(model_path: str, flows_df: pd.DataFrame) -> pd.DataFrame:
    bundle = joblib.load(model_path)
    model, scaler, label_encoder = bundle["model"], bundle["scaler"], bundle["label_encoder"]

    X = transform(flows_df, scaler)
    y_pred = model.predict(X)
    labels = label_encoder.inverse_transform(y_pred)

    result = flows_df.copy()
    result["predicted_label"] = labels
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Classifica flows usando um modelo treinado")
    parser.add_argument("model", help="Caminho para o .joblib gerado por train.py")
    parser.add_argument("flows_csv", help="CSV de flows (saida de pcap_to_flows.py)")
    parser.add_argument("-o", "--output", default="predictions.csv")
    args = parser.parse_args()

    flows_df = pd.read_csv(args.flows_csv)
    result = predict(args.model, flows_df)
    result.to_csv(args.output, index=False)
    print(result["predicted_label"].value_counts())
    print(f"Resultado salvo em {args.output}")


if __name__ == "__main__":
    main()
