"""Aplica um detector de anomalias treinado (train.py) a novos flows,
tipicamente vindos de siadar.capture.pcap_to_flows.extract_flows, para
sinalizar trafego que foge do padrao aprendido como normal.

Uso:
    python -m siadar.anomaly.predict models/anomaly_model.joblib flows.csv
"""

from __future__ import annotations

import argparse

import joblib
import pandas as pd

from siadar.anomaly.preprocess import transform


def predict(model_path: str, flows_df: pd.DataFrame) -> pd.DataFrame:
    bundle = joblib.load(model_path)
    model, scaler = bundle["model"], bundle["scaler"]

    X = transform(flows_df, scaler)
    raw_pred = model.predict(X)  # 1 = normal, -1 = anomalia
    scores = -model.decision_function(X)  # maior = mais anomalo

    result = flows_df.copy()
    result["anomaly_score"] = scores
    result["is_anomaly"] = raw_pred == -1
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Sinaliza flows anomalos usando um modelo treinado")
    parser.add_argument("model", help="Caminho para o .joblib gerado por train.py")
    parser.add_argument("flows_csv", help="CSV de flows (saida de pcap_to_flows.py)")
    parser.add_argument("-o", "--output", default="anomalies.csv")
    args = parser.parse_args()

    flows_df = pd.read_csv(args.flows_csv)
    result = predict(args.model, flows_df)
    result = result.sort_values("anomaly_score", ascending=False)
    n_anom = int(result["is_anomaly"].sum())
    print(f"{n_anom} de {len(result)} flows sinalizados como anomalos")
    result.to_csv(args.output, index=False)
    print(f"Resultado salvo em {args.output}")


if __name__ == "__main__":
    main()
