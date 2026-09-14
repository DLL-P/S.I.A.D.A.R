"""Modulo 3 (baseline): treina um Isolation Forest para deteccao de anomalias
de trafego -- abordagem nao-supervisionada do guia do projeto: aprende o
perfil de trafego NORMAL (BENIGN) e sinaliza desvios, sem nunca ver um
ataque durante o treino (simula o cenario real de producao, onde trafego
malicioso rotulado normalmente nao esta disponivel).

Uso:
    python -m siadar.anomaly.train data/raw/MachineLearningCVE \
        --model-out models/anomaly_model.joblib
"""

from __future__ import annotations

import argparse
import os

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

from siadar.anomaly.preprocess import fit_scaler, transform
from siadar.data.load_cicids import load_cicids
from siadar.features.schema import LABEL_COLUMN


def train(
    dataset_path: str,
    model_out: str,
    contamination: float = 0.05,
    test_size: float = 0.3,
    random_state: int = 42,
):
    print(f"Carregando dataset de {dataset_path} ...")
    df = load_cicids(dataset_path)
    is_benign = df[LABEL_COLUMN].str.upper() == "BENIGN"
    print(f"{len(df)} flows carregados ({is_benign.sum()} BENIGN, {(~is_benign).sum()} ataques)")

    if is_benign.sum() == 0:
        raise ValueError("Nenhum flow BENIGN encontrado -- o Isolation Forest precisa de trafego normal para treinar.")

    benign_df = df[is_benign].reset_index(drop=True)
    benign_train, benign_test = train_test_split(benign_df, test_size=test_size, random_state=random_state)
    attack_df = df[~is_benign].reset_index(drop=True)

    print(f"Treinando com {len(benign_train)} flows normais (BENIGN)...")
    X_train, scaler = fit_scaler(benign_train)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train)

    # avaliacao: BENIGN nunca visto no treino + todos os ataques -> so os
    # ataques deveriam ser sinalizados como anomalia
    eval_df = pd.concat([benign_test, attack_df], ignore_index=True)
    y_true = (~(eval_df[LABEL_COLUMN].str.upper() == "BENIGN")).astype(int)  # 1 = ataque
    X_eval = transform(eval_df, scaler)
    raw_pred = model.predict(X_eval)  # 1 = normal, -1 = anomalia
    y_pred = (raw_pred == -1).astype(int)
    scores = -model.decision_function(X_eval)  # maior = mais anomalo

    report = classification_report(y_true, y_pred, target_names=["normal", "anomalia"])
    print(report)

    auc = None
    if y_true.nunique() > 1:
        auc = roc_auc_score(y_true, scores)
        print(f"AUC-ROC: {auc:.4f}")

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler}, model_out)
    print(f"Modelo salvo em {model_out}")

    report_path = os.path.splitext(model_out)[0] + "_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
        if auc is not None:
            f.write(f"\nAUC-ROC: {auc:.4f}\n")

    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["normal", "anomalia"], yticklabels=["normal", "anomalia"], ax=ax)
    ax.set_xlabel("Predito")
    ax.set_ylabel("Real")
    fig.tight_layout()
    cm_path = os.path.splitext(model_out)[0] + "_confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    print(f"Matriz de confusao salva em {cm_path}")

    return model, scaler


def main() -> None:
    parser = argparse.ArgumentParser(description="Treina o detector de anomalias (Isolation Forest)")
    parser.add_argument("dataset", help="CSV ou pasta com os CSVs do CICIDS2017")
    parser.add_argument("--model-out", default="models/anomaly_model.joblib")
    parser.add_argument("--contamination", type=float, default=0.05,
                         help="Proporcao esperada de anomalias no trafego real (default 0.05)")
    parser.add_argument("--test-size", type=float, default=0.3)
    args = parser.parse_args()

    train(args.dataset, args.model_out, contamination=args.contamination, test_size=args.test_size)


if __name__ == "__main__":
    main()
