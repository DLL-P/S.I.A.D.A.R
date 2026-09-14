"""Modulo 2 (baseline): treina um Random Forest para classificar trafego,
seguindo o pipeline do guia (split estratificado, RandomizedSearchCV opcional,
classification_report + matriz de confusao).

Uso:
    python -m siadar.classification.train data/raw/MachineLearningCVE \
        --model-out models/rf_classifier.joblib --search
"""

from __future__ import annotations

import argparse
import os
from collections import Counter

import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix
from sklearn.model_selection import RandomizedSearchCV, train_test_split

from siadar.classification.preprocess import fit_transform
from siadar.data.load_cicids import load_cicids

PARAM_DIST = {
    "n_estimators": [100, 200, 300],
    "max_depth": [10, 20, 30, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
}


def _balance_with_smote(X_train, y_train, target_size: int, random_state: int):
    """Superamostra (SMOTE) as classes com menos que target_size exemplos --
    nao mexe nas classes ja bem representadas (evita explodir o tempo de
    treino tentando igualar tudo a BENIGN, que tem milhoes de linhas)."""
    class_counts = Counter(y_train)
    sampling_strategy = {cls: target_size for cls, count in class_counts.items() if count < target_size}
    if not sampling_strategy:
        print("Nenhuma classe abaixo do alvo de balanceamento -- SMOTE nao aplicado.")
        return X_train, y_train

    min_count = min(class_counts[c] for c in sampling_strategy)
    k_neighbors = max(1, min(5, min_count - 1))
    print(f"Balanceando {len(sampling_strategy)} classe(s) raras para ~{target_size} "
          f"amostras cada (SMOTE, k_neighbors={k_neighbors})...")
    smoter = SMOTE(sampling_strategy=sampling_strategy, k_neighbors=k_neighbors, random_state=random_state)
    X_train, y_train = smoter.fit_resample(X_train, y_train)
    print(f"Treino balanceado: {len(y_train)} amostras (antes: {sum(class_counts.values())})")
    return X_train, y_train


def train(
    dataset_path: str,
    model_out: str,
    test_size: float = 0.2,
    do_search: bool = False,
    balance: bool = True,
    balance_target: int = 10_000,
    random_state: int = 42,
):
    print(f"Carregando dataset de {dataset_path} ...")
    df = load_cicids(dataset_path)
    print(f"{len(df)} flows carregados, {df['label'].nunique()} classes: "
          f"{sorted(df['label'].unique())}")

    X, y, label_encoder, scaler = fit_transform(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    if balance:
        X_train, y_train = _balance_with_smote(X_train, y_train, balance_target, random_state)

    if do_search:
        print("Rodando RandomizedSearchCV (pode demorar)...")
        base_rf = RandomForestClassifier(class_weight="balanced", n_jobs=-1, random_state=random_state)
        search = RandomizedSearchCV(
            base_rf,
            param_distributions=PARAM_DIST,
            n_iter=20,
            cv=5,
            scoring="f1_macro",
            n_jobs=-1,
            random_state=random_state,
        )
        search.fit(X_train, y_train)
        model = search.best_estimator_
        print(f"Melhores parametros: {search.best_params_}")
    else:
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=10,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        )
        model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
    print(report)

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
    joblib.dump(
        {"model": model, "scaler": scaler, "label_encoder": label_encoder},
        model_out,
    )
    print(f"Modelo salvo em {model_out}")

    report_path = os.path.splitext(model_out)[0] + "_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_, ax=ax)
    ax.set_xlabel("Predito")
    ax.set_ylabel("Real")
    fig.tight_layout()
    cm_path = os.path.splitext(model_out)[0] + "_confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    print(f"Matriz de confusao salva em {cm_path}")

    return model, label_encoder, scaler


def main() -> None:
    parser = argparse.ArgumentParser(description="Treina o classificador de trafego (Random Forest)")
    parser.add_argument("dataset", help="CSV ou pasta com os CSVs do CICIDS2017")
    parser.add_argument("--model-out", default="models/rf_classifier.joblib")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--search", action="store_true", help="Rodar RandomizedSearchCV")
    parser.add_argument("--no-smote", action="store_true",
                         help="Desativa o balanceamento por SMOTE das classes raras")
    parser.add_argument("--balance-target", type=int, default=10_000,
                         help="Classes com menos amostras que isso sao superamostradas ate esse valor (default 10000)")
    args = parser.parse_args()

    train(
        args.dataset, args.model_out, test_size=args.test_size, do_search=args.search,
        balance=not args.no_smote, balance_target=args.balance_target,
    )


if __name__ == "__main__":
    main()
