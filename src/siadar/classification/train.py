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

import joblib
import matplotlib.pyplot as plt
import seaborn as sns
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


def train(
    dataset_path: str,
    model_out: str,
    test_size: float = 0.2,
    do_search: bool = False,
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
    args = parser.parse_args()

    train(args.dataset, args.model_out, test_size=args.test_size, do_search=args.search)


if __name__ == "__main__":
    main()
