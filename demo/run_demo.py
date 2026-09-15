"""Executavel de demonstracao do SIADAR: roda o pipeline completo (M1 + M2 + M3)
com trafego sintetico e mostra o resultado na tela -- pensado para rodar com um
duplo-clique (via a versao empacotada em .exe), sem precisar abrir terminal ou
instalar Python.

Roda a mesma logica de demo/make_demo_dataset.py e demo/make_demo_pcap.py, so
que chamando as funcoes diretamente (mais rapido que subir subprocessos) e
imprimindo o progresso passo a passo.

Uso (com Python):
    python demo/run_demo.py
"""

from __future__ import annotations

import os
import sys
import time
import traceback

# garante que "src/" e a propria pasta demo/ estao no path, tanto rodando
# como script quanto empacotado pelo PyInstaller
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, os.path.join(_ROOT, "src")):
    if p not in sys.path:
        sys.path.insert(0, p)

# quando empacotado (--onefile), __file__ aponta para a pasta temporaria de
# extracao (_MEIxxxxx), que e apagada ao fechar o programa -- os resultados
# tem que ir para um lugar que sobrevive ao processo, ao lado do proprio .exe
if getattr(sys, "frozen", False):
    OUT_DIR = os.path.join(os.path.dirname(sys.executable), "SIADAR-Demo-resultados")
else:
    OUT_DIR = os.path.join(_HERE, "output", "app")


def _step(n, total, text):
    print(f"\n[{n}/{total}] {text}")


def _ok(text):
    print(f"      -> {text}")


def _open_image(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')
    except Exception:
        pass


def main() -> int:
    print("=" * 56)
    print("   SIADAR - Demonstracao do pipeline (dados sinteticos)")
    print("=" * 56)
    print("\nEsta demonstracao gera trafego de rede sintetico, treina os")
    print("modelos e classifica uma captura -- os mesmos modulos que rodam")
    print("com dados reais, so que sem precisar baixar nenhum dataset.\n")

    os.makedirs(OUT_DIR, exist_ok=True)
    total = 6

    try:
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.model_selection import train_test_split

        from make_demo_dataset import build_labeled_dataset, to_cicids_csv_format
        from make_demo_pcap import build_normal_traffic, build_portscan

        from siadar.capture.pcap_to_flows import extract_flows
        from siadar.classification.preprocess import fit_transform as clf_fit_transform, transform as clf_transform
        from siadar.anomaly.preprocess import fit_scaler, transform as anom_transform
        from siadar.data.load_cicids import load_cicids
        from siadar.features.schema import LABEL_COLUMN

        # 1. dataset de treino a partir de trafego sintetico real -----------
        _step(1, total, "Gerando trafego sintetico rotulado (normal, portscan, DDoS)...")
        train_flows = build_labeled_dataset(seed=42, tmp_pcap=os.path.join(OUT_DIR, "_train.pcap"))
        csv_path = os.path.join(OUT_DIR, "synthetic_cicids.csv")
        to_cicids_csv_format(train_flows).to_csv(csv_path, index=False)
        counts = train_flows[LABEL_COLUMN].value_counts().to_dict()
        _ok(f"{len(train_flows)} flows extraidos: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

        # 2. treino do classificador (Modulo 2) ------------------------------
        _step(2, total, "Treinando o classificador de trafego (Modulo 2, Random Forest)...")
        df = load_cicids(csv_path)
        X, y, label_encoder, scaler = clf_fit_transform(df)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        clf = RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        acc = clf.score(X_test, y_test)
        _ok(f"accuracy no conjunto de teste: {acc:.0%}")

        # 3. treino do detector de anomalias (Modulo 3) ----------------------
        _step(3, total, "Treinando o detector de anomalias (Modulo 3, Isolation Forest)...")
        is_benign = df[LABEL_COLUMN] == "BENIGN"
        X_benign, anom_scaler = fit_scaler(df[is_benign])
        anom_model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1)
        anom_model.fit(X_benign)
        _ok(f"treinado com {is_benign.sum()} flows normais (nunca viu um ataque)")

        # 4. captura sintetica separada (nao usada no treino) -----------------
        _step(4, total, "Gerando uma captura de rede separada (5 conversas normais + 1 portscan)...")
        base_time = 1_700_100_000.0
        normal_packets, t = build_normal_traffic(base_time, n_flows=5, seed=7)
        scan_packets, _ = build_portscan(t + 1.0, n_ports=40)
        pcap_path = os.path.join(OUT_DIR, "demo_capture.pcap")
        from scapy.all import wrpcap
        wrpcap(pcap_path, normal_packets + scan_packets)
        _ok(f"{len(normal_packets) + len(scan_packets)} pacotes gerados -> {os.path.basename(pcap_path)}")

        # 5. extracao dos flows (Modulo 1) ------------------------------------
        _step(5, total, "Extraindo flows da captura (Modulo 1)...")
        flows_df = extract_flows(pcap_path)
        _ok(f"{len(flows_df)} flows extraidos")

        # 6. classificacao + deteccao de anomalias ----------------------------
        _step(6, total, "Classificando os flows e verificando anomalias...")
        preds = label_encoder.inverse_transform(clf.predict(clf_transform(flows_df, scaler)))
        anom_pred = anom_model.predict(anom_transform(flows_df, anom_scaler))
        flows_df = flows_df.assign(predicted_label=preds, is_anomaly=(anom_pred == -1))

        n_scan = int((flows_df["total_fwd_packets"] == 1).sum())
        n_scan_ok = int((flows_df.loc[flows_df["total_fwd_packets"] == 1, "predicted_label"] == "PortScan").sum())
        n_normal = int((flows_df["total_bwd_packets"] > 0).sum())
        n_anom_scan = int(flows_df.loc[flows_df["total_fwd_packets"] == 1, "is_anomaly"].sum())
        n_anom_normal = int(flows_df.loc[flows_df["total_bwd_packets"] > 0, "is_anomaly"].sum())

        _ok(f"classificacao: {n_scan_ok}/{n_scan} flows do portscan identificados como PortScan")
        _ok(f"anomalia: {n_anom_scan}/{n_scan} flows do portscan sinalizados | "
            f"{n_anom_normal}/{n_normal} falsos positivos no trafego normal")

        pred_path = os.path.join(OUT_DIR, "predictions.csv")
        flows_df.to_csv(pred_path, index=False)

        # matrizes de confusao para exibir --------------------------------------
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns
        from sklearn.metrics import confusion_matrix

        cm = confusion_matrix(y_test, clf.predict(X_test))
        fig, ax = plt.subplots(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_, ax=ax)
        ax.set_xlabel("Predito"); ax.set_ylabel("Real"); ax.set_title("Modulo 2 - Triagem de trafego")
        fig.tight_layout()
        cm_path = os.path.join(OUT_DIR, "resultado_classificacao.png")
        fig.savefig(cm_path, dpi=150)
        plt.close(fig)

        print("\n" + "=" * 56)
        print("   Pipeline rodou ponta a ponta com sucesso")
        print("=" * 56)
        print(f"\nArquivos gerados em: {OUT_DIR}")
        print("Abrindo o grafico de resultado...")
        _open_image(cm_path)

    except Exception:
        print("\n[ERRO] A demonstracao falhou:\n")
        traceback.print_exc()
        input("\nPressione ENTER para sair...")
        return 1

    input("\nPressione ENTER para sair...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
