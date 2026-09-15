"""Modulo complementar de verificacao de arquivos: varre uma pasta ou disco
em busca de indicios de ameacas -- hash conhecido, entropia alta (possivel
arquivo compactado/criptografado/empacotado) e padroes de extensao suspeitos.

Diferente dos modulos 1-5 (que analisam TRAFEGO DE REDE), este modulo
analisa ARQUIVOS em disco -- e um dominio de seguranca diferente, mais
parecido com um antivirus heuristico do que com um IDS.

IMPORTANTE: e um scanner heuristico, NAO substitui um antivirus com base de
assinaturas atualizada. Falsos positivos (arquivos legitimos compactados) e
falsos negativos (malware sem essas caracteristicas) sao esperados -- trate
os arquivos sinalizados como ponto de investigacao, nao como veredito.

Uso:
    python -m siadar.filescan.scan C:\\Users\\voce\\Downloads -o varredura.csv
    python -m siadar.filescan.scan D:\\ --hashes hashes_maliciosos.txt --max-files 5000
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
from collections import Counter

import pandas as pd

EXECUTABLE_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".dll"}
WATCHED_DIR_KEYWORDS = {"downloads", "temp", "tmp", "desktop"}
ENTROPY_SAMPLE_BYTES = 2 * 1024 * 1024  # amostra os primeiros 2MB -- suficiente pro sinal, rapido em arquivos grandes
HASH_CHUNK = 1024 * 1024


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_sample(path: str, size: int) -> float:
    read_size = min(size, ENTROPY_SAMPLE_BYTES)
    with open(path, "rb") as f:
        data = f.read(read_size)
    return _shannon_entropy(data)


def _has_double_extension(name: str) -> bool:
    """Detecta padroes tipo 'fatura.pdf.exe' -- extensao executavel escondida
    atras de uma extensao inofensiva, tecnica classica de engenharia social."""
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    return f".{parts[-1]}" in EXECUTABLE_EXT


def load_known_hashes(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


def scan_path(
    root: str,
    known_hashes: set[str] | None = None,
    entropy_threshold: float = 7.5,
    max_files: int | None = None,
) -> pd.DataFrame:
    known_hashes = known_hashes or set()
    rows: list[dict] = []
    scanned = 0

    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for name in filenames:
            if max_files is not None and scanned >= max_files:
                return pd.DataFrame(rows)

            full_path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full_path)
                sha = _sha256(full_path)
                entropy = _entropy_sample(full_path, size)
            except (PermissionError, OSError):
                continue
            scanned += 1

            reasons = []
            if sha in known_hashes:
                reasons.append("hash conhecido malicioso")
            if entropy >= entropy_threshold:
                reasons.append(f"entropia alta ({entropy:.2f}) -- possivel arquivo compactado/criptografado")
            if _has_double_extension(name):
                reasons.append("extensao dupla suspeita (ex.: nome.pdf.exe)")
            ext = os.path.splitext(name)[1].lower()
            dir_lower = dirpath.lower()
            if ext in EXECUTABLE_EXT and any(w in dir_lower for w in WATCHED_DIR_KEYWORDS):
                reasons.append(f"executavel ({ext}) em pasta tipicamente usada por downloads/temporarios")

            rows.append({
                "caminho": full_path,
                "tamanho_bytes": size,
                "sha256": sha,
                "entropia": round(entropy, 3),
                "extensao": ext,
                "suspeito": bool(reasons),
                "motivos": "; ".join(reasons),
            })
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Varre uma pasta/disco em busca de indicios de ameacas (heuristico)")
    parser.add_argument("path", help="Pasta ou disco a varrer (ex.: C:\\Users\\voce\\Downloads ou D:\\)")
    parser.add_argument("-o", "--output", default="varredura.csv")
    parser.add_argument("--hashes", help="Arquivo texto com hashes SHA-256 conhecidos maliciosos, um por linha")
    parser.add_argument("--entropy-threshold", type=float, default=7.5)
    parser.add_argument("--max-files", type=int, default=None, help="Limite de arquivos (util para testar antes de varrer um disco inteiro)")
    args = parser.parse_args()

    known_hashes = load_known_hashes(args.hashes) if args.hashes else set()

    print(f"Varrendo {args.path} ...")
    df = scan_path(args.path, known_hashes=known_hashes, entropy_threshold=args.entropy_threshold, max_files=args.max_files)
    df.to_csv(args.output, index=False)

    n_suspeitos = int(df["suspeito"].sum()) if len(df) else 0
    print(f"{len(df)} arquivos verificados, {n_suspeitos} sinalizados como suspeitos")
    print(f"Resultado salvo em {args.output}")
    if n_suspeitos:
        print("\nAtencao: isto e um scanner heuristico, nao um antivirus com base de")
        print("assinaturas atualizada. Trate os arquivos sinalizados como ponto de")
        print("investigacao, nao como veredito definitivo.")


if __name__ == "__main__":
    main()
