"""Testa o modulo de verificacao de arquivos: cada heuristica (hash
conhecido, entropia alta, extensao dupla, executavel em pasta de risco)
precisa sinalizar exatamente o arquivo sintetico feito para dispara-la, e
nao os arquivos normais ao lado."""

import hashlib
import os

from siadar.filescan.scan import scan_path, load_known_hashes


def test_scan_flags_each_heuristic_independently(tmp_path):
    # arquivo normal -- nao deveria disparar nada
    normal = tmp_path / "relatorio.txt"
    normal.write_text("conteudo de texto normal, nada suspeito aqui." * 5)

    # arquivo de alta entropia (bytes aleatorios -- parece compactado/criptografado)
    high_entropy = tmp_path / "pacote.bin"
    high_entropy.write_bytes(os.urandom(4096))

    # extensao dupla classica de engenharia social
    double_ext = tmp_path / "fatura.pdf.exe"
    double_ext.write_bytes(b"MZ" + b"\x00" * 100)

    # executavel dentro de uma pasta "Downloads"
    downloads_dir = tmp_path / "Downloads"
    downloads_dir.mkdir()
    exe_in_downloads = downloads_dir / "instalador.exe"
    exe_in_downloads.write_bytes(b"MZ" + b"\x00" * 100)

    # arquivo cujo hash sera marcado como malicioso conhecido
    known_bad = tmp_path / "documento.docx"
    known_bad.write_bytes(b"conteudo de um documento qualquer")
    known_bad_hash = hashlib.sha256(known_bad.read_bytes()).hexdigest()
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text(f"# lista de teste\n{known_bad_hash}\n")

    known_hashes = load_known_hashes(str(hashes_file))
    df = scan_path(str(tmp_path), known_hashes=known_hashes, entropy_threshold=7.5)
    df = df.set_index(df["caminho"].apply(os.path.basename))

    assert df.loc["relatorio.txt", "suspeito"] == False  # noqa: E712
    assert df.loc["pacote.bin", "suspeito"]
    assert "entropia alta" in df.loc["pacote.bin", "motivos"]
    assert df.loc["fatura.pdf.exe", "suspeito"]
    assert "extensao dupla" in df.loc["fatura.pdf.exe", "motivos"]
    assert df.loc["instalador.exe", "suspeito"]
    assert "pasta tipicamente usada" in df.loc["instalador.exe", "motivos"]
    assert df.loc["documento.docx", "suspeito"]
    assert "hash conhecido" in df.loc["documento.docx", "motivos"]


def test_max_files_limits_scan(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("x")
    df = scan_path(str(tmp_path), max_files=3)
    assert len(df) == 3
