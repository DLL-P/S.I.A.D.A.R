# Demo — ambiente simulado

Roda o pipeline do SIADAR (M1 + M2 + M3) de ponta a ponta **sem precisar
baixar o CICIDS2017 completo**: gera tráfego sintético com rótulo conhecido,
extrai os flows com o código real do Módulo 1, treina os modelos e classifica
uma captura separada.

O objetivo é ver o mecanismo funcionando de verdade — mesmo código, mesmos
comandos que rodariam com dados reais — não é um mock separado do sistema.

## Como o dataset de treino é gerado

`make_demo_dataset.py` **não inventa números de feature à mão**. Em vez
disso, ele gera pacotes sintéticos com rótulo conhecido (tráfego normal com
handshake TCP completo, um portscan, várias rajadas tipo DDoS), escreve um
`.pcap` temporário e extrai os flows com `siadar.capture.pcap_to_flows.py` —
o mesmo código que roda sobre uma captura real. Isso garante que a
distribuição de treino bate exatamente com o que uma captura real produz.

*(A primeira versão deste gerador usava distribuições estatísticas
inventadas à mão; descobrimos, rodando o Módulo 3 de ponta a ponta, que a
escala não batia com o extrator real — tráfego normal de verdade era
sinalizado como anômalo só por causa disso. Gerar o treino a partir de pcap
de verdade elimina esse descasamento pela raiz.)*

## Passo a passo

```bash
# 1. gera o dataset de treino a partir de trafego sintetico real (normal, portscan, DDoS)
python demo/make_demo_dataset.py -o demo/output/synthetic_cicids.csv

# 2. treina o classificador de trafego (Modulo 2)
python -m siadar.classification.train demo/output/synthetic_cicids.csv --model-out demo/output/models/rf_classifier.joblib

# 3. treina o detector de anomalias (Modulo 3) -- aprende so com os flows BENIGN
python -m siadar.anomaly.train demo/output/synthetic_cicids.csv --model-out demo/output/models/anomaly_model.joblib

# 4. gera uma captura .pcap separada (nao usada no treino): 5 conversas HTTPS normais + um portscan de 40 portas
python demo/make_demo_pcap.py -o demo/output/demo_capture.pcap

# 5. extrai os flows dessa captura (Modulo 1 rodando sobre um pcap de verdade)
python -m siadar.capture.pcap_to_flows demo/output/demo_capture.pcap -o demo/output/flows.csv

# 6. classifica os flows extraidos
python -m siadar.classification.predict demo/output/models/rf_classifier.joblib demo/output/flows.csv -o demo/output/predictions.csv

# 7. sinaliza flows anomalos
python -m siadar.anomaly.predict demo/output/models/anomaly_model.joblib demo/output/flows.csv -o demo/output/anomalies.csv
```

## O que esperar

O portscan simulado gera 40 flows de um pacote só (um `SYN` por porta, sem
resposta) e as 5 conversas HTTPS geram flows bidirecionais com handshake e
várias trocas de pacote. Com os modelos treinados no passo 2 e 3:

- **Classificação (passo 6):** os 40 flows do portscan → `PortScan`, os 5 das
  conversas normais → `BENIGN`.
- **Anomalia (passo 7):** os 40 flows do portscan → sinalizados como
  anômalos (o detector nunca viu ataque no treino); os 5 flows normais →
  **não** sinalizados, mesmo sendo de uma captura diferente da usada no
  treino.

`demo/output/` é gerado localmente e não entra no repositório (ver
`.gitignore`) — rode os comandos acima para reproduzir.

## Por que os números são "bons demais"

Os cenários sintéticos em `make_demo_dataset.py` foram desenhados para
serem bem distinguíveis (accuracy/recall costumam sair perto de 100%). Isso
valida o **mecanismo do pipeline**, não a performance do modelo em produção
— para números realistas, é necessário treinar com o CICIDS2017 real (ver
`README.md` da raiz do projeto, seção "Uso").
