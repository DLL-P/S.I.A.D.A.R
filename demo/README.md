# Demo — ambiente simulado

Roda o pipeline inteiro do SIADAR (M1 + M2) de ponta a ponta **sem precisar
baixar o CICIDS2017 completo**: gera um dataset sintético para treinar e uma
captura `.pcap` sintética (tráfego normal + um portscan) para classificar.

O objetivo é ver o mecanismo funcionando de verdade — mesmo código, mesmos
comandos que rodariam com dados reais — não é um mock separado do sistema.

## Passo a passo

```bash
# 1. gera um dataset sintético no formato CICIDS2017 (3 classes: BENIGN, PortScan, DDoS)
python demo/make_demo_dataset.py -o demo/output/synthetic_cicids.csv -n 300

# 2. treina o classificador de verdade sobre esse dataset
python -m siadar.classification.train demo/output/synthetic_cicids.csv --model-out demo/output/models/rf_classifier.joblib

# 3. gera uma captura .pcap sintética: 5 conversas HTTP normais + um portscan de 40 portas
python demo/make_demo_pcap.py -o demo/output/demo_capture.pcap

# 4. extrai os flows dessa captura (Módulo 1 rodando sobre um pcap de verdade)
python -m siadar.capture.pcap_to_flows demo/output/demo_capture.pcap -o demo/output/flows.csv

# 5. classifica os flows extraídos com o modelo treinado no passo 2
python -m siadar.classification.predict demo/output/models/rf_classifier.joblib demo/output/flows.csv -o demo/output/predictions.csv
```

## O que esperar

O portscan simulado gera 40 flows de um pacote só (um `SYN` por porta, sem
resposta) e as 5 conversas HTTP geram flows bidirecionais com várias trocas de
pacote. Um modelo treinado **apenas nos dados tabulares sintéticos** do passo
2 deve classificar corretamente os 40 flows do pcap como `PortScan` e os 5
das conversas normais como `BENIGN` — prova de que o schema de features
(`siadar.features.schema`) realmente conecta as duas fontes de dados.

`demo/output/` é gerado localmente e não entra no repositório (ver
`.gitignore`) — rode os comandos acima para reproduzir.

## Por que os números são "bons demais"

As distribuições sintéticas em `make_demo_dataset.py` foram desenhadas para
serem bem separáveis (accuracy costuma sair em ~100%). Isso valida o
**mecanismo do pipeline**, não a performance do modelo em produção — para
números realistas de accuracy/F1, é necessário treinar com o CICIDS2017 real
(ver `README.md` da raiz do projeto, seção "Uso").
