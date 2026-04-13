# Technova IncidentScope 2.3

---

# 🇧🇷 README (PT-BR)

## Visão Geral

**Technova IncidentScope** é uma ferramenta de coleta estruturada de evidências para investigação de incidentes em ambientes **Linux** e **Windows**.

O projeto foi criado para padronizar a coleta de informações técnicas durante cenários de indisponibilidade, degradação de serviço, troubleshooting operacional e análise de causa raiz (**RCA**), gerando:

- um **relatório principal legível por humanos** (`.log`)
- um **resumo estruturado em JSON** (`.json`)
- **arquivos auxiliares por categoria**, para facilitar análise manual, automação, dashboards e uso com IA

---

## Objetivo

O IncidentScope nasceu para resolver um problema real de operação:

Em muitos incidentes, a coleta de evidências acontece de forma improvisada — comandos soltos, prints, logs copiados às pressas e muita interpretação no meio da pressão.

A proposta do IncidentScope é transformar isso em um processo:

- **padronizado**
- **repetível**
- **comparável**
- **orientado a evidências**

---

## Principais Recursos

- Coleta estruturada para **Windows e Linux**
- Modo **interativo** e **não interativo**
- Janela temporal por:
  - data/hora exata
  - últimas N horas
  - duração a partir do início
  - mês anterior completo
- Perfis de ambiente
- Níveis de coleta
- Contexto do host
- Contexto de virtualização
- Coleta de eventos/logs
- Serviços, rede, portas, memória, storage e timeline
- Relatório principal `.log`
- Resumo estruturado `.json`
- Arquivos auxiliares por categoria

---

## Plataformas Suportadas

### Linux
Projetado para distribuições com **bash + systemd + journalctl**, como:

- Rocky Linux
- Oracle Linux
- Red Hat Enterprise Linux
- AlmaLinux
- Ubuntu
- Debian
- Proxmox VE
- outras distribuições compatíveis

### Windows
Projetado para:

- Windows PowerShell **5.1**
- PowerShell **7+**
- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

---

## Filosofia do Projeto

O IncidentScope não foi pensado como “um monte de comandos em sequência”.

Ele foi construído como uma camada de **evidência operacional**.

Isso significa que a ferramenta busca entregar, de forma organizada:

- identidade do host
- contexto temporal
- contexto do sistema operacional
- contexto de virtualização
- eventos e erros relevantes
- pistas de serviços
- evidências de rede e portas
- snapshots de memória, CPU e storage
- logons recentes
- reboot / shutdown
- timeline do incidente
- resumo executivo
- saída estruturada para correlação

---

## Saídas Geradas

Normalmente, o IncidentScope gera:

- `relatorio-principal_*.log`
- `resumo-estruturado_*.json`
- `host_identity_*.log`
- `tempo_*.log`
- `virtualizacao_*.log`
- `events_raw_*.log`
- `erros_filtrados_*.log`
- `timeline_*.log`
- `services_*.log`
- `network_*.log`
- `dns_*.log`
- `event_stats_*.log`
- `portas_*.log`
- `servicos_escuta_*.log`
- `memoria_*.log`
- `storage_*.log`
- `ultimos_logons_*.log`
- `ultimo_evento_energia_*.log`
- `mudancas_*.log`
- `collection_status_*.log`
- `role_context_*.log`

---

## Casos de Uso

- investigação de indisponibilidade
- troubleshooting de serviço
- análise de reboot inesperado
- validação de portas e conectividade
- análise operacional em Windows/Linux
- preparação de material para RCA
- apoio a automação e dashboards
- enriquecimento de análise com IA

---

## Linux e Windows: mesma filosofia, coleta adaptada

A versão Windows não é um script “paralelo” sem relação com o Linux.

A ideia do projeto é manter a mesma filosofia em ambos os mundos:

### Linux
Usa recursos nativos como:
- `journalctl`
- `systemctl`
- `ss`
- `ip`
- `last`
- `df`
- `vmstat`
- `iostat`
- `sar` (quando disponível)

### Windows
Usa recursos nativos como:
- `Get-WinEvent`
- `Get-Service`
- `Get-NetTCPConnection`
- CIM / WMI
- Event Viewer
- contexto de PowerShell
- eventos de logon, energia e serviço

---

## Observações Importantes

O IncidentScope trabalha em modelo **best-effort**.

Algumas informações dependem do que o sistema já registrou historicamente, como por exemplo:

- motivo real de reboot
- responsável por reboot
- latência histórica de storage
- pressão de memória ao longo do tempo
- logons detalhados
- mudanças administrativas anteriores

Por isso, a qualidade da evidência pode variar conforme:
- auditoria habilitada
- retenção de logs
- permissões disponíveis
- ferramentas já instaladas no host

---

## Estrutura Sugerida do Repositório

```text
IncidentScope/
├── linux/
│   └── incidentscope-2.3.12-unix-based.sh
├── windows/
│   └── incidentscope-2.3.12-windows-based.ps1
├── docs/
│   ├── homologacao/
│   ├── exemplos/
│   └── releases/
├── images/
└── README.md
