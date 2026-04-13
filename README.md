# Technova IncidentScope 2.3

Structured incident evidence collection for Windows and Linux environments.

---

# 🇧🇷 PT-BR

## O que é o IncidentScope?

**Technova IncidentScope** é uma ferramenta de coleta estruturada de evidências para investigação de incidentes em ambientes **Linux** e **Windows**.

Ele foi criado para padronizar a coleta técnica durante cenários de indisponibilidade, troubleshooting operacional e análise de causa raiz (**RCA**), gerando:

- **relatório principal legível por humanos** (`.log`)
- **resumo estruturado** (`.json`)
- **arquivos auxiliares por categoria**, úteis para investigação manual, automação, dashboards e análise assistida por IA

---

## Objetivo

Em muitos incidentes, a coleta de evidências acontece de forma improvisada: alguns comandos, prints, logs copiados às pressas e muita interpretação no meio da pressão.

O IncidentScope existe para transformar isso em um processo:

- padronizado
- repetível
- comparável
- orientado a evidências

---

## Principais recursos

- Coleta estruturada para **Windows** e **Linux**
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
- Eventos e logs
- Serviços, rede, portas, memória, storage e timeline
- Relatório principal `.log`
- Resumo estruturado `.json`
- Arquivos auxiliares por categoria

---

## Plataformas suportadas

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

## Filosofia do projeto

O IncidentScope não foi pensado como “um monte de comandos em sequência”.

Ele foi construído como uma camada de **evidência operacional**, organizada para entregar:

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

## Saídas geradas

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

## Linux e Windows: mesma filosofia, coleta adaptada

A versão Windows não é um projeto sem relação com a versão Linux.

A proposta é manter a mesma filosofia de coleta estruturada, adaptando a implementação ao ecossistema nativo de cada plataforma.

### Linux
Utiliza recursos como:
- `journalctl`
- `systemctl`
- `ss`
- `ip`
- `last`
- `df`
- `vmstat`
- `iostat`
- `sar`

### Windows
Utiliza recursos como:
- `Get-WinEvent`
- `Get-Service`
- `Get-NetTCPConnection`
- CIM / WMI
- Event Viewer
- contexto do PowerShell
- eventos de logon, energia e serviços

---

## Observações importantes

O IncidentScope trabalha em modelo **best-effort**.

Algumas informações dependem do que o sistema já registrou historicamente, como:

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

## Autor

**André Rodrigues**  
Technova  
Contato: **technova.sti@outlook.com**

---

## Licença

Defina aqui a licença mais adequada ao projeto, como por exemplo:

- MIT
- Apache-2.0
- GPL-3.0
- Proprietary / Internal Use

---

# 🇺🇸 ENG

## What is IncidentScope?

**Technova IncidentScope** is a structured incident evidence collection toolkit for **Linux** and **Windows** environments.

It was created to standardize technical evidence gathering during outage scenarios, operational troubleshooting, and root cause analysis (**RCA**), generating:

- a **human-readable main report** (`.log`)
- a **structured summary** (`.json`)
- **auxiliary evidence files by category**, useful for manual investigation, automation, dashboards, and AI-assisted analysis

---

## Purpose

In many incidents, evidence collection is done in an improvised way: a few commands, screenshots, copied logs, and too much interpretation under pressure.

IncidentScope exists to turn that into a process that is:

- standardized
- repeatable
- comparable
- evidence-driven

---

## Main features

- Structured collection for **Windows** and **Linux**
- **Interactive** and **non-interactive** mode
- Time window support by:
  - exact date/time
  - last N hours
  - duration from start
  - previous full month
- Environment profiles
- Collection levels
- Host context
- Virtualization context
- Events and logs
- Services, network, ports, memory, storage and timeline
- Main `.log` report
- Structured `.json` summary
- Auxiliary files by category

---

## Supported platforms

### Linux
Designed for distributions using **bash + systemd + journalctl**, such as:

- Rocky Linux
- Oracle Linux
- Red Hat Enterprise Linux
- AlmaLinux
- Ubuntu
- Debian
- Proxmox VE
- other compatible distributions

### Windows
Designed for:

- Windows PowerShell **5.1**
- PowerShell **7+**
- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

---

## Project philosophy

IncidentScope was not designed as “just a group of commands”.

It was built as an **operational evidence layer** to provide:

- host identity
- time context
- operating system context
- virtualization context
- relevant events and errors
- service clues
- network and port evidence
- memory, CPU and storage snapshots
- recent logons
- reboot / shutdown evidence
- incident timeline
- executive summary
- structured output for correlation

---

## Generated outputs

IncidentScope typically generates:

- `main-report_*.log`
- `structured-summary_*.json`
- host identity files
- time/context files
- virtualization files
- raw events
- filtered errors
- timeline
- services
- network
- DNS
- event statistics
- port checks
- listening services
- memory
- storage
- recent logons
- power event evidence
- recent changes
- collection status
- role context

---

## Linux and Windows: same philosophy, adapted collection

The Windows version is not an unrelated script.

The idea is to preserve the same structured evidence philosophy while adapting the implementation to each platform’s native ecosystem.

### Linux
Uses tools such as:
- `journalctl`
- `systemctl`
- `ss`
- `ip`
- `last`
- `df`
- `vmstat`
- `iostat`
- `sar`

### Windows
Uses tools such as:
- `Get-WinEvent`
- `Get-Service`
- `Get-NetTCPConnection`
- CIM / WMI
- Event Viewer
- PowerShell execution context
- logon, power and service events

---

## Important notes

IncidentScope works in **best-effort** mode.

Some information depends on what the system has already recorded historically, such as:

- reboot reason
- reboot actor
- historical storage latency
- memory pressure over time
- detailed logon history
- previous administrative changes

Because of that, evidence quality may vary depending on:

- enabled auditing
- log retention
- available permissions
- tools already installed on the host

---

## Author

**André Rodrigues**  
Technova  
Contact: **technova.sti@outlook.com**

---

## License

Define the license that best fits the project, such as:

- MIT
- Apache-2.0
- GPL-3.0
- Proprietary / Internal Use

---

# 🇪🇸 ESP

## ¿Qué es IncidentScope?

**Technova IncidentScope** es una herramienta de recolección estructurada de evidencias para investigación de incidentes en entornos **Linux** y **Windows**.

Fue creada para estandarizar la recolección técnica durante escenarios de indisponibilidad, troubleshooting operativo y análisis de causa raíz (**RCA**), generando:

- un **informe principal legible por humanos** (`.log`)
- un **resumen estructurado** (`.json`)
- **archivos auxiliares por categoría**, útiles para investigación manual, automatización, dashboards y análisis asistido por IA

---

## Objetivo

En muchos incidentes, la recolección de evidencias ocurre de forma improvisada: algunos comandos, capturas, logs copiados con prisa y demasiada interpretación bajo presión.

IncidentScope existe para transformar eso en un proceso:

- estandarizado
- repetible
- comparable
- orientado a evidencias

---

## Recursos principales

- Recolección estructurada para **Windows** y **Linux**
- Modo **interactivo** y **no interactivo**
- Ventana temporal por:
  - fecha/hora exacta
  - últimas N horas
  - duración desde el inicio
  - mes anterior completo
- Perfiles de entorno
- Niveles de recolección
- Contexto del host
- Contexto de virtualización
- Eventos y logs
- Servicios, red, puertos, memoria, storage y timeline
- Informe principal `.log`
- Resumen estructurado `.json`
- Archivos auxiliares por categoría

---

## Plataformas soportadas

### Linux
Diseñado para distribuciones con **bash + systemd + journalctl**, como:

- Rocky Linux
- Oracle Linux
- Red Hat Enterprise Linux
- AlmaLinux
- Ubuntu
- Debian
- Proxmox VE
- otras distribuciones compatibles

### Windows
Diseñado para:

- Windows PowerShell **5.1**
- PowerShell **7+**
- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

---

## Filosofía del proyecto

IncidentScope no fue pensado como “solo una secuencia de comandos”.

Fue construido como una capa de **evidencia operativa** para entregar:

- identidad del host
- contexto temporal
- contexto del sistema operativo
- contexto de virtualización
- eventos y errores relevantes
- pistas de servicios
- evidencias de red y puertos
- snapshots de memoria, CPU y storage
- logons recientes
- reboot / shutdown
- timeline del incidente
- resumen ejecutivo
- salida estructurada para correlación

---

## Salidas generadas

IncidentScope normalmente genera:

- `main-report_*.log`
- `structured-summary_*.json`
- archivos de identidad del host
- contexto de tiempo
- virtualización
- eventos brutos
- errores filtrados
- timeline
- servicios
- red
- DNS
- estadísticas de eventos
- validación de puertos
- servicios en escucha
- memoria
- storage
- logons recientes
- evidencias de energía
- cambios recientes
- estado de la recolección
- contexto de rol

---

## Linux y Windows: misma filosofía, recolección adaptada

La versión Windows no es un script sin relación con Linux.

La propuesta es mantener la misma filosofía de evidencia estructurada, adaptando la implementación al ecosistema nativo de cada plataforma.

### Linux
Usa herramientas como:
- `journalctl`
- `systemctl`
- `ss`
- `ip`
- `last`
- `df`
- `vmstat`
- `iostat`
- `sar`

### Windows
Usa herramientas como:
- `Get-WinEvent`
- `Get-Service`
- `Get-NetTCPConnection`
- CIM / WMI
- Event Viewer
- contexto de ejecución de PowerShell
- eventos de logon, energía y servicios

---

## Observaciones importantes

IncidentScope trabaja en modo **best-effort**.

Algunas informaciones dependen de lo que el sistema ya registró históricamente, como:

- motivo del reboot
- responsable del reboot
- latencia histórica de storage
- presión de memoria a lo largo del tiempo
- historial detallado de logons
- cambios administrativos previos

Por eso, la calidad de la evidencia puede variar según:

- auditoría habilitada
- retención de logs
- permisos disponibles
- herramientas ya instaladas en el host

---

## Autor

**André Rodrigues**  
Technova  
Contacto: **technova.sti@outlook.com**

---

## Licencia

Defina aquí la licencia más adecuada para el proyecto, por ejemplo:

- MIT
- Apache-2.0
- GPL-3.0
- Proprietary / Internal Use
