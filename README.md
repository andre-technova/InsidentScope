# InsidentScope
Technova IncidentScope: structured incident evidence collection for Windows and Linux environments.

# IncidentScope

**Technova IncidentScope** is a cross-platform incident evidence collection toolkit for **Windows** and **Linux** environments.

It was designed to standardize evidence gathering for **unavailability analysis**, **operational investigation**, and **root cause analysis (RCA)**, generating both a **human-readable report** and a **structured JSON summary**.

---

## Overview

IncidentScope was created to solve a very common problem in real-world IT operations:

When an incident happens, teams often collect evidence in an ad-hoc way — a few commands here, some copied logs there, maybe a screenshot, and a lot of guesswork.

IncidentScope changes that approach by providing a **repeatable**, **structured**, and **evidence-driven** collection process.

Instead of relying on memory, urgency, or improvisation, IncidentScope helps teams collect:

- host identity
- time window context
- operating system context
- virtualization context
- logs and event evidence
- services and process clues
- network and port information
- memory, CPU and storage snapshots
- recent logons
- reboot / shutdown evidence
- incident timeline
- structured auxiliary artifacts

---

## Supported Platforms

### Linux
Designed for Linux distributions using **bash + systemd + journalctl**, including:

- Rocky Linux
- Oracle Linux
- Red Hat Enterprise Linux
- AlmaLinux
- Ubuntu
- Debian
- Proxmox VE
- other compatible Linux distributions

### Windows
Designed for **Windows PowerShell 5.1** and **PowerShell 7+**, including:

- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

---

## Main Goals

- Standardize incident evidence collection
- Reduce improvisation during outages
- Improve troubleshooting consistency
- Accelerate RCA preparation
- Generate outputs useful for:
  - human investigation
  - dashboards
  - automation
  - AI-assisted analysis

---

## Key Features

### Cross-platform approach
Linux and Windows versions were built to follow the same philosophy:
- structured evidence collection
- best-effort contextual enrichment
- human-readable report
- structured JSON summary
- auxiliary evidence files by category

### Interactive and non-interactive execution
IncidentScope can run:
- interactively, prompting the analyst
- non-interactively, using predefined parameters

### Time window flexibility
Supports:
- exact `since/until`
- relative windows (`--hours`)
- calculated windows (`--duration-min`)
- previous full month (`--mensal` / `--monthly`)

### Operational context
Collects context such as:
- hostname / FQDN / IPs
- OS and kernel information
- timezone and current time
- virtualization signals
- role-aware context (especially in Windows)

### Structured output
Generates:
- main report `.log`
- structured summary `.json`
- auxiliary files for host, network, storage, logs, ports, timeline, memory, services, etc.

---

## Output

By default, IncidentScope writes results to a directory such as:

### Linux
```bash
/tmp/analise-incidente-<CASEID|STAMP>
