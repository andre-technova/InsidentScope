#!/usr/bin/env bash
# --- Versioning ---
VERSION="2.3.12-unix-based"
BUILD_DATE="$(date +%Y-%m-%d)"

# analise_incidente_indisponibilidade.sh
#
# Objetivo:
# Coletar evidências de indisponibilidade/incidente em Linux de forma prática, organizada e reutilizável.
#
# O que esta versão faz:
# - Janela por data/hora, últimas N horas ou mês anterior completo
# - Modo interativo e não interativo
# - Perfis: auto, generic, virt-host
# - Níveis de coleta: leve, padrao, detalhada
# - Contexto do host (hostname, FQDN, IPs, OS, kernel, timezone, execução)
# - Contexto de virtualização (guest, físico, host de virtualização, stack detectada)
# - Registro do analista responsável pela execução
# - Logs via journalctl com filtros por unit/regex
# - Memória, swap, disco, inodes, rede, systemd, login, reboot e timeline do incidente
# - Saída humana (.log) + resumo estruturado (.json, best-effort)
#
# Arquivos gerados por padrão em /tmp/analise-incidente-<CASEID|STAMP>
# - Relatório principal .log
# - Resumo estruturado .json
# - Arquivos auxiliares por categoria (tempo, memória, storage, rede, timeline etc.)
#
# Sistemas suportados do jeito que está:
# - Linux com bash + systemd + journalctl
# - RHEL / Rocky / Oracle / Alma
# - Ubuntu / Debian
# - Proxmox VE
# - Outros Linux compatíveis com as ferramentas utilizadas
#
# Limitações importantes:
# - Histórico de consumo “ao longo do tempo” depende de o sistema já ter métricas registradas (sar, iostat, pcp, etc.)
# - Motivo e responsável por reboot são best-effort
# - Latência de storage e iowait históricos dependem de ferramentas já ativas no host
#
# Troubleshooting CRLF:
# /usr/bin/env: ‘bash\r’: No such file or directory
# Corrija com:
#   sed -i 's/\r$//' /tmp/analise_incidente_indisponibilidade_linux.sh
#
# Escrito por André Rodrigues - technova.sti@outlook.com

set -Eeuo pipefail

say()  { printf "%s\n" "$*"; }
err()  { printf "\033[31m[ERRO]\033[0m %s\n" "$*" >&2; }
info() { printf "\033[36m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[33m[AVISO]\033[0m %s\n" "$*"; }


SYS_LANG=$(echo "${LANG:-en}" | cut -d_ -f1)
case "$SYS_LANG" in
  pt|es|en) ;;
  *) SYS_LANG="en" ;;
esac

print_startup_banner() {
  local subtitle_line1 subtitle_line2 version_label

  case "$SYS_LANG" in
    pt)
      subtitle_line1="      Coleta estruturada de evidências para indisponibilidade"
      subtitle_line2="         e investigação operacional em ambientes Linux/Unix"
      version_label="Versão"
      ;;
    es)
      subtitle_line1="      Recolección estructurada de evidencias para indisponibilidad"
      subtitle_line2="         e investigación operativa en entornos Linux/Unix"
      version_label="Versión"
      ;;
    *)
      subtitle_line1="      Structured evidence collection for unavailability"
      subtitle_line2="         and operational investigation in Linux/Unix environments"
      version_label="Version"
      ;;
  esac

  [[ -t 1 ]] && clear || true

  cat <<'EOF2'
████████╗███████╗ ██████╗██╗  ██╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
╚══██╔══╝██╔════╝██╔════╝██║  ██║████╗  ██║██╔═══██╗██║   ██║██╔══██╗
   ██║   █████╗  ██║     ███████║██╔██╗ ██║██║   ██║██║   ██║███████║
   ██║   ██╔══╝  ██║     ██╔══██║██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
   ██║   ███████╗╚██████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
EOF2
  echo
  echo "                          IncidentScope"
  echo " ─────────────────────────────────────────────────────────────────────"
  echo "$subtitle_line1"
  echo "$subtitle_line2"
  echo " ─────────────────────────────────────────────────────────────────────"
  printf '                           %s %s

' "$version_label" "$VERSION"
}

print_startup_disclaimer() {
  case "$SYS_LANG" in
    pt)
      cat <<EOF2
Esta é a versão ${VERSION} do Technova IncidentScope, desenvolvida por André Rodrigues
para coleta estruturada de evidências de indisponibilidade, investigação operacional
e apoio à análise técnica de incidentes em ambientes Linux/Unix.

Esta versão foi pensada para uso em distribuições com systemd/journalctl, como
Rocky Linux, Oracle Linux, Red Hat Enterprise Linux, Ubuntu, Debian e Proxmox VE.

O script pode coletar contexto do host, logs, memória, storage, rede, services,
portas, timeline do incidente, contexto de virtualização e arquivos auxiliares
para facilitar a análise e a correlação de evidências.

Este script deve ser executado como root ou com sudo.

Para ajuda resumida, use --help. Para documentação detalhada, use --manual.
Se nenhuma janela de tempo for informada, o script usará automaticamente as últimas 24 horas.
Você também pode definir a janela antes da execução com --since/--until, --hours,
--duration-min ou --mensal.

Em caso de dúvidas, sugestões de melhoria ou necessidade de suporte,
entre em contato pelo e-mail: technova.sti@outlook.com

Se o Technova IncidentScope agregou valor ao seu dia a dia,
considere contribuir com qualquer valor via PIX: technova.sti@outlook.com :)
EOF2
      if [[ "$NON_INTERACTIVE" != "1" ]]; then
        echo
        echo "Pressione ENTER para continuar ou Ctrl+C para cancelar."
        read -r
      fi
      ;;
    es)
      cat <<EOF2
Esta es la versión ${VERSION} de Technova IncidentScope, desarrollada por André Rodrigues
para la recolección estructurada de evidencias de indisponibilidad, investigación operativa
y apoyo al análisis técnico de incidentes en entornos Linux/Unix.

Esta versión fue pensada para distribuciones con systemd/journalctl, como
Rocky Linux, Oracle Linux, Red Hat Enterprise Linux, Ubuntu, Debian y Proxmox VE.

El script puede recopilar contexto del host, logs, memoria, storage, red, services,
puertos, timeline del incidente, contexto de virtualización y archivos auxiliares
para facilitar el análisis y la correlación de evidencias.

En caso de dudas, sugerencias de mejora o necesidad de soporte,
contacte por correo electrónico: technova.sti@outlook.com

Si Technova IncidentScope aportó valor a su rutina,
considere contribuir con cualquier monto vía PIX: technova.sti@outlook.com :)
EOF2
      if [[ "$NON_INTERACTIVE" != "1" ]]; then
        echo
        echo "Presione ENTER para continuar o Ctrl+C para cancelar."
        read -r
      fi
      ;;
    *)
      cat <<EOF2
This is version ${VERSION} of Technova IncidentScope, developed by André Rodrigues
for structured evidence collection for unavailability scenarios, operational investigation
and technical incident analysis support in Linux/Unix environments.

This version was designed for distributions with systemd/journalctl such as
Rocky Linux, Oracle Linux, Red Hat Enterprise Linux, Ubuntu, Debian and Proxmox VE.

The script can collect host context, logs, memory, storage, network, services,
ports, incident timeline, virtualization context and auxiliary files
to support evidence correlation and technical analysis.

For questions, improvement suggestions or support needs,
please contact: technova.sti@outlook.com

If Technova IncidentScope added value to your daily work,
please consider contributing any amount via PIX: technova.sti@outlook.com :)
EOF2
      if [[ "$NON_INTERACTIVE" != "1" ]]; then
        echo
        echo "Press ENTER to continue or Ctrl+C to cancel."
        read -r
      fi
      ;;
  esac

  say ""
}

print_closing_message() {
  case "$SYS_LANG" in
    pt)
      cat <<EOF2

─────────────────────────────────────────────────────────────────────
Technova IncidentScope ${VERSION}

A execução do script foi concluída.
Os arquivos gerados foram salvos em: ${OUTDIR}

Relatório principal: ${REPORT}
Resumo estruturado JSON: ${JSON_OUT}

Em caso de dúvidas, sugestões de melhoria ou necessidade de suporte,
entre em contato pelo e-mail: technova.sti@outlook.com

Se o Technova IncidentScope agregou valor ao seu dia a dia,
considere contribuir com qualquer valor via PIX: technova.sti@outlook.com
─────────────────────────────────────────────────────────────────────
EOF2
      ;;
    es)
      cat <<EOF2

─────────────────────────────────────────────────────────────────────
Technova IncidentScope ${VERSION}

La ejecución del script ha finalizado.
Los archivos generados fueron guardados en: ${OUTDIR}

Informe principal: ${REPORT}
Resumen estructurado JSON: ${JSON_OUT}

En caso de dudas, sugerencias de mejora o necesidad de soporte,
contacte por correo electrónico: technova.sti@outlook.com

Si Technova IncidentScope aportó valor a su rutina,
considere contribuir con cualquier monto vía PIX: technova.sti@outlook.com
─────────────────────────────────────────────────────────────────────
EOF2
      ;;
    *)
      cat <<EOF2

─────────────────────────────────────────────────────────────────────
Technova IncidentScope ${VERSION}

The script execution has finished.
The generated files were saved in: ${OUTDIR}

Main report: ${REPORT}
Structured JSON summary: ${JSON_OUT}

For questions, improvement suggestions or support needs,
please contact: technova.sti@outlook.com

If Technova IncidentScope added value to your daily work,
please consider contributing any amount via PIX: technova.sti@outlook.com
─────────────────────────────────────────────────────────────────────
EOF2
      ;;
  esac
}
help() {
  cat << EOF2
Uso:
  $(basename "$0") [--mensal] [--since "YYYY-MM-DD HH:MM"] [--until "YYYY-MM-DD HH:MM"]
                   [--duration-min MINUTOS] [--hours HORAS]
                   [--app APP_NAME] [--case-id CASE_ID]
                   [--analista "NOME DO ANALISTA"]
                   [--outdir OUTDIR] [--unit UNIT_FILTER]
                   [--grep EXTRA_REGEX] [--port "P1,P2,...|all"]
                   [--profile auto|generic|virt-host]
                   [--profile_auto|--profile_generic|--profile_virt_host]
                   [--coleta leve|padrao|detalhada]
                   [--coleta_leve|--coleta_padrao|--coleta_detalhada]
                   [--manual] [--non-interactive]

Parâmetros principais:
  --mensal             Analisa o mês anterior completo
  --since              Início da janela (YYYY-MM-DD HH:MM ou com segundos)
  --until              Fim da janela
  --duration-min       Duração em minutos a partir de --since
  --hours / -H         Últimas N horas até agora
  --app                Aplicação impactada
  --case-id            Número do chamado/incidente
  --analista           Nome do analista responsável pela execução
  --outdir             Diretório de saída
  --unit               Filtra journal por unit systemd
  --grep               Regex adicional para enriquecer o filtro de erros
  --port               Portas específicas (ex: 22,443) ou "all"; vazio = todas em escuta
  --profile            auto | generic | virt-host
  --profile_auto       Atalho para --profile auto
  --profile_generic    Atalho para --profile generic
  --profile_virt_host  Atalho para --profile virt-host
  --coleta             leve | padrao | detalhada
  --coleta_leve        Atalho para --coleta leve
  --coleta_padrao      Atalho para --coleta padrao
  --coleta_detalhada   Atalho para --coleta detalhada
  --manual             Exibe documentação estendida
  --non-interactive    Não faz perguntas no terminal

Interação:
  - Se nenhuma janela de tempo for informada no modo interativo, o script usa as últimas 24 horas
  - Janelas muito grandes geram um aviso no terminal
  - Para ajuda rápida, use --help
  - Para documentação detalhada, use --manual
  - Você também pode usar atalhos como --coleta_detalhada e --profile_auto

Perfis:
  auto                 Resolve automaticamente entre generic e virt-host
  generic              Linux genérico
  virt-host            Linux genérico + extensões para host/plataforma de virtualização

Níveis de coleta:
  leve                 Mais rápido, menos blocos extras
  padrao               Equilíbrio entre velocidade e profundidade (padrão)
  detalhada            Mais correlação, timeline e dados auxiliares

Exemplos:
  $(basename "$0")
  $(basename "$0") --hours 4
  $(basename "$0") --profile auto --coleta detalhada --hours 2 --analista "André Rodrigues" --non-interactive
  $(basename "$0") --since "2026-04-07 00:00" --until "2026-04-07 23:59" --port all --non-interactive
  $(basename "$0") --mensal --case-id INC-123456 --profile auto --coleta padrao

Use --manual para ver a documentação detalhada.
EOF2
  exit 0
}

manual() {
  cat << EOF2
MANUAL ESTENDIDO - ${VERSION}

1. Objetivo
   Este script foi pensado para gerar um pacote de evidências de incidente em Linux.
   Ele serve tanto para hosts físicos quanto para VMs e hosts de virtualização.

2. Diferença entre perfil e nível de coleta
   --profile define o tipo de ambiente que o script vai assumir.
     auto      -> detecta sozinho
     generic   -> Linux genérico
     virt-host -> adiciona coletas de host/plataforma de virtualização

   --coleta define a profundidade da coleta.
     leve      -> mais rápido, menos blocos complementares
     padrao    -> equilíbrio entre tempo e profundidade
     detalhada -> mais correlação, timeline, mudanças recentes e dados auxiliares

3. Interação no terminal
   Ao rodar sem parâmetros de janela de tempo, o script pode perguntar algumas informações.
   Se o analista não informar nenhuma janela, a coleta assume automaticamente as últimas 24 horas.

   Para apoio rápido durante o uso:
   - use --help para ajuda resumida
   - use --manual para documentação detalhada

4. Exemplo comentado
   ./analise_incidente_indisponibilidade-2.3.2-unix-based.sh --profile_auto --coleta_detalhada

   O que significa:
   - executa o script localmente
   - deixa o perfil ser resolvido automaticamente
   - usa o nível de coleta detalhada
   - no modo interativo, o restante será perguntado no terminal

5. O que o script coleta
   - Identidade do host
   - Contexto de virtualização
   - Janela temporal
   - Journal e erros relevantes
   - Memória, swap, disco, inodes, rede, systemd
   - Login(s) recente(s), reboot/shutdown, timeline do incidente
   - Resumo executivo e JSON best-effort

6. O que é best-effort
   Algumas informações dependem do que o SO já registrou historicamente:
   - responsável por reboot
   - motivo do reboot
   - iowait histórico
   - latência histórica de storage
   - consumo de processo ao longo do tempo

   Sem sar/iostat/pcp/monitoramento prévio, o script mostra snapshot atual + inferência via logs.

7. Recomendações práticas
   - Rodar como root ou com sudo disponível
   - Em incidentes reais, preferir --coleta padrao ou detalhada
   - Em hosts críticos, manter sysstat/iostat/sar instalados melhora muito a qualidade histórica

8. Exemplos úteis
   Últimas 4 horas:
     $(basename "$0") --hours 4 --profile auto --coleta detalhada --analista "Seu Nome" --non-interactive

   Janela fechada por data/hora:
     $(basename "$0") --since "2026-04-07 00:00" --until "2026-04-07 23:59" --profile auto --coleta detalhada --analista "Seu Nome" --non-interactive

   Mês anterior:
     $(basename "$0") --mensal --profile auto --coleta padrao --analista "Seu Nome" --non-interactive
EOF2
  exit 0
}

print_interactive_guidance() {
  say ""
  info "Menu rápido de apoio"
  say " - Para ajuda resumida: use --help"
  say " - Para documentação detalhada: use --manual"
  say " - Se nenhuma janela de tempo for informada, o script usará automaticamente as últimas 24 horas."
  say " - Você também pode definir a janela antes da execução com --since/--until, --hours, --duration-min ou --mensal."
  say " - Atalhos aceitos: --coleta_detalhada, --coleta_padrao, --coleta_leve, --profile_auto, --profile_generic e --profile_virt_host."
  say ""
}

confirm_continue_without_analyst() {
  local ans=""
  while true; do
    read -rp ">>> Nome do analista não informado. Deseja prosseguir assim mesmo? [y/n]: " ans
    case "${ans,,}" in
      y|yes|s|sim) ANALYST_NAME="não informado"; return 0 ;;
      n|no|nao|não) err "Execução cancelada pelo operador."; exit 1 ;;
      *) warn "Resposta inválida. Digite y ou n." ;;
    esac
  done
}

set_default_last_24h() {
  SINCE="24 hours ago"
  UNTIL="now"
  info "Nenhuma janela informada. Usando automaticamente as últimas 24 horas."
}

run_priv() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    if command -v sudo >/dev/null 2>&1; then
      sudo "$@"
    else
      err "Este script precisa ser executado como root ou ter sudo disponível."
      return 1
    fi
  fi
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }
normalize_ts() {
  local ts="${1:-}"
  [[ -z "${ts}" ]] && { printf "%s" "${ts}"; return 0; }
  if [[ "${ts}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then printf "%s 00:00:00" "${ts}"; return 0; fi
  if [[ "${ts}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}$ ]]; then printf "%s:00" "${ts}"; return 0; fi
  printf "%s" "${ts}"
}
validate_ts() { date -d "${1:-}" >/dev/null 2>&1; }
ts_to_epoch() { date -d "${1:-}" +%s 2>/dev/null; }
ts_to_stamp() {
  local ts="${1:-}" parsed=""
  parsed="$(date -d "${ts}" +"%d%m%Y%H%M" 2>/dev/null || true)"
  [[ -n "${parsed}" ]] || parsed="$(echo "${ts}" | tr -cd '0-9' | cut -c1-12)"
  [[ -n "${parsed}" ]] || parsed="$(date +'%d%m%Y%H%M')"
  printf "%s" "${parsed}"
}
first_nonempty() {
  local value=""
  for value in "$@"; do [[ -n "${value}" ]] && { printf "%s" "${value}"; return 0; }; done
  return 1
}

grep_count_safe() {
  local pattern="$1"
  local file="$2"
  local out=""
  out="$(grep -Eic "${pattern}" "${file}" 2>/dev/null || true)"
  out="${out##*$'\n'}"
  [[ "${out}" =~ ^[0-9]+$ ]] || out=0
  printf "%s" "${out}"
}

PROFILE="auto"
PROFILE_RESOLVED=""
COLETA="padrao"
MODE_MENSAL="0"
SINCE=""
UNTIL=""
HOURS=""
DURATION_MIN=""
UNIT_FILTER=""
EXTRA_REGEX=""
APP_NAME=""
CASE_ID=""
ANALYST_NAME=""
OUTDIR=""
REPORT=""
JSON_OUT=""
PORT_LIST=""
NON_INTERACTIVE="0"
SHOW_MANUAL="0"

HOSTNAME_SHORT="não identificado"
HOSTNAME_FQDN="não identificado"
HOST_IPV4="não identificado"
HOST_IPV6="não identificado"
OS_PRETTY="não identificado"
KERNEL_INFO="não identificado"
UPTIME_INFO="não identificado"
TIMEZONE_INFO="não identificado"
CURRENT_TIME_INFO="não identificado"
SINCE_DISPLAY=""
UNTIL_DISPLAY=""
IS_PROXMOX_NODE="no"
EXECUTION_CONTEXT="physical"
VIRT_TECH="none"
VIRT_STACK="none"
HOST_ROLE="linux genérico"
HYPERVISOR_CONTEXT="não"
HW_VENDOR="não identificado"
HW_PRODUCT="não identificado"
HW_VERSION="não identificado"
EXEC_USER="$(id -un 2>/dev/null || whoami 2>/dev/null || echo 'não identificado')"
EXEC_UID="$(id -u 2>/dev/null || echo 'não identificado')"

CPU_STATUS="não avaliado"
MEM_STATUS="não avaliado"
DISK_STATUS="não avaliado"
INODE_STATUS="não avaliado"
FAILED_UNITS_STATUS="não avaliado"
PORT_STATUS="não avaliado"
MAIN_CLUE="não identificado"
WINDOW_WARNING="nenhum"
WINDOW_WARNING_LINE=""
OOM_STATUS="não avaliado"
OOM_FIRST_CLUE=""
SWAP_PRESSURE_STATUS="não avaliado"
IOWAIT_STATUS="não avaliado"
STORAGE_LATENCY_STATUS="não avaliado"
CRITICAL_FS_SUMMARY="nenhum filesystem >= 90% detectado"
CRITICAL_INODE_SUMMARY="nenhum inode >= 90% detectado"
TESTED_PORTS_SUMMARY="nenhuma"
LISTENING_SERVICES_SUMMARY="não identificado"

LAST_LOGIN_LINE=""
LAST_LOGIN_USER="não identificado"
LAST_LOGIN_DURATION="não identificado"
LAST_LOGIN_TOP10=""
LAST_POWER_LINE=""
LAST_POWER_TYPE="não identificado"
LAST_POWER_REASON=""
LAST_POWER_ACTOR=""

PORT_SCOPE_DESC=""
PORTS=()
FAILED_PORTS=()
PORT_FAIL_COUNT=0
PORT_OK_COUNT=0
FAILED_PORTS_SUMMARY="nenhuma"
FAILED_UNITS_LIST="nenhuma"
STACKS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) help ;;
    --manual) SHOW_MANUAL="1"; shift ;;
    --version) echo "$(basename "$0") v${VERSION} (${BUILD_DATE})"; exit 0 ;;
    --mensal) MODE_MENSAL="1"; shift ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --until) UNTIL="${2:-}"; shift 2 ;;
    --duration-min) DURATION_MIN="${2:-}"; shift 2 ;;
    --hours|-H) HOURS="${2:-}"; shift 2 ;;
    --unit) UNIT_FILTER="${2:-}"; shift 2 ;;
    --grep) EXTRA_REGEX="${2:-}"; shift 2 ;;
    --app) APP_NAME="${2:-}"; shift 2 ;;
    --case-id) CASE_ID="${2:-}"; shift 2 ;;
    --analista) ANALYST_NAME="${2:-}"; shift 2 ;;
    --outdir) OUTDIR="${2:-}"; shift 2 ;;
    --report) REPORT="${2:-}"; shift 2 ;;
    --port) PORT_LIST="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2,,}"; shift 2 ;;
    --profile_auto) PROFILE="auto"; shift ;;
    --profile_generic) PROFILE="generic"; shift ;;
    --profile_virt_host) PROFILE="virt-host"; shift ;;
    --coleta) COLETA="${2,,}"; shift 2 ;;
    --coleta_leve) COLETA="leve"; shift ;;
    --coleta_padrao) COLETA="padrao"; shift ;;
    --coleta_detalhada) COLETA="detalhada"; shift ;;
    --non-interactive) NON_INTERACTIVE="1"; shift ;;
    *) err "Parâmetro desconhecido: $1"; echo; help ;;
  esac
done

[[ "${SHOW_MANUAL}" == "1" ]] && manual
[[ "${COLETA}" =~ ^(leve|padrao|detalhada)$ ]] || { err "Valor inválido para --coleta: ${COLETA}. Use leve|padrao|detalhada"; exit 1; }

print_startup_banner
print_startup_disclaimer

info "Nível de coleta: ${COLETA}"
info "Perfil solicitado: ${PROFILE}"

collect_host_identity() {
  HOSTNAME_SHORT="$(hostname 2>/dev/null || echo 'não identificado')"
  HOSTNAME_FQDN="$(hostname -f 2>/dev/null || echo "${HOSTNAME_SHORT}")"
  HOST_IPV4="$(ip -o -4 addr show up scope global 2>/dev/null | awk '{print $2"=" $4}' | paste -sd '; ' -)"
  HOST_IPV6="$(ip -o -6 addr show up scope global 2>/dev/null | awk '{print $2"=" $4}' | paste -sd '; ' -)"
  [[ -n "${HOST_IPV4}" ]] || HOST_IPV4="não identificado"
  [[ -n "${HOST_IPV6}" ]] || HOST_IPV6="não identificado"
  if [[ -f /etc/os-release ]]; then OS_PRETTY="$(. /etc/os-release && echo "${PRETTY_NAME:-${NAME:-não identificado}}")"; fi
  KERNEL_INFO="$(uname -srmo 2>/dev/null || echo 'não identificado')"
  UPTIME_INFO="$(uptime 2>/dev/null || echo 'não identificado')"
  TIMEZONE_INFO="$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'não identificado')"
  CURRENT_TIME_INFO="$(date 2>/dev/null || echo 'não identificado')"
  HW_VENDOR="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo 'não identificado')"
  HW_PRODUCT="$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'não identificado')"
  HW_VERSION="$(cat /sys/class/dmi/id/product_version 2>/dev/null || echo 'não identificado')"
}

add_stack() {
  local item="$1" existing=""
  for existing in "${STACKS[@]:-}"; do [[ "${existing}" == "${item}" ]] && return 0; done
  STACKS+=("${item}")
}

detect_virtualization_context() {
  IS_PROXMOX_NODE="no"; EXECUTION_CONTEXT="physical"; VIRT_TECH="none"; VIRT_STACK="none"; HOST_ROLE="linux genérico"; HYPERVISOR_CONTEXT="não"; STACKS=()
  if cmd_exists pveversion && [[ -d /etc/pve ]]; then IS_PROXMOX_NODE="yes"; add_stack "proxmox"; add_stack "kvm"; add_stack "lxc"; fi
  if cmd_exists systemd-detect-virt; then
    if systemd-detect-virt --quiet --container; then EXECUTION_CONTEXT="container"; VIRT_TECH="$(systemd-detect-virt 2>/dev/null || echo 'unknown')";
    elif systemd-detect-virt --quiet; then EXECUTION_CONTEXT="vm"; VIRT_TECH="$(systemd-detect-virt 2>/dev/null || echo 'unknown')";
    else EXECUTION_CONTEXT="physical"; VIRT_TECH="none"; fi
  fi
  [[ "${VIRT_TECH}" != "none" ]] && add_stack "${VIRT_TECH}"
  if cmd_exists virsh || systemctl list-unit-files 2>/dev/null | grep -qE '^libvirtd|^virtqemud'; then add_stack "libvirt"; add_stack "kvm"; fi
  if cmd_exists xl || systemctl list-unit-files 2>/dev/null | grep -q '^xen'; then add_stack "xen"; fi
  if cmd_exists lxc || cmd_exists lxd || [[ -d /var/lib/lxc ]] || [[ -S /var/snap/lxd/common/lxd/unix.socket ]]; then add_stack "lxc/lxd"; fi
  if systemctl list-unit-files 2>/dev/null | grep -q 'nova-compute'; then add_stack "openstack-compute"; fi
  if systemctl list-unit-files 2>/dev/null | grep -q 'docker'; then add_stack "docker"; fi
  if systemctl list-unit-files 2>/dev/null | grep -q 'containerd'; then add_stack "containerd"; fi
  if [[ "${#STACKS[@]}" -gt 0 ]]; then VIRT_STACK="$(IFS=', '; echo "${STACKS[*]}")"; fi

  case "${PROFILE}" in
    auto)
      if [[ "${IS_PROXMOX_NODE}" == "yes" ]] || [[ "${#STACKS[@]}" -gt 1 ]] || cmd_exists virsh || cmd_exists xl || cmd_exists lxc || cmd_exists lxd; then PROFILE_RESOLVED="virt-host"; else PROFILE_RESOLVED="generic"; fi
      ;;
    generic|linux) PROFILE_RESOLVED="generic" ;;
    virt-host|virthost|hypervisor) PROFILE_RESOLVED="virt-host" ;;
    *) err "Perfil inválido: ${PROFILE}. Use: auto | generic | virt-host"; exit 1 ;;
  esac

  if [[ "${PROFILE_RESOLVED}" == "virt-host" ]]; then
    HOST_ROLE="host de virtualização"
    HYPERVISOR_CONTEXT="sim - $(first_nonempty "${VIRT_STACK}" "host de virtualização")"
  else
    HOST_ROLE="linux genérico"
    if [[ "${EXECUTION_CONTEXT}" == "vm" || "${EXECUTION_CONTEXT}" == "container" ]]; then
      HYPERVISOR_CONTEXT="não - guest ${EXECUTION_CONTEXT} (${VIRT_TECH})"
    else
      HYPERVISOR_CONTEXT="não"
    fi
  fi
}

collect_timing_info() {
  {
    echo "==== Contexto de Tempo ($(date)) ===="
    echo "Timezone: ${TIMEZONE_INFO}"
    echo "Hora atual: ${CURRENT_TIME_INFO}"
    echo
    echo "-- timedatectl --"; cmd_exists timedatectl && timedatectl 2>/dev/null || echo "(timedatectl não disponível)"
    echo
    echo "-- chronyc tracking --"; cmd_exists chronyc && chronyc tracking 2>/dev/null || echo "(chronyc não disponível)"
    echo
    echo "-- ntpq -p --"; cmd_exists ntpq && ntpq -p 2>/dev/null || echo "(ntpq não disponível)"
  } > "${TIME_INFO_OUT}" 2>&1 || true
}

collect_memory_info() {
  {
    echo "==== Memória / Swap / Pressão ($(date)) ===="
    echo "-- free -h --"; cmd_exists free && free -h 2>/dev/null || echo "(free não disponível)"
    echo
    echo "-- swapon --show --"; cmd_exists swapon && swapon --show 2>/dev/null || echo "(swapon não disponível)"
    echo
    echo "-- /proc/pressure/memory --"; [[ -f /proc/pressure/memory ]] && cat /proc/pressure/memory || echo "(PSI memory não disponível)"
    echo
    if [[ "${COLETA}" != "leve" ]]; then
      echo "-- vmstat 1 5 --"; cmd_exists vmstat && vmstat 1 5 2>/dev/null || echo "(vmstat não disponível)"
    fi
  } > "${MEM_INFO_OUT}" 2>&1 || true
}

collect_storage_info() {
  {
    echo "==== Inventário de Discos / Filesystems ($(date)) ===="
    echo "-- lsblk (discos do tipo disk) --"; cmd_exists lsblk && lsblk -d -n -o NAME,SIZE,MODEL,TYPE 2>/dev/null | awk '$4=="disk"' || echo "(lsblk não disponível)"
    echo
    echo "-- df -hP --"; df -hP 2>/dev/null || true
    echo
    echo "-- df -hiP --"; df -hiP 2>/dev/null || true
  } > "${STORAGE_INFO_OUT}" 2>&1 || true
}

collect_perf_info() {
  {
    echo "==== Performance / IO / Latência ($(date)) ===="
    echo "-- /proc/pressure/io --"; [[ -f /proc/pressure/io ]] && cat /proc/pressure/io || echo "(PSI IO não disponível)"
    echo
    echo "-- /proc/pressure/cpu --"; [[ -f /proc/pressure/cpu ]] && cat /proc/pressure/cpu || echo "(PSI CPU não disponível)"
    echo
    echo "-- vmstat 1 3 --"; cmd_exists vmstat && vmstat 1 3 2>/dev/null || echo "(vmstat não disponível)"
    echo
    echo "-- iostat -xz 1 2 --"; cmd_exists iostat && iostat -xz 1 2 2>/dev/null | awk '/^Linux/ || /^avg-cpu:/ || /^Device/ || /^$/ {print; next} $1 ~ /^(loop|ram|sr)/ {next} {print}' || echo "(iostat não disponível; instale sysstat para enriquecer este bloco)"
    echo
    if [[ "${COLETA}" == "detalhada" ]]; then
      echo "-- sar -u 1 3 --"; cmd_exists sar && sar -u 1 3 2>/dev/null || echo "(sar não disponível)"
      echo
      echo "-- sar -d 1 3 --"; cmd_exists sar && sar -d 1 3 2>/dev/null || echo "(sar não disponível)"
    fi
  } > "${PERF_INFO_OUT}" 2>&1 || true
}

collect_systemd_info() {
  {
    echo "==== Systemd / Services ($(date)) ===="
    echo "-- systemctl --failed --"; systemctl --failed --no-pager 2>/dev/null || echo "(systemctl --failed indisponível)"
    echo
    echo "-- failed units count --"; systemctl --failed --no-legend 2>/dev/null | wc -l || true
    echo
    if [[ "${COLETA}" != "leve" ]]; then
      echo "-- últimas mudanças relevantes de units --"; journalctl --no-pager -u '*'.service -n 100 2>/dev/null || true
      echo
      echo "-- warning..alert --"; journalctl --no-pager -p warning..alert -n 80 2>/dev/null || true
    fi
  } > "${SYSTEMD_INFO_OUT}" 2>&1 || true
}

collect_network_info() {
  {
    echo "==== Rede ($(date)) ===="
    echo "-- ip addr --"; cmd_exists ip && ip addr 2>/dev/null || echo "(ip não disponível)"
    echo
    echo "-- ip route --"; cmd_exists ip && ip route 2>/dev/null || echo "(ip não disponível)"
    echo
    echo "-- DNS --"
    if cmd_exists resolvectl; then resolvectl status 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || true; else cat /etc/resolv.conf 2>/dev/null || true; fi
    echo
    echo "-- ss -s / netstat -s --"
    if cmd_exists ss; then ss -s 2>/dev/null || true; elif cmd_exists netstat; then netstat -s 2>/dev/null || true; else echo "(ss/netstat não disponíveis)"; fi
    echo
    if [[ "${COLETA}" != "leve" ]]; then
      echo "-- conexões estabelecidas relevantes --"
      if cmd_exists ss; then ss -tpna state established 2>/dev/null | head -n 80 || true; elif cmd_exists netstat; then netstat -tpna 2>/dev/null | grep ESTABLISHED | head -n 80 || true; else echo "(ss/netstat não disponíveis)"; fi
      echo
      echo "-- erros por interface (ip -s link) --"; cmd_exists ip && ip -s link 2>/dev/null || echo "(ip não disponível)"
    fi
  } > "${NETWORK_INFO_OUT}" 2>&1 || true
}

collect_recent_changes() {
  {
    echo "==== Mudanças Recentes no Host ($(date)) ===="
    echo "-- pacotes recentes --"
    if [[ -f /var/log/dpkg.log ]]; then tail -n 80 /var/log/dpkg.log 2>/dev/null || true
    elif cmd_exists dnf; then dnf history list 2>/dev/null | head -n 40 || true
    elif cmd_exists yum; then yum history list 2>/dev/null | head -n 40 || true
    else echo "(histórico de pacotes não encontrado)"; fi
    echo
    echo "-- alterações recentes em /etc (últimos 7 dias, top 80) --"; find /etc -maxdepth 3 -type f -mtime -7 2>/dev/null | sort | head -n 80 || true
    echo
    echo "-- possíveis comandos sudo de restart/reboot/poweroff --"
    if [[ -f /var/log/auth.log ]]; then
      grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl (restart|reboot|poweroff)|service .* restart)|COMMAND=.*(reboot|shutdown|poweroff|halt|systemctl|service)' /var/log/auth.log 2>/dev/null | tail -n 80 || true
    elif [[ -f /var/log/secure ]]; then
      grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl (restart|reboot|poweroff)|service .* restart)|COMMAND=.*(reboot|shutdown|poweroff|halt|systemctl|service)' /var/log/secure 2>/dev/null | tail -n 80 || true
    else
      journalctl --no-pager 2>/dev/null | grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl (restart|reboot|poweroff)|service .* restart)|COMMAND=.*(reboot|shutdown|poweroff|halt|systemctl|service)' | tail -n 80 || true
    fi
  } > "${CHANGES_INFO_OUT}" 2>&1 || true
}

resolve_ports() {
  local input="${1:-}" normalized=""
  PORTS=(); PORT_SCOPE_DESC=""
  normalized="$(echo "${input}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if [[ -z "${normalized}" || "${normalized}" == "all" || "${normalized}" == "todas" || "${normalized}" == "*" ]]; then
    PORT_SCOPE_DESC="todas as portas TCP em escuta no host"
    if cmd_exists ss; then
      mapfile -t PORTS < <(run_priv ss -H -lnt 2>/dev/null | awk '{print $4}' | sed -E 's/^\[::ffff:([^]]+)\]$/\1/' | sed -E 's/^\[([^]]+)\]$//' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -n -u)
    elif cmd_exists lsof; then
      mapfile -t PORTS < <(run_priv lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {split($9,a,":"); print a[length(a)]}' | grep -E '^[0-9]+$' | sort -n -u)
    else
      PORT_SCOPE_DESC="não foi possível descobrir as portas em escuta (ss/lsof ausentes)"; PORTS=()
    fi
  else
    PORT_SCOPE_DESC="portas específicas informadas: ${input}"
    mapfile -t PORTS < <(echo "${input}" | tr ',' '\n' | tr -d '[:space:]' | grep -E '^[0-9]+$' | sort -n -u)
  fi
}

collect_listening_services_info() {
  {
    echo "==== Serviços em Escuta ($(date)) ===="
    if cmd_exists lsof; then
      run_priv lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {split($9,a,":"); print a[length(a)] " -> " $1 " (pid=" $2 ")"}' | sort -n -u || true
    elif cmd_exists ss; then
      run_priv ss -ltnpH 2>/dev/null || true
    else
      echo "(lsof/ss não disponíveis)"
    fi
  } > "${LISTENING_INFO_OUT}" 2>&1 || true

  TESTED_PORTS_SUMMARY="$(IFS=', '; echo "${PORTS[*]:-nenhuma}")"
  LISTENING_SERVICES_SUMMARY="$(tail -n +2 "${LISTENING_INFO_OUT}" 2>/dev/null | head -n 10 | awk 'NR==1{printf "%s",$0; next}{printf "; %s",$0} END{if(NR) print ""}')"
  [[ -n "${LISTENING_SERVICES_SUMMARY}" ]] || LISTENING_SERVICES_SUMMARY="não identificado"
}

collect_last_login_info() {
  LAST_LOGIN_LINE=""; LAST_LOGIN_USER="não identificado"; LAST_LOGIN_DURATION="não identificado"; LAST_LOGIN_TOP10=""
  LAST_LOGIN_TOP10="$(last -Faiw 2>/dev/null | awk '!/^(reboot|shutdown|wtmp|btmp)/ && NF {print}' | head -n 10 || true)"
  LAST_LOGIN_LINE="$(printf "%s\n" "${LAST_LOGIN_TOP10}" | head -n 1)"

  {
    echo "==== Últimos 10 logins/sessões registrados ===="
    if [[ -n "${LAST_LOGIN_TOP10}" ]]; then printf "%s\n" "${LAST_LOGIN_TOP10}"; else echo "Nenhum registro de login encontrado."; fi
  } > "${LOGIN_INFO_OUT}"

  if [[ -n "${LAST_LOGIN_LINE}" ]]; then
    LAST_LOGIN_USER="$(awk '{print $1}' <<< "${LAST_LOGIN_LINE}" 2>/dev/null || echo 'não identificado')"
    if grep -qi 'still logged in' <<< "${LAST_LOGIN_LINE}"; then LAST_LOGIN_DURATION="sessão ainda ativa"
    elif [[ "${LAST_LOGIN_LINE}" =~ \(([0-9:+]+)\)$ ]]; then LAST_LOGIN_DURATION="${BASH_REMATCH[1]}"
    else LAST_LOGIN_DURATION="não foi possível determinar automaticamente"; fi
  fi
}

find_last_power_reason() {
  local reason=""
  reason="$(journalctl -b -1 --no-pager 2>/dev/null | grep -Ei 'power key|reboot|shutdown|poweroff|halt|watchdog|panic|oom|out of memory|system is rebooting|system is powering off|The system will reboot now|The system will power off now' | tail -n 1 || true)"
  [[ -n "${reason}" ]] || reason="$(journalctl --no-pager 2>/dev/null | grep -Ei 'power key|reboot|shutdown|poweroff|halt|watchdog|panic|oom|out of memory|system is rebooting|system is powering off|The system will reboot now|The system will power off now' | tail -n 1 || true)"
  printf "%s" "${reason}"
}

find_last_power_actor() {
  local actor=""
  if [[ -f /var/log/auth.log ]]; then actor="$(grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl reboot|systemctl poweroff)|COMMAND=.*(reboot|shutdown|poweroff|halt)' /var/log/auth.log | tail -n 1 || true)"
  elif [[ -f /var/log/secure ]]; then actor="$(grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl reboot|systemctl poweroff)|COMMAND=.*(reboot|shutdown|poweroff|halt)' /var/log/secure | tail -n 1 || true)"; fi
  [[ -n "${actor}" ]] || actor="$(journalctl --no-pager 2>/dev/null | grep -Ei 'sudo:.*(reboot|shutdown|poweroff|halt|systemctl reboot|systemctl poweroff)|COMMAND=.*(reboot|shutdown|poweroff|halt)|power key pressed' | tail -n 1 || true)"
  printf "%s" "${actor}"
}

collect_last_power_event_info() {
  LAST_POWER_LINE="$(last -xFwi 2>/dev/null | awk '/^(reboot|shutdown)/ {print; exit}' || true)"
  LAST_POWER_REASON="$(find_last_power_reason)"
  LAST_POWER_ACTOR="$(find_last_power_actor)"
  [[ -n "${LAST_POWER_LINE}" ]] && LAST_POWER_TYPE="$(awk '{print $1}' <<< "${LAST_POWER_LINE}" 2>/dev/null || echo 'não identificado')" || LAST_POWER_TYPE="não identificado"
  {
    echo "==== Último evento de desligamento/reboot ===="
    [[ -n "${LAST_POWER_LINE}" ]] && echo "Registro last -x: ${LAST_POWER_LINE}" || echo "Registro last -x: não encontrado"
    [[ -n "${LAST_POWER_REASON}" ]] && echo "Evidência de motivo (best-effort): ${LAST_POWER_REASON}" || echo "Evidência de motivo (best-effort): não encontrada"
    [[ -n "${LAST_POWER_ACTOR}" ]] && echo "Possível responsável (best-effort): ${LAST_POWER_ACTOR}" || echo "Possível responsável (best-effort): não encontrado"
    echo "Observação: motivo e responsável nem sempre ficam registrados de forma confiável no Linux."
  } > "${POWER_EVENT_OUT}"
}

collect_timeline_info() {
  {
    echo "==== Timeline do Incidente (${SINCE} -> ${UNTIL}) ===="
    journalctl --since "${SINCE}" --until "${UNTIL}" --no-pager -o short-iso 2>/dev/null \
      | grep -Ei 'oom|out of memory|killed process|no space left|i/o error|io error|timeout|timed out|fail|failed|panic|segfault|reboot|shutdown|restart|stopped|starting|connection refused|unreachable|reset by peer' \
      | tail -n 500 || true
  } > "${TIMELINE_OUT}" 2>&1 || true
}

collect_virt_host_info() {
  {
    echo "==== Informações de Host de Virtualização ($(date)) ===="
    echo "Perfil resolvido: ${PROFILE_RESOLVED}"
    echo "Stack detectada: ${VIRT_STACK}"
    echo "É nó Proxmox: ${IS_PROXMOX_NODE}"
    echo "Contexto de execução: ${EXECUTION_CONTEXT}"
    echo "Tecnologia de virtualização: ${VIRT_TECH}"
    echo
    if [[ "${IS_PROXMOX_NODE}" == "yes" ]]; then
      echo "-- pveversion -v --"; pveversion -v 2>/dev/null || true
      echo
      echo "-- pvecm status --"; cmd_exists pvecm && pvecm status 2>/dev/null || echo "(pvecm não disponível)"
      echo
      echo "-- pvesm status --"; cmd_exists pvesm && pvesm status 2>/dev/null || echo "(pvesm não disponível)"
      echo
      echo "-- qm list --"; cmd_exists qm && qm list 2>/dev/null || echo "(qm não disponível)"
      echo
      echo "-- pct list --"; cmd_exists pct && pct list 2>/dev/null || echo "(pct não disponível)"
      echo
      echo "-- serviços Proxmox --"; systemctl status pve-cluster pvedaemon pveproxy pvestatd corosync --no-pager 2>/dev/null || true
      echo
      echo "-- bridges --"
      if cmd_exists bridge; then bridge link 2>/dev/null || true; elif cmd_exists brctl; then brctl show 2>/dev/null || true; else echo "(bridge/brctl não disponíveis)"; fi
    fi
    if cmd_exists virsh; then echo; echo "-- virsh list --all --"; virsh list --all 2>/dev/null || true; fi
    if cmd_exists xl; then echo; echo "-- xl info --"; xl info 2>/dev/null || true; echo; echo "-- xl list --"; xl list 2>/dev/null || true; fi
    if cmd_exists lxc; then echo; echo "-- lxc list --"; lxc list 2>/dev/null || true; fi
  } > "${VIRT_HOST_INFO_OUT}" 2>&1 || true
}

get_best_main_clue() {
  local line=""
  line="$(grep -Eim1 'out of memory|oom-killer|oom killer|oom-kill|killed process' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'no space left|disk full|filesystem full' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'i/o error|io error|blk_update_request|ext4.*error|xfs.*error' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'failed to start|failed with result|unit .*failed|service failed|entered failed state' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'timeout|timed out' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'connection refused|unreachable|name or service not known|temporary failure in name resolution|reset by peer' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'segfault|panic|call trace' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'watchdog|hogged CPU|clocksource' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  line="$(grep -Eim1 'restart|stopped|starting' "${ERROS_OUT}" 2>/dev/null || true)"
  [[ -n "${line}" ]] && { printf "%s" "${line}"; return 0; }
  printf "%s" ""
}

build_executive_summary() {
  local cpu_count="0" load1="0" mem_total_kb="0" mem_avail_kb="0" mem_avail_pct="0" failed_units_count="0" first_error="" last_vmstat_line="" maxawait="" maxawaitdev=""
  cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)"
  load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
  if awk -v l="${load1}" -v c="${cpu_count}" 'BEGIN {exit !(c>0 && l>c)}'; then CPU_STATUS="pressão detectada (load1=${load1} > cpus=${cpu_count})"; else CPU_STATUS="sem pressão relevante aparente (load1=${load1}, cpus=${cpu_count})"; fi

  mem_total_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_avail_kb="$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [[ "${mem_total_kb}" -gt 0 ]]; then
    mem_avail_pct=$(( mem_avail_kb * 100 / mem_total_kb ))
    if [[ "${mem_avail_pct}" -lt 10 ]]; then MEM_STATUS="crítica (MemAvailable=${mem_avail_pct}%)"
    elif [[ "${mem_avail_pct}" -lt 20 ]]; then MEM_STATUS="atenção (MemAvailable=${mem_avail_pct}%)"
    else MEM_STATUS="normal (MemAvailable=${mem_avail_pct}%)"; fi
  fi

  CRITICAL_FS_SUMMARY="$(df -PT 2>/dev/null | awk 'NR>1 && $2 !~ /^(tmpfs|devtmpfs|efivarfs|proc|sysfs|cgroup|cgroup2|overlay|squashfs|devpts|mqueue|tracefs|debugfs|securityfs|pstore|configfs|autofs|fusectl|binfmt_misc)$/ {gsub(/%/,"",$6); if($6>=90) print $7 " (" $6 "% usado, tipo=" $2 ")"}' | paste -sd '; ' -)"
  [[ -n "${CRITICAL_FS_SUMMARY}" ]] || CRITICAL_FS_SUMMARY="nenhum filesystem operacional >= 90% detectado"
  if [[ "${CRITICAL_FS_SUMMARY}" == "nenhum filesystem operacional >= 90% detectado" ]]; then
    DISK_STATUS="normal"
  else
    DISK_STATUS="atenção (${CRITICAL_FS_SUMMARY})"
  fi

  CRITICAL_INODE_SUMMARY="$(df -iPT 2>/dev/null | awk 'NR>1 && $2 !~ /^(tmpfs|devtmpfs|efivarfs|proc|sysfs|cgroup|cgroup2|overlay|squashfs|devpts|mqueue|tracefs|debugfs|securityfs|pstore|configfs|autofs|fusectl|binfmt_misc)$/ {gsub(/%/,"",$6); if($6>=90) print $7 " (" $6 "% inode usado, tipo=" $2 ")"}' | paste -sd '; ' -)"
  [[ -n "${CRITICAL_INODE_SUMMARY}" ]] || CRITICAL_INODE_SUMMARY="nenhum inode operacional >= 90% detectado"
  if [[ "${CRITICAL_INODE_SUMMARY}" == "nenhum inode operacional >= 90% detectado" ]]; then INODE_STATUS="normal"; else INODE_STATUS="atenção (${CRITICAL_INODE_SUMMARY})"; fi

  FAILED_UNITS_LIST="$(systemctl --failed --plain --no-legend 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /\.(service|socket|mount|target|timer|path|scope|slice|device)$/){print $i; break}}' | head -n 5 | awk 'NR==1{printf "%s",$0; next}{printf ", %s",$0} END{if(NR) print ""}')"
  [[ -n "${FAILED_UNITS_LIST}" ]] || FAILED_UNITS_LIST="nenhuma"
  failed_units_count="$(systemctl --failed --plain --no-legend 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /\.(service|socket|mount|target|timer|path|scope|slice|device)$/){print $i; break}}' | wc -l | awk '{print $1}' || echo 0)"
  if [[ "${failed_units_count}" -gt 0 ]]; then FAILED_UNITS_STATUS="${failed_units_count} unidade(s) com falha"; else FAILED_UNITS_STATUS="nenhuma unidade com falha aparente"; fi

  if [[ "${PORT_FAIL_COUNT}" -gt 0 ]]; then PORT_STATUS="${PORT_OK_COUNT} OK / ${PORT_FAIL_COUNT} falha(s)"; else PORT_STATUS="${PORT_OK_COUNT} OK / 0 falhas"; fi

  oom_count=$(( $(grep_count_safe 'killed process' "${DMESG_KILLED}") + $(grep_count_safe 'out of memory|oom-killer|oom killer|oom-kill' "${VARLOG_OOM}") + $(grep_count_safe 'out of memory|oom-killer|oom killer|oom-kill|killed process' "${ERROS_OUT}") ))
  OOM_STATUS="${oom_count} ocorrência(s) correlacionadas"
  OOM_FIRST_CLUE="$(first_nonempty "$(grep -Eim1 'killed process' "${DMESG_KILLED}" 2>/dev/null || true)" "$(grep -Eim1 'out of memory|oom-killer|oom killer|oom-kill' "${VARLOG_OOM}" 2>/dev/null || true)" "$(grep -Eim1 'out of memory|oom-killer|oom killer|oom-kill|killed process' "${ERROS_OUT}" 2>/dev/null || true)")"

  last_vmstat_line="$(awk 'NF>=16 && $1 ~ /^[0-9.]+$/ && $7 ~ /^[0-9.]+$/ {line=$0} END{print line}' "${PERF_INFO_OUT}" 2>/dev/null || true)"
  if [[ -n "${last_vmstat_line}" ]]; then
    local_si="$(awk '{print $7}' <<< "${last_vmstat_line}" 2>/dev/null || echo 0)"
    local_so="$(awk '{print $8}' <<< "${last_vmstat_line}" 2>/dev/null || echo 0)"
    local_wa="$(awk '{print $16}' <<< "${last_vmstat_line}" 2>/dev/null || echo 0)"
    if awk -v si="${local_si:-0}" -v so="${local_so:-0}" 'BEGIN {exit !((si+0)>0 || (so+0)>0)}'; then SWAP_PRESSURE_STATUS="indício de swap activity (si=${local_si}, so=${local_so})"; else SWAP_PRESSURE_STATUS="sem atividade relevante de swap no snapshot"; fi
    if awk -v wa="${local_wa:-0}" 'BEGIN {exit !((wa+0)>=10)}'; then IOWAIT_STATUS="atenção (wa=${local_wa}%)"; else IOWAIT_STATUS="sem iowait relevante no snapshot (wa=${local_wa:-0}%)"; fi
  fi

  if cmd_exists iostat; then
    maxawait="$(iostat -xz 1 2 2>/dev/null | awk '/^Device/ {for(i=1;i<=NF;i++) if($i=="await") a=i; next} a && NF>=a && $1!="" && $1 !~ /^(loop|ram|sr)/ {if($a+0>m){m=$a+0; d=$1}} END{if(d!="") printf "%.2f", m}')"
    maxawaitdev="$(iostat -xz 1 2 2>/dev/null | awk '/^Device/ {for(i=1;i<=NF;i++) if($i=="await") a=i; next} a && NF>=a && $1!="" && $1 !~ /^(loop|ram|sr)/ {if($a+0>m){m=$a+0; d=$1}} END{print d}')"
    if [[ -n "${maxawait}" ]]; then STORAGE_LATENCY_STATUS="${maxawaitdev} await=${maxawait}ms (best-effort)"; else STORAGE_LATENCY_STATUS="não foi possível determinar"; fi
  else
    STORAGE_LATENCY_STATUS="iostat não disponível (instale sysstat para enriquecer este bloco)"
  fi

  first_error="$(head -n 1 "${ERROS_OUT}" 2>/dev/null || true)"
  if [[ "${oom_count}" -gt 0 && -n "${OOM_FIRST_CLUE}" ]]; then
    MAIN_CLUE="${OOM_FIRST_CLUE}"
  elif [[ "${failed_units_count}" -gt 0 && "${FAILED_UNITS_LIST}" != "nenhuma" ]]; then
    MAIN_CLUE="Unidades com falha detectadas: ${FAILED_UNITS_LIST}"
  elif [[ "${PORT_FAIL_COUNT}" -gt 0 && "${FAILED_PORTS_SUMMARY}" != "nenhuma" ]]; then
    MAIN_CLUE="Portas com falha detectadas: ${FAILED_PORTS_SUMMARY}"
  else
    MAIN_CLUE="$(first_nonempty       "$(grep -Eim1 'connection refused|unreachable|temporary failure in name resolution|name or service not known|reset by peer' "${SYSTEMD_INFO_OUT}" 2>/dev/null || true)"       "$(grep -Eim1 'connection refused|unreachable|temporary failure in name resolution|name or service not known|reset by peer' "${ERROS_OUT}" 2>/dev/null || true)"       "$(grep -Eim1 'failed to start|failed with result|service failed|entered failed state' "${SYSTEMD_INFO_OUT}" 2>/dev/null || true)"       "$(grep -Eim1 'timeout|timed out|failed|no space left|i/o error|segfault|panic' "${ERROS_OUT}" 2>/dev/null || true)"       "${LAST_POWER_REASON}"       "${first_error}"       "Nenhum indício forte capturado automaticamente")"
  fi
}

write_json_summary() {
  if ! cmd_exists python3; then echo '{"json_status": "python3 não disponível"}' > "${JSON_OUT}"; return 0; fi
  env \
    VERSION="${VERSION}" BUILD_DATE="${BUILD_DATE}" PROFILE_REQUESTED="${PROFILE}" PROFILE_RESOLVED="${PROFILE_RESOLVED}" COLETA="${COLETA}" \
    ANALYST_NAME="${ANALYST_NAME}" EXEC_USER="${EXEC_USER}" EXEC_UID="${EXEC_UID}" \
    HOSTNAME_SHORT="${HOSTNAME_SHORT}" HOSTNAME_FQDN="${HOSTNAME_FQDN}" HOST_IPV4="${HOST_IPV4}" HOST_IPV6="${HOST_IPV6}" \
    OS_PRETTY="${OS_PRETTY}" KERNEL_INFO="${KERNEL_INFO}" UPTIME_INFO="${UPTIME_INFO}" TIMEZONE_INFO="${TIMEZONE_INFO}" CURRENT_TIME_INFO="${CURRENT_TIME_INFO}" SINCE_DISPLAY="${SINCE_DISPLAY}" UNTIL_DISPLAY="${UNTIL_DISPLAY}" \
    IS_PROXMOX_NODE="${IS_PROXMOX_NODE}" EXECUTION_CONTEXT="${EXECUTION_CONTEXT}" VIRT_TECH="${VIRT_TECH}" VIRT_STACK="${VIRT_STACK}" HOST_ROLE="${HOST_ROLE}" HYPERVISOR_CONTEXT="${HYPERVISOR_CONTEXT}" \
    HW_VENDOR="${HW_VENDOR}" HW_PRODUCT="${HW_PRODUCT}" HW_VERSION="${HW_VERSION}" SINCE="${SINCE}" UNTIL="${UNTIL}" APP_NAME="${APP_NAME:-}" CASE_ID="${CASE_ID:-}" OUTDIR="${OUTDIR}" UNIT_FILTER="${UNIT_FILTER:-}" EXTRA_REGEX="${EXTRA_REGEX:-}" PORT_SCOPE_DESC="${PORT_SCOPE_DESC}" \
    LAST_LOGIN_USER="${LAST_LOGIN_USER}" LAST_LOGIN_DURATION="${LAST_LOGIN_DURATION}" LAST_POWER_TYPE="${LAST_POWER_TYPE}" LAST_POWER_REASON="${LAST_POWER_REASON}" LAST_POWER_ACTOR="${LAST_POWER_ACTOR}" \
    CPU_STATUS="${CPU_STATUS}" MEM_STATUS="${MEM_STATUS}" DISK_STATUS="${DISK_STATUS}" INODE_STATUS="${INODE_STATUS}" FAILED_UNITS_STATUS="${FAILED_UNITS_STATUS}" PORT_STATUS="${PORT_STATUS}" MAIN_CLUE="${MAIN_CLUE}" WINDOW_WARNING="${WINDOW_WARNING}" FAILED_UNITS_LIST="${FAILED_UNITS_LIST}" FAILED_PORTS_SUMMARY="${FAILED_PORTS_SUMMARY}" \
    OOM_STATUS="${OOM_STATUS}" SWAP_PRESSURE_STATUS="${SWAP_PRESSURE_STATUS}" IOWAIT_STATUS="${IOWAIT_STATUS}" STORAGE_LATENCY_STATUS="${STORAGE_LATENCY_STATUS}" CRITICAL_FS_SUMMARY="${CRITICAL_FS_SUMMARY}" CRITICAL_INODE_SUMMARY="${CRITICAL_INODE_SUMMARY}" TESTED_PORTS_SUMMARY="${TESTED_PORTS_SUMMARY}" \
    python3 - <<'PY' > "${JSON_OUT}"
import json, os
keys = [
"VERSION","BUILD_DATE","PROFILE_REQUESTED","PROFILE_RESOLVED","COLETA","ANALYST_NAME","EXEC_USER","EXEC_UID",
"HOSTNAME_SHORT","HOSTNAME_FQDN","HOST_IPV4","HOST_IPV6","OS_PRETTY","KERNEL_INFO","UPTIME_INFO","TIMEZONE_INFO","CURRENT_TIME_INFO","SINCE_DISPLAY","UNTIL_DISPLAY",
"IS_PROXMOX_NODE","EXECUTION_CONTEXT","VIRT_TECH","VIRT_STACK","HOST_ROLE","HYPERVISOR_CONTEXT","HW_VENDOR","HW_PRODUCT","HW_VERSION",
"SINCE","UNTIL","APP_NAME","CASE_ID","OUTDIR","UNIT_FILTER","EXTRA_REGEX","PORT_SCOPE_DESC",
"LAST_LOGIN_USER","LAST_LOGIN_DURATION","LAST_POWER_TYPE","LAST_POWER_REASON","LAST_POWER_ACTOR",
"CPU_STATUS","MEM_STATUS","DISK_STATUS","INODE_STATUS","FAILED_UNITS_STATUS","FAILED_UNITS_LIST","PORT_STATUS","FAILED_PORTS_SUMMARY","MAIN_CLUE","WINDOW_WARNING",
"OOM_STATUS","SWAP_PRESSURE_STATUS","IOWAIT_STATUS","STORAGE_LATENCY_STATUS","CRITICAL_FS_SUMMARY","CRITICAL_INODE_SUMMARY","TESTED_PORTS_SUMMARY"
]
print(json.dumps({k.lower(): os.environ.get(k, '') for k in keys}, ensure_ascii=False, indent=2))
PY
}

collect_host_identity
detect_virtualization_context

if [[ "${MODE_MENSAL}" != "1" && "${NON_INTERACTIVE}" != "1" ]]; then
  if [[ -z "${ANALYST_NAME}" ]]; then
    read -rp ">>> Nome do analista que está executando o script: " ANALYST_NAME
    [[ -z "${ANALYST_NAME}" ]] && confirm_continue_without_analyst
  fi
fi

if [[ "${MODE_MENSAL}" == "1" ]]; then
  START_MONTH="$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m-%d)"
  END_MONTH="$(date -d "${START_MONTH} +1 month -1 day" +%Y-%m-%d)"
  SINCE="${START_MONTH} 00:00:00"
  UNTIL="${END_MONTH} 23:59:59"
  info "Modo mensal ativado: janela ${SINCE} → ${UNTIL}"
else
  if [[ -z "${SINCE}" && -z "${HOURS}" ]]; then
    if [[ "${NON_INTERACTIVE}" == "1" ]]; then
      set_default_last_24h
    else
      read -rp ">>> INÍCIO do incidente (YYYY-MM-DD HH:MM) ou ENTER para usar as últimas 24 horas: " SINCE
      if [[ -z "${SINCE}" ]]; then
        set_default_last_24h
      else
        read -rp ">>> FIM do incidente (YYYY-MM-DD HH:MM) ou ENTER para agora: " UNTIL
        if [[ -z "${UNTIL}" ]]; then
          read -rp ">>> (Opcional) Duração em minutos. ENTER para usar a hora atual como fim: " DURATION_MIN
          [[ -z "${DURATION_MIN}" ]] && UNTIL="now"
        fi
      fi
    fi
  fi

  if [[ -n "${HOURS}" && -z "${SINCE}" ]]; then
    if [[ "${HOURS}" =~ ^[0-9]+$ ]]; then
      SINCE="${HOURS} hours ago"
      UNTIL="now"
    else
      warn "Valor inválido em --hours. Aplicando fallback para as últimas 24 horas."
      set_default_last_24h
    fi
  fi

  if [[ -n "${SINCE}" && -n "${DURATION_MIN}" && -z "${UNTIL}" ]]; then
    if [[ "${DURATION_MIN}" =~ ^[0-9]+$ ]]; then
      UNTIL="$(date -d "$(normalize_ts "${SINCE}") + ${DURATION_MIN} minutes" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || true)"
      [[ -n "${UNTIL}" ]] || UNTIL="now"
    else
      warn "Duração inválida informada. Considerando a hora atual como fim da janela."
      UNTIL="now"
    fi
  fi

  [[ -n "${SINCE}" ]] || set_default_last_24h
  [[ -n "${UNTIL}" ]] || UNTIL="now"

  SINCE="$(normalize_ts "${SINCE}")"
  UNTIL="$(normalize_ts "${UNTIL}")"

  if ! validate_ts "${SINCE}" || ! validate_ts "${UNTIL}"; then
    warn "Data/hora inválida informada. Aplicando fallback para as últimas 24 horas."
    set_default_last_24h
    SINCE="$(normalize_ts "${SINCE}")"
    UNTIL="$(normalize_ts "${UNTIL}")"
  fi
fi

if [[ "${MODE_MENSAL}" != "1" && "${NON_INTERACTIVE}" != "1" ]]; then
  read -rp ">>> (Opcional) Aplicação impactada (ex: IBM ACE, IIS, Nginx, etc.): " APP_NAME
  read -rp ">>> Nº do chamado/incidente (ENTER para pular): " CASE_ID
  CASE_ID="$(echo "${CASE_ID}" | tr -d '[:space:]' | tr -cd '[:alnum:]_-')"
  read -rp ">>> Unidade systemd para filtrar (ex: myservice.service) ou ENTER para todas: " UNIT_FILTER
  read -rp ">>> Checagem de Portas de rede específicas (como 7840, 7840,443) ou todas as portas disponíveis? Pressione ENTER para todas: " PORT_LIST
fi

[[ -n "${ANALYST_NAME}" ]] || ANALYST_NAME="não informado"

s_since="$(ts_to_epoch "${SINCE}" 2>/dev/null || echo '')"
s_until="$(ts_to_epoch "${UNTIL}" 2>/dev/null || echo '')"
if [[ -n "${s_since}" && -n "${s_until}" && "${s_since}" -gt "${s_until}" ]]; then info "Início (${SINCE}) é posterior ao fim (${UNTIL}); invertendo."; tmp="${SINCE}"; SINCE="${UNTIL}"; UNTIL="${tmp}"; s_since="$(ts_to_epoch "${SINCE}" 2>/dev/null || echo '')"; s_until="$(ts_to_epoch "${UNTIL}" 2>/dev/null || echo '')"; fi

if [[ -n "${s_since}" && -n "${s_until}" ]]; then
  window_seconds=$((s_until - s_since))
  if [[ "${window_seconds}" -gt 604800 ]]; then
    WINDOW_WARNING="[AVISO] A janela de tempo solicitada é grande e pode aumentar consideravelmente o tempo de execução e o volume de saída."
    warn "A janela de tempo solicitada é grande e pode aumentar consideravelmente o tempo de execução e o volume de saída."
  fi
fi
if [[ "${WINDOW_WARNING}" != "nenhum" ]]; then
  WINDOW_WARNING_LINE="${WINDOW_WARNING}"
else
  WINDOW_WARNING_LINE=""
fi

SINCE_DISPLAY="$(date -d "${SINCE}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "${SINCE}")"
UNTIL_DISPLAY="$(date -d "${UNTIL}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "${UNTIL}")"

STAMP_A="$(ts_to_stamp "${SINCE}")"; STAMP_B="$(ts_to_stamp "${UNTIL}")"; NOW_TAG="$(date +'%Y%m%d_%H%M' 2>/dev/null || echo now)"
if [[ -z "${OUTDIR}" ]]; then
  if [[ -n "${CASE_ID}" ]]; then OUTDIR="/tmp/analise-incidente-${CASE_ID}"; else OUTDIR="/tmp/analise-incidente-${NOW_TAG}"; fi
fi
mkdir -p "${OUTDIR}"
if [[ -z "${REPORT}" ]]; then
  if [[ -n "${CASE_ID}" ]]; then REPORT="${OUTDIR}/analise-${CASE_ID}-${STAMP_A}-${STAMP_B}.log"; JSON_OUT="${OUTDIR}/analise-${CASE_ID}-${STAMP_A}-${STAMP_B}.json";
  else REPORT="${OUTDIR}/analise-${STAMP_A}-${STAMP_B}.log"; JSON_OUT="${OUTDIR}/analise-${STAMP_A}-${STAMP_B}.json"; fi
else JSON_OUT="${REPORT%.*}.json"; fi

JOURNAL_OUT="${OUTDIR}/journal_${STAMP_A}_${STAMP_B}.log"
ERROS_OUT="${OUTDIR}/erros_${STAMP_A}_${STAMP_B}.log"
DMESG_KILLED="${OUTDIR}/dmesg_killed_${STAMP_B}.log"
VARLOG_OOM="${OUTDIR}/varlog_oom_${STAMP_B}.log"
NETSTAT_ERR="${OUTDIR}/netstat_err_${STAMP_B}.log"
DMESG_TAIL="${OUTDIR}/dmesg_tail_${STAMP_B}.log"
PORT_CHECK="${OUTDIR}/ports_${STAMP_B}.log"
LISTENING_INFO_OUT="${OUTDIR}/servicos_escuta_${STAMP_B}.log"
LOGIN_INFO_OUT="${OUTDIR}/ultimos_logins_${STAMP_B}.log"
POWER_EVENT_OUT="${OUTDIR}/ultimo_evento_energia_${STAMP_B}.log"
TIME_INFO_OUT="${OUTDIR}/tempo_${STAMP_B}.log"
MEM_INFO_OUT="${OUTDIR}/memoria_${STAMP_B}.log"
STORAGE_INFO_OUT="${OUTDIR}/storage_${STAMP_B}.log"
PERF_INFO_OUT="${OUTDIR}/performance_${STAMP_B}.log"
SYSTEMD_INFO_OUT="${OUTDIR}/systemd_${STAMP_B}.log"
NETWORK_INFO_OUT="${OUTDIR}/network_${STAMP_B}.log"
CHANGES_INFO_OUT="${OUTDIR}/mudancas_${STAMP_B}.log"
VIRT_HOST_INFO_OUT="${OUTDIR}/virt_host_${STAMP_B}.log"
TIMELINE_OUT="${OUTDIR}/timeline_${STAMP_B}.log"

info "Perfil resolvido: ${PROFILE_RESOLVED}"
info "Função do host: ${HOST_ROLE}"
info "Contexto de execução: ${EXECUTION_CONTEXT}"
info "Stack detectada: ${VIRT_STACK}"
info "Analista responsável: ${ANALYST_NAME}"
info "Janela: SINCE='${SINCE}' UNTIL='${UNTIL}'"
[[ -n "${UNIT_FILTER}" ]] && info "Unit: ${UNIT_FILTER}"
[[ -n "${EXTRA_REGEX}" ]] && info "Regex: ${EXTRA_REGEX}"
[[ -n "${APP_NAME}" ]] && info "Aplicação: ${APP_NAME}"
[[ -n "${CASE_ID}" ]] && info "Chamado: ${CASE_ID}"
info "Saída: ${OUTDIR}"
info "Relatório: ${REPORT}"
info "JSON: ${JSON_OUT}"

if ! cmd_exists journalctl; then err "journalctl não encontrado. Este script requer systemd."; exit 1; fi
BASE_ERR_RE="error|fail|oom|killed|panic|hung|not responding|timeout|timed out|segfault|no space left|i/o error|connection refused"
FULL_RE="${BASE_ERR_RE}"; [[ -n "${EXTRA_REGEX}" ]] && FULL_RE="(${BASE_ERR_RE}|${EXTRA_REGEX})"

info "Exportando journal..."
if [[ -n "${UNIT_FILTER}" ]]; then run_priv journalctl --no-pager -u "${UNIT_FILTER}" --since "${SINCE}" --until "${UNTIL}" > "${JOURNAL_OUT}" || { err "journalctl -u falhou."; exit 1; }
else run_priv journalctl --no-pager --since "${SINCE}" --until "${UNTIL}" > "${JOURNAL_OUT}" || { err "journalctl falhou."; exit 1; }
fi

info "Filtrando erros/alertas (${FULL_RE}) ..."
grep -Ei "${FULL_RE}" "${JOURNAL_OUT}" > "${ERROS_OUT}" || true

info "Executando verificações do host ..."
run_priv dmesg | grep -i "killed process" > "${DMESG_KILLED}" || true
if [[ -f /var/log/messages ]]; then grep -i "Out of memory" /var/log/messages > "${VARLOG_OOM}" || true
elif [[ -f /var/log/syslog ]]; then grep -i "Out of memory" /var/log/syslog > "${VARLOG_OOM}" || true
else echo "(sem /var/log/messages e sem /var/log/syslog)" > "${VARLOG_OOM}"; fi
if cmd_exists netstat; then run_priv netstat -s | grep -E "error|fail|retransmit|dropped|timeouts" > "${NETSTAT_ERR}" || true
else echo "(netstat não encontrado; usando 'ss -s')" > "${NETSTAT_ERR}"; cmd_exists ss && ss -s >> "${NETSTAT_ERR}" || true; fi
run_priv dmesg | tail -n 50 > "${DMESG_TAIL}" || true

info "Coletando contexto do host ..."
collect_timing_info
collect_memory_info
collect_storage_info
collect_perf_info
collect_systemd_info
collect_network_info
if [[ "${COLETA}" != "leve" ]]; then collect_recent_changes; else echo "(coleta leve: bloco de mudanças recentes não executado)" > "${CHANGES_INFO_OUT}"; fi

info "Coletando informações de login ..."
collect_last_login_info
info "Coletando informações do último evento de energia ..."
collect_last_power_event_info
info "Montando timeline do incidente ..."
collect_timeline_info

if [[ "${PROFILE_RESOLVED}" == "virt-host" ]]; then info "Coletando informações de host de virtualização ..."; collect_virt_host_info
else echo "(perfil ${PROFILE_RESOLVED}: bloco virt-host não executado)" > "${VIRT_HOST_INFO_OUT}"; fi

resolve_ports "${PORT_LIST}"
info "Validando portas ..."
PORT_FAIL_COUNT=0; PORT_OK_COUNT=0; FAILED_PORTS=()
{
  echo "==== Validação de Portas ($(date)) ===="
  echo "Escopo de checagem: ${PORT_SCOPE_DESC}"
  echo
  echo "-- Serviços em escuta (ss -tulpen) --"; cmd_exists ss && run_priv ss -tulpen || echo "(ss não encontrado)"
  echo
  echo "-- Serviços em escuta (lsof -i) --"; cmd_exists lsof && run_priv lsof -nP -i || echo "(lsof não encontrado)"
  echo
  echo "-- Portas TCP selecionadas para teste ativo --"
  if [[ "${#PORTS[@]}" -gt 0 ]]; then printf '%s\n' "${PORTS[@]}"; else echo "(nenhuma porta disponível para teste ativo)"; fi
  if [[ "${#PORTS[@]}" -gt 0 ]]; then
    echo; echo "-- Testes de conexão (localhost) --"
    for p in "${PORTS[@]}"; do
      [[ -z "${p}" ]] && continue
      printf "Porta %s: " "${p}"
      if cmd_exists nc; then
        if nc -vz -w2 127.0.0.1 "${p}" >/dev/null 2>&1; then echo "OK (conectou)"; PORT_OK_COUNT=$((PORT_OK_COUNT + 1)); else echo "FALHA (não conectou)"; PORT_FAIL_COUNT=$((PORT_FAIL_COUNT + 1)); FAILED_PORTS+=("${p}"); fi
      else
        if (echo >/dev/tcp/127.0.0.1/"${p}") >/dev/null 2>&1; then echo "OK (/dev/tcp)"; PORT_OK_COUNT=$((PORT_OK_COUNT + 1)); else echo "FALHA (/dev/tcp)"; PORT_FAIL_COUNT=$((PORT_FAIL_COUNT + 1)); FAILED_PORTS+=("${p}"); fi
      fi
      if [[ "${p}" == "80" || "${p}" == "8080" || "${p}" == "443" || "${p}" == "7840" ]]; then cmd_exists curl && { echo "  curl HEAD http://127.0.0.1:${p} (timeout 2s):"; curl -I --max-time 2 -s "http://127.0.0.1:${p}" || true; }; fi
    done
  fi
} > "${PORT_CHECK}" 2>&1 || true

if [[ "${#FAILED_PORTS[@]}" -gt 0 ]]; then FAILED_PORTS_SUMMARY="$(IFS=", "; echo "${FAILED_PORTS[*]}")"; else FAILED_PORTS_SUMMARY="nenhuma"; fi

set +e
collect_listening_services_info
RC_LISTENING=$?
build_executive_summary
RC_SUMMARY=$?
write_json_summary
RC_JSON=$?
set -e

if [[ ${RC_LISTENING} -ne 0 ]]; then
  warn "Falha ao consolidar serviços em escuta. O script continuará com os dados coletados."
  [[ -f "${LISTENING_INFO_OUT}" ]] || echo "(falha ao consolidar serviços em escuta)" > "${LISTENING_INFO_OUT}"
fi

if [[ ${RC_SUMMARY} -ne 0 ]]; then
  warn "Falha ao montar o resumo executivo. O script continuará com os dados brutos coletados."
fi

if [[ ${RC_JSON} -ne 0 ]]; then
  warn "Falha ao gerar o resumo JSON. Será criado um arquivo mínimo de contingência."
  cat > "${JSON_OUT}" <<EOF2
{
  "json_status": "falha ao gerar resumo completo; arquivo de contingência criado",
  "version": "${VERSION}",
  "outdir": "${OUTDIR}",
  "report": "${REPORT}"
}
EOF2
fi

info "Gerando relatório ..."
cat > "${REPORT}" <<EOF2
Relatório de Evidência – Incidente
Versão: ${VERSION}  (Build: ${BUILD_DATE})
Gerado em: $(date)
Perfil solicitado: ${PROFILE}
Perfil resolvido: ${PROFILE_RESOLVED}
Nível de coleta: ${COLETA}

[Responsável pela execução]
Analista responsável: ${ANALYST_NAME}
Usuário Linux executor: ${EXEC_USER}
UID do executor: ${EXEC_UID}

[Identidade do host]
Host analisado: ${HOSTNAME_SHORT}
FQDN: ${HOSTNAME_FQDN}
IPv4(s): ${HOST_IPV4}
IPv6(s): ${HOST_IPV6}
Sistema operacional: ${OS_PRETTY}
Kernel: ${KERNEL_INFO}
Uptime: ${UPTIME_INFO}
Timezone: ${TIMEZONE_INFO}
Hora atual do host: ${CURRENT_TIME_INFO}

[Contexto de virtualização]
Função do host: ${HOST_ROLE}
É um host hypervisor/plataforma de virtualização?: ${HYPERVISOR_CONTEXT}
Contexto de execução: ${EXECUTION_CONTEXT}
Tecnologia detectada: ${VIRT_TECH}
Pilha detectada: ${VIRT_STACK}
Fabricante: ${HW_VENDOR}
Modelo: ${HW_PRODUCT}
Versão do produto: ${HW_VERSION}

[Janela analisada]
Janela analisada: ${SINCE_DISPLAY} → ${UNTIL_DISPLAY}
Aplicação: ${APP_NAME:-(não informada)}
Identificador do incidente: ${CASE_ID:-(não informado)}
Local de armazenamento: ${OUTDIR}
Unit filtrada: ${UNIT_FILTER:-(todas)}
Regex extra: ${EXTRA_REGEX:-(nenhuma)}
Escopo da checagem de portas: ${PORT_SCOPE_DESC}
${WINDOW_WARNING_LINE}

[Resumo executivo]
CPU: ${CPU_STATUS}
Memória: ${MEM_STATUS}
Swap pressure: ${SWAP_PRESSURE_STATUS}
Disco: ${DISK_STATUS}
Filesystems operacionais >= 90%: ${CRITICAL_FS_SUMMARY}
Inodes operacionais >= 90%: ${CRITICAL_INODE_SUMMARY}
I/O wait: ${IOWAIT_STATUS}
Latência de storage: ${STORAGE_LATENCY_STATUS}
OOM killer / OOM correlacionado: ${OOM_STATUS}
Services com falha: ${FAILED_UNITS_STATUS}
Units falhas (resumo): ${FAILED_UNITS_LIST}
Portas: ${PORT_STATUS}
Portas com falha: ${FAILED_PORTS_SUMMARY}
Portas testadas: ${TESTED_PORTS_SUMMARY}
Serviços em escuta (resumo): ${LISTENING_SERVICES_SUMMARY}
Indício principal: ${MAIN_CLUE}

[Resumo de disponibilidade e carga]
$(uptime 2>/dev/null || true)

[TOP 10 processos por CPU]
$(ps -eo pid,comm,%cpu,%mem,etime --sort=-%cpu 2>/dev/null | awk 'NR==1 || $2 !~ /^(ps|grep|head|sed|awk|bash|sh)$/ {print}' | head -n 11 || true)

[TOP 10 processos por MEMÓRIA]
$(ps -eo pid,comm,%mem,%cpu,etime --sort=-%mem 2>/dev/null | awk 'NR==1 || $2 !~ /^(ps|grep|head|sed|awk|bash|sh)$/ {print}' | head -n 11 || true)

[Últimos 10 usuários logados]
Usuário mais recente: ${LAST_LOGIN_USER}
Duração da sessão mais recente: ${LAST_LOGIN_DURATION}

$(cat "${LOGIN_INFO_OUT}" 2>/dev/null || true)

[Último desligamento ou reboot do host]
Tipo do último evento: ${LAST_POWER_TYPE}
Registro bruto:
${LAST_POWER_LINE:-"(não encontrado)"}

Motivo (best-effort):
${LAST_POWER_REASON:-"(não encontrado)"}

Possível responsável (best-effort):
${LAST_POWER_ACTOR:-"(não encontrado)"}

Observação:
Motivo e responsável nem sempre ficam registrados de forma confiável no Linux.

[Timeline do incidente]
(veja detalhes em: ${TIMELINE_OUT})
$(sed -n '1,120p' "${TIMELINE_OUT}" 2>/dev/null || true)

[Erros e falhas no sistema (últimas 80 linhas do filtro aplicado)]
$(tail -n 80 "${ERROS_OUT}" 2>/dev/null || true)

[Uso de disco]
$(df -hP 2>/dev/null || true)

[Uso de inodes]
$(df -hiP 2>/dev/null || true)

[Kernel logs recentes]
$(run_priv dmesg 2>/dev/null | tail -n 30 || true)

[Teste de Portas]
(veja detalhes em: ${PORT_CHECK})
$(sed -n '1,120p' "${PORT_CHECK}" 2>/dev/null || true)

[Serviços em escuta]
(veja detalhes em: ${LISTENING_INFO_OUT})
$(sed -n '1,60p' "${LISTENING_INFO_OUT}" 2>/dev/null || true)

[Referências de arquivos de evidência]
- Dump do journal:             ${JOURNAL_OUT}
- Erros/alertas filtrados:     ${ERROS_OUT}
- dmesg (killed process):      ${DMESG_KILLED}
- Logs OOM:                    ${VARLOG_OOM}
- Rede (erros/falhas):         ${NETSTAT_ERR}
- Kernel (últimas linhas):     ${DMESG_TAIL}
- Teste de portas:             ${PORT_CHECK}
- Serviços em escuta:          ${LISTENING_INFO_OUT}
- Últimos logins:              ${LOGIN_INFO_OUT}
- Último evento energia:       ${POWER_EVENT_OUT}
- Timeline do incidente:       ${TIMELINE_OUT}
- Contexto de tempo:           ${TIME_INFO_OUT}
- Memória e swap:              ${MEM_INFO_OUT}
- Storage / filesystems:       ${STORAGE_INFO_OUT}
- Performance / IO:            ${PERF_INFO_OUT}
- Services / systemd:          ${SYSTEMD_INFO_OUT}
- Rede detalhada:              ${NETWORK_INFO_OUT}
- Mudanças recentes:           ${CHANGES_INFO_OUT}
- Host de virtualização:       ${VIRT_HOST_INFO_OUT}
- Resumo estruturado JSON:     ${JSON_OUT}

[Guia rápido dos arquivos de evidência]
- Relatório principal:         ${REPORT}
- Resumo estruturado JSON:     ${JSON_OUT}
- Arquivo bruto (Journal):     ${JOURNAL_OUT}
- Arquivo de alertas filtrados:${ERROS_OUT}
- Kernel matou processos:      ${DMESG_KILLED}
- Out of memory:               ${VARLOG_OOM}
- Estatísticas de rede:        ${NETSTAT_ERR}
- Últimos eventos kernel:      ${DMESG_TAIL}
- Teste de portas:             ${PORT_CHECK}
- Serviços em escuta:          ${LISTENING_INFO_OUT}
- Últimos logins:              ${LOGIN_INFO_OUT}
- Último evento energia:       ${POWER_EVENT_OUT}
- Timeline do incidente:       ${TIMELINE_OUT}
- Tempo / NTP:                 ${TIME_INFO_OUT}
- Memória / Swap / PSI:        ${MEM_INFO_OUT}
- Discos / FS / Inodes:        ${STORAGE_INFO_OUT}
- Performance / IO / iostat:   ${PERF_INFO_OUT}
- Systemd / services:          ${SYSTEMD_INFO_OUT}
- Rede detalhada:              ${NETWORK_INFO_OUT}
- Mudanças recentes:           ${CHANGES_INFO_OUT}
- Perfil virt-host:            ${VIRT_HOST_INFO_OUT}

EOF2

say
info "Concluído. Relatório salvo em ${REPORT}"
info "Resumo JSON salvo em ${JSON_OUT}"
say "Arquivos no diretório ${OUTDIR}:"
for f in \
  "${REPORT}" "${JSON_OUT}" "${JOURNAL_OUT}" "${ERROS_OUT}" "${DMESG_KILLED}" \
  "${VARLOG_OOM}" "${NETSTAT_ERR}" "${DMESG_TAIL}" "${PORT_CHECK}" \
  "${LISTENING_INFO_OUT}" "${LOGIN_INFO_OUT}" "${POWER_EVENT_OUT}" "${TIMELINE_OUT}" \
  "${TIME_INFO_OUT}" "${MEM_INFO_OUT}" "${STORAGE_INFO_OUT}" "${PERF_INFO_OUT}" \
  "${SYSTEMD_INFO_OUT}" "${NETWORK_INFO_OUT}" "${CHANGES_INFO_OUT}" "${VIRT_HOST_INFO_OUT}"; do
  printf " - %s\n" "$(basename -- "$f")"
done

print_closing_message
