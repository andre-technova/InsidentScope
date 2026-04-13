[CmdletBinding()]
param(
    [switch]$Monthly,
    [string]$Since,
    [string]$Until,
    [int]$DurationMinutes,
    [Alias('H')]
    [int]$Hours,
    [string]$App,
    [string]$CaseId,
    [string]$Analyst,
    [string]$OutDir,
    [string]$Unit,
    [string]$Regex,
    [string]$Port = '',
    [ValidateSet('Auto','Generic','Virt-Host')]
    [string]$Profile = 'Auto',
    [ValidateSet('Light','Standard','Detailed')]
    [string]$CollectionLevel = 'Standard',
    [switch]$ProfileAuto,
    [switch]$ProfileGeneric,
    [switch]$ProfileVirtHost,
    [switch]$CollectionLight,
    [switch]$CollectionStandard,
    [switch]$CollectionDetailed,
    [switch]$Manual,
    [switch]$NonInteractive,
    [int]$LogonMaxEvents = 200,
    [int]$EventCapPerLog = 0
)

$script:Version = '2.3.12-windows-based'
$script:BuildDate = '2026-04-09'
$script:ToolName = 'Technova IncidentScope'
$script:ErrorActionPreference = 'Stop'
$script:Messages = $null
$script:Lang = 'en'
$script:IsAdmin = $false
$script:ProfileResolved = ''
$script:DetectedExecutionContext = 'physical'
$script:VirtTech = 'none'
$script:VirtStack = 'none'
$script:HostRole = 'generic windows host'
$script:HypervisorContext = 'no'
$script:WindowWarning = 'none'
$script:MainClue = 'not identified'
$script:InputMonthly = $false
$script:InputSince = ''
$script:InputUntil = ''
$script:InputHours = 0
$script:InputDurationMinutes = 0
$script:InteractiveStartDT = $null
$script:InteractiveEndDT = $null
$script:AdminSid = 'S-1-5-32-544'
$script:Report = $null
$script:JsonOut = $null
$script:StampBase = $null
$script:EvidenceFiles = [ordered]@{}
$script:CollectionStatus = [ordered]@{}
$script:BaseErrorRegex = 'error|fail|failed|timeout|timed out|refused|dns|disk|ntfs|reset|reboot|shutdown|crash|critical|panic|unreachable|resource-exhaustion|out of memory|oom|service control manager'
$script:FullErrorRegex = $script:BaseErrorRegex
$script:SpinnerChars = @('|','/','-','\\')
$script:SpinnerIndex = 0

function Initialize-Localization {
    $script:Lang = 'en'
    try {
        $name = [System.Globalization.CultureInfo]::InstalledUICulture.Name
        if ($name -match '^pt') { $script:Lang = 'pt' }
        elseif ($name -match '^es') { $script:Lang = 'es' }
    } catch { $script:Lang = 'en' }

    $catalog = @{
        en = @{
            Info='INFO'; Warn='WARN'; Error='ERROR'
            ContinuePrompt='Press ENTER to continue or Ctrl+C to cancel.'
            ContinueWithoutAnalyst='Analyst name not provided. Continue anyway? [y/n]'
            Cancelled='Execution cancelled by the operator.'
            InvalidAnswer='Invalid answer. Type y or n.'
            DefaultLast24='No time window was provided. Automatically using the last 24 hours.'
            QuickHelp='Quick help'
            Help1='Use -Manual for extended documentation.'
            Help2='If no time window is informed in interactive mode, the script uses the last 24 hours.'
            Help3='You may use -Since/-Until, -Hours, -DurationMinutes or -Monthly.'
            Help4='Shortcut switches: -ProfileAuto, -ProfileGeneric, -ProfileVirtHost, -CollectionLight, -CollectionStandard, -CollectionDetailed. In interactive mode the script asks the same core questions in sequence, similar to the Linux flow.'
            Banner1='Structured evidence collection for unavailability'
            Banner2='and operational investigation in Windows environments'
            Version='Version'
            Disclaimer1='This is version 2.3.12-windows-based of Technova IncidentScope, developed by André Rodrigues for structured evidence collection for unavailability scenarios, operational investigation and technical incident analysis support in Windows environments.'
            Disclaimer2='This version was designed for Windows hosts using Windows PowerShell 5.1 and PowerShell 7+, with native cmdlets and Windows APIs whenever possible.'
            Disclaimer3='The script can collect host context, logs, memory, storage, network, services, ports, incident timeline, virtualization context and auxiliary files to support evidence correlation and technical analysis.'
            ManualTitle='EXTENDED MANUAL'
            Closing='The script execution has finished.'
            AdminPartial='The script is not running as Administrator. Some collections may be partial.'
            LargeWindow='Large time window detected; collection may take longer and generate more data.'
            HeadingExec='[Execution owner]'
            HeadingHost='[Host identity]'
            HeadingVirt='[Virtualization context]'
            HeadingWindow='[Analyzed window]'
            HeadingSummary='[Executive summary]'
            HeadingLogons='[Recent logons]'
            HeadingPower='[Last reboot or shutdown]'
            HeadingErrors='[Relevant errors and failures]'
            HeadingStorage='[Disk and storage]'
            HeadingMemory='[Memory, CPU and paging]'
            HeadingPorts='[Port checks]'
            HeadingRefs='[Evidence file references]'
            Na='not identified'
            NotInformed='not informed'
            None='none'
        }
        pt = @{
            Info='INFO'; Warn='AVISO'; Error='ERRO'
            ContinuePrompt='Pressione ENTER para continuar ou Ctrl+C para cancelar.'
            ContinueWithoutAnalyst='Nome do analista nao informado. Deseja prosseguir assim mesmo? [y/n]'
            Cancelled='Execucao cancelada pelo operador.'
            InvalidAnswer='Resposta invalida. Digite y ou n.'
            DefaultLast24='Nenhuma janela foi informada. Usando automaticamente as ultimas 24 horas.'
            QuickHelp='Ajuda rapida'
            Help1='Use -Manual para ver a documentacao estendida.'
            Help2='Se nenhuma janela for informada no modo interativo, o script usa as ultimas 24 horas.'
            Help3='Voce pode usar -Since/-Until, -Hours, -DurationMinutes ou -Monthly.'
            Help4='Atalhos: -ProfileAuto, -ProfileGeneric, -ProfileVirtHost, -CollectionLight, -CollectionStandard, -CollectionDetailed. No modo interativo o script pergunta os mesmos campos principais em sequencia, semelhante ao fluxo Linux.'
            Banner1='Coleta estruturada de evidencias para indisponibilidade'
            Banner2='e investigacao operacional em ambientes Windows'
            Version='Versao'
            Disclaimer1='Esta e a versao 2.3.12-windows-based do Technova IncidentScope, desenvolvida por André Rodrigues para coleta estruturada de evidencias de indisponibilidade, investigacao operacional e apoio a analise tecnica de incidentes em ambientes Windows.'
            Disclaimer2='Esta versao foi pensada para hosts Windows com Windows PowerShell 5.1 e PowerShell 7+, usando cmdlets nativos e APIs do Windows sempre que possivel.'
            Disclaimer3='O script pode coletar contexto do host, logs, memoria, storage, rede, services, portas, timeline do incidente, contexto de virtualizacao e arquivos auxiliares para facilitar a analise e a correlacao de evidencias.'
            ManualTitle='MANUAL ESTENDIDO'
            Closing='A execucao do script foi concluida.'
            AdminPartial='O script nao esta em execucao como Administrador. Algumas coletas podem ser parciais.'
            LargeWindow='Janela de tempo grande detectada; a coleta pode levar mais tempo e gerar mais dados.'
            HeadingExec='[Responsavel pela execucao]'
            HeadingHost='[Identidade do host]'
            HeadingVirt='[Contexto de virtualizacao]'
            HeadingWindow='[Janela analisada]'
            HeadingSummary='[Resumo executivo]'
            HeadingLogons='[Logons recentes]'
            HeadingPower='[Ultimo reboot ou shutdown]'
            HeadingErrors='[Erros e falhas relevantes]'
            HeadingStorage='[Disco e storage]'
            HeadingMemory='[Memoria, CPU e paginacao]'
            HeadingPorts='[Teste de portas]'
            HeadingRefs='[Referencias dos arquivos de evidencia]'
            Na='nao identificado'
            NotInformed='nao informado'
            None='nenhum'
        }
        es = @{
            Info='INFO'; Warn='AVISO'; Error='ERROR'
            ContinuePrompt='Presione ENTER para continuar o Ctrl+C para cancelar.'
            ContinueWithoutAnalyst='Nombre del analista no informado. Desea continuar de todos modos? [y/n]'
            Cancelled='Ejecucion cancelada por el operador.'
            InvalidAnswer='Respuesta invalida. Escriba y o n.'
            DefaultLast24='No se informo una ventana de tiempo. Usando automaticamente las ultimas 24 horas.'
            QuickHelp='Ayuda rapida'
            Help1='Use -Manual para ver la documentacion extendida.'
            Help2='Si no se informa una ventana en modo interactivo, el script usa las ultimas 24 horas.'
            Help3='Puede usar -Since/-Until, -Hours, -DurationMinutes o -Monthly.'
            Help4='Atajos: -ProfileAuto, -ProfileGeneric, -ProfileVirtHost, -CollectionLight, -CollectionStandard, -CollectionDetailed. En modo interactivo el script pregunta los mismos campos principales en secuencia, similar al flujo Linux.'
            Banner1='Recoleccion estructurada de evidencias para indisponibilidad'
            Banner2='e investigacion operativa en entornos Windows'
            Version='Version'
            Disclaimer1='Esta es la version 2.3.12-windows-based de Technova IncidentScope, desarrollada por André Rodrigues para la recoleccion estructurada de evidencias de indisponibilidad, investigacion operativa y apoyo al analisis tecnico de incidentes en entornos Windows.'
            Disclaimer2='Esta version fue pensada para hosts Windows con Windows PowerShell 5.1 y PowerShell 7+, usando cmdlets nativos y APIs de Windows siempre que sea posible.'
            Disclaimer3='El script puede recopilar contexto del host, logs, memoria, storage, red, services, puertos, timeline del incidente, contexto de virtualizacion y archivos auxiliares para facilitar el analisis y la correlacion de evidencias.'
            ManualTitle='MANUAL EXTENDIDO'
            Closing='La ejecucion del script ha finalizado.'
            AdminPartial='El script no se esta ejecutando como Administrador. Algunas recolecciones pueden ser parciales.'
            LargeWindow='Se detecto una ventana de tiempo grande; la recoleccion puede tardar mas y generar mas datos.'
            HeadingExec='[Responsable de la ejecucion]'
            HeadingHost='[Identidad del host]'
            HeadingVirt='[Contexto de virtualizacion]'
            HeadingWindow='[Ventana analizada]'
            HeadingSummary='[Resumen ejecutivo]'
            HeadingLogons='[Inicios de sesion recientes]'
            HeadingPower='[Ultimo reinicio o apagado]'
            HeadingErrors='[Errores y fallas relevantes]'
            HeadingStorage='[Disco y storage]'
            HeadingMemory='[Memoria, CPU y paginacion]'
            HeadingPorts='[Prueba de puertos]'
            HeadingRefs='[Referencias de archivos de evidencia]'
            Na='no identificado'
            NotInformed='no informado'
            None='ninguno'
        }
    }
    $script:Messages = $catalog[$script:Lang]
}

function Write-Info([string]$Message) { Write-Host ("[{0}] {1}" -f $script:Messages.Info, $Message) -ForegroundColor Cyan }
function Write-WarnMsg([string]$Message) { Write-Host ("[{0}] {1}" -f $script:Messages.Warn, $Message) -ForegroundColor Yellow }
function Write-ErrMsg([string]$Message) { Write-Host ("[{0}] {1}" -f $script:Messages.Error, $Message) -ForegroundColor Red }
function Get-SpinnerMark {
    $mark = $script:SpinnerChars[$script:SpinnerIndex % $script:SpinnerChars.Count]
    $script:SpinnerIndex++
    return $mark
}
function Write-Step([string]$Message) {
    Write-Info $Message
}

function Get-AsciiBanner {
@'
████████╗███████╗ ██████╗██╗  ██╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
╚══██╔══╝██╔════╝██╔════╝██║  ██║████╗  ██║██╔═══██╗██║   ██║██╔══██╗
   ██║   █████╗  ██║     ███████║██╔██╗ ██║██║   ██║██║   ██║███████║
   ██║   ██╔══╝  ██║     ██╔══██║██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
   ██║   ███████╗╚██████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
'@
}

function Set-ConsoleUtf8 {
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    } catch {}
}

function Show-StartupBanner {
    try { Clear-Host } catch {}
    Write-Host (Get-AsciiBanner)
    Write-Host ''
    Write-Host '                          IncidentScope'
    Write-Host ' --------------------------------------------------------------------'
    Write-Host (" {0}" -f $script:Messages.Banner1)
    Write-Host (" {0}" -f $script:Messages.Banner2)
    Write-Host ' --------------------------------------------------------------------'
    Write-Host ("                           {0} {1}" -f $script:Messages.Version, $script:Version)
    Write-Host ''
}

function Show-StartupDisclaimer {
    Write-Host $script:Messages.Disclaimer1
    Write-Host ''
    Write-Host $script:Messages.Disclaimer2
    Write-Host ''
    Write-Host $script:Messages.Disclaimer3
    Write-Host ''
    if ($script:Lang -eq 'pt') {
        Write-Host 'Este script deve ser executado preferencialmente como Administrador.'
        Write-Host 'Para ajuda resumida, use -Help. Para documentacao detalhada, use -Manual.'
        Write-Host 'Se nenhuma janela de tempo for informada, o script usara automaticamente as ultimas 24 horas.'
        Write-Host 'Voce tambem pode definir a janela antes da execucao com -Since/-Until, -Hours, -DurationMinutes ou -Monthly.'
        Write-Host ''
        Write-Host 'Em caso de duvidas, sugestoes de melhoria ou necessidade de suporte,'
        Write-Host 'entre em contato pelo e-mail: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'Se o Technova IncidentScope agregou valor ao seu dia a dia,'
        Write-Host 'considere contribuir com qualquer valor via PIX: technova.sti@outlook.com :)'
    } elseif ($script:Lang -eq 'es') {
        Write-Host 'Este script debe ejecutarse preferentemente como Administrador.'
        Write-Host 'Para ayuda resumida, use -Help. Para documentacion detallada, use -Manual.'
        Write-Host 'Si no se informa una ventana de tiempo, el script usara automaticamente las ultimas 24 horas.'
        Write-Host 'Tambien puede definir la ventana antes de la ejecucion con -Since/-Until, -Hours, -DurationMinutes o -Monthly.'
        Write-Host ''
        Write-Host 'En caso de dudas, sugerencias de mejora o necesidad de soporte,'
        Write-Host 'contacte por correo electronico: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'Si Technova IncidentScope aporto valor a su rutina,'
        Write-Host 'considere contribuir con cualquier monto via PIX: technova.sti@outlook.com :)'
    } else {
        Write-Host 'This script should preferably be executed as Administrator.'
        Write-Host 'For quick help, use -Help. For detailed documentation, use -Manual.'
        Write-Host 'If no time window is informed, the script automatically uses the last 24 hours.'
        Write-Host 'You may also define the window before execution with -Since/-Until, -Hours, -DurationMinutes or -Monthly.'
        Write-Host ''
        Write-Host 'For questions, improvement suggestions or support needs,'
        Write-Host 'please contact: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'If Technova IncidentScope added value to your daily work,'
        Write-Host 'please consider contributing any amount via PIX: technova.sti@outlook.com :)'
    }
    Write-Host ''
    if (-not $NonInteractive) {
        Write-Host $script:Messages.ContinuePrompt
        [void](Read-Host)
    }
}

function Show-QuickGuidance {
    Write-Info $script:Messages.QuickHelp
    Write-Host (" - {0}" -f $script:Messages.Help1)
    Write-Host (" - {0}" -f $script:Messages.Help2)
    Write-Host (" - {0}" -f $script:Messages.Help3)
    Write-Host (" - {0}" -f $script:Messages.Help4)
    Write-Host ''
}

function Show-HelpText {
@"
Usage:
  .\incidentscope-2.3.12-windows-based.ps1 [-Monthly] [-Since "YYYY-MM-DD HH:MM"] [-Until "YYYY-MM-DD HH:MM"]
                                               [-DurationMinutes MINUTES] [-Hours HOURS]
                                               [-App APP_NAME] [-CaseId CASE_ID]
                                               [-Analyst "ANALYST NAME"]
                                               [-OutDir OUTDIR] [-Unit PROVIDER_OR_SERVICE]
                                               [-Regex EXTRA_REGEX] [-Port "P1,P2,...|all"]
                                               [-Profile Auto|Generic|Virt-Host]
                                               [-ProfileAuto|-ProfileGeneric|-ProfileVirtHost]
                                               [-CollectionLevel Light|Standard|Detailed]
                                               [-CollectionLight|-CollectionStandard|-CollectionDetailed]
                                               [-Manual] [-NonInteractive]

Main parameters:
  -Monthly             Analyze the previous full month
  -Since               Start of the window (YYYY-MM-DD HH:MM[:SS])
  -Until               End of the window
  -DurationMinutes     Duration in minutes starting from -Since
  -Hours / -H          Last N hours until now
  -App                 Impacted application
  -CaseId              Ticket or incident number
  -Analyst             Analyst responsible for execution
  -OutDir              Output directory
  -Unit                Filter log collection by provider/source/service text
  -Regex               Additional regex to enrich error filtering
  -Port                Specific ports (example: 80,443) or all
  -Profile             Auto | Generic | Virt-Host
  -CollectionLevel     Light | Standard | Detailed
  -LogonMaxEvents      Limits Security logon query volume (default: 200)
  -EventCapPerLog      Optional raw event cap per log; 0 disables the cap (default)
  -Manual              Show extended documentation
  -NonInteractive      Do not ask questions in the terminal

Examples:
  .\incidentscope-2.3.12-windows-based.ps1
  .\incidentscope-2.3.12-windows-based.ps1 -Hours 4 -Profile Auto -CollectionLevel Detailed -Analyst "Andre Rodrigues" -NonInteractive
  .\incidentscope-2.3.12-windows-based.ps1 -Since "2026-04-07 00:00" -Until "2026-04-07 23:59" -Port all -NonInteractive
  .\incidentscope-2.3.12-windows-based.ps1 -Monthly -CaseId INC-123456 -Profile Auto -CollectionLevel Standard
"@
}

function Show-ManualText {
@"
$($script:Messages.ManualTitle) - $($script:Version)

1. Objective
   This script generates a structured evidence package for Windows incident investigation.
   It supports physical hosts, VMs and virtualization hosts in best-effort mode.

2. Profile and collection level
   -Profile defines the environment assumption:
     Auto      -> detect automatically
     Generic   -> generic Windows host
     Virt-Host -> adds virtualization host evidence

   -CollectionLevel defines depth:
     Light     -> faster, fewer complementary blocks
     Standard  -> balance between speed and depth
     Detailed  -> more correlation, timeline and auxiliary data

3. Time window
   Supported modes:
   - Since/Until
   - Since + DurationMinutes
   - Hours
   - Monthly
   If no window is informed, the script automatically uses the last 24 hours.
   If Since has only a date, start of day is assumed.
   If Until has only a date, end of day is assumed.

4. Best-effort
   Some items depend on what Windows has already recorded:
   - reboot actor and reason
   - full logon history
   - resource exhaustion clues
   - storage latency over time
   - recent administrative changes

5. Main evidence blocks
   - Host identity
   - Virtualization context
   - Windows event logs and filtered errors
   - Services and SCM clues
   - Network, routes, DNS, listening ports, established connections
   - Memory, CPU, disks, volumes and page file
   - Recent logons and last reboot/shutdown
   - Recent changes and incident timeline
   - Human-readable report and structured JSON summary
"@
}

function Assert-AdministratorFlag {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        $script:IsAdmin = $false
    }
}

function Resolve-ShortcutParameters {
    if ($ProfileAuto) { $script:Profile = 'Auto' } else { $script:Profile = $Profile }
    if ($ProfileGeneric) { $script:Profile = 'Generic' }
    if ($ProfileVirtHost) { $script:Profile = 'Virt-Host' }

    if ($CollectionLight) { $script:Collection = 'Light' } else { $script:Collection = $CollectionLevel }
    if ($CollectionStandard) { $script:Collection = 'Standard' }
    if ($CollectionDetailed) { $script:Collection = 'Detailed' }
}


function Sanitize-TimeInput([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $clean = ($Value -replace '[^\d:/\-\s]', '').Trim()
    if ($clean -match '^[\s:/-]*$') { return '' }
    return $clean
}

function Test-TimeInputFormat([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($Value -match '^\d{4}-\d{2}-\d{2}$') { return $true }
    if ($Value -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(:\d{2})?$') { return $true }
    if ($Value -match '^\d{2}/\d{2}/\d{4}$') { return $true }
    if ($Value -match '^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}(:\d{2})?$') { return $true }
    if ($Value -match '^\d{4}/\d{2}/\d{2}$') { return $true }
    if ($Value -match '^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}(:\d{2})?$') { return $true }
    return $false
}

function Read-TimeInputLoop([string]$PromptText, [bool]$AllowBlank) {
    while ($true) {
        $raw = Read-Host $PromptText
        $clean = Sanitize-TimeInput $raw
        if ([string]::IsNullOrWhiteSpace($clean) -and $AllowBlank) { return '' }
        if (Test-TimeInputFormat $clean) { return $clean }
        Write-WarnMsg 'Formato invalido. Use YYYY-MM-DD HH:MM, YYYY-MM-DD, DD/MM/YYYY HH:MM ou pressione ENTER.'
    }
}

function Normalize-DateString([string]$Value, [string]$Kind) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = Sanitize-TimeInput $Value
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $null }

    $y = 0; $m = 0; $d = 0; $hh = 0; $mm = 0; $ss = 0

    if ($trimmed -match '^(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        if ($Kind -eq 'end') { $hh = 23; $mm = 59; $ss = 59 }
    }
    elseif ($trimmed -match '^(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})\s+(?<hh>\d{2}):(?<mm>\d{2})(:(?<ss>\d{2}))?$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        $hh = [int]$matches.hh
        $mm = [int]$matches.mm
        $ss = if ($matches.ss) { [int]$matches.ss } else { 0 }
    }
    elseif ($trimmed -match '^(?<d>\d{2})/(?<m>\d{2})/(?<y>\d{4})$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        if ($Kind -eq 'end') { $hh = 23; $mm = 59; $ss = 59 }
    }
    elseif ($trimmed -match '^(?<d>\d{2})/(?<m>\d{2})/(?<y>\d{4})\s+(?<hh>\d{2}):(?<mm>\d{2})(:(?<ss>\d{2}))?$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        $hh = [int]$matches.hh
        $mm = [int]$matches.mm
        $ss = if ($matches.ss) { [int]$matches.ss } else { 0 }
    }
    elseif ($trimmed -match '^(?<y>\d{4})/(?<m>\d{2})/(?<d>\d{2})$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        if ($Kind -eq 'end') { $hh = 23; $mm = 59; $ss = 59 }
    }
    elseif ($trimmed -match '^(?<y>\d{4})/(?<m>\d{2})/(?<d>\d{2})\s+(?<hh>\d{2}):(?<mm>\d{2})(:(?<ss>\d{2}))?$') {
        $y  = [int]$matches.y
        $m  = [int]$matches.m
        $d  = [int]$matches.d
        $hh = [int]$matches.hh
        $mm = [int]$matches.mm
        $ss = if ($matches.ss) { [int]$matches.ss } else { 0 }
    }
    else {
        return $null
    }

    try {
        return [datetime]::new($y, $m, $d, $hh, $mm, $ss)
    } catch {
        return $null
    }
}

function Prompt-InteractiveInputsLikeLinux {
    if ($NonInteractive) { return }

    if ([string]::IsNullOrWhiteSpace($Analyst)) {
        $script:Analyst = Read-Host '>>> Nome do analista que esta executando o script'
        if ([string]::IsNullOrWhiteSpace($script:Analyst)) { $script:Analyst = Confirm-ContinueWithoutAnalyst }
    }

    if (-not $script:InputMonthly -and $script:InputHours -le 0 -and [string]::IsNullOrWhiteSpace($script:InputSince) -and [string]::IsNullOrWhiteSpace($script:InputUntil) -and $script:InputDurationMinutes -le 0) {
        $startInput = Read-TimeInputLoop '>>> INICIO do incidente (YYYY-MM-DD HH:MM) ou ENTER para usar as ultimas 24 horas' $true
        if ([string]::IsNullOrWhiteSpace($startInput)) {
            $script:InputHours = 24
            $script:InteractiveStartDT = $null
            $script:InteractiveEndDT = $null
        } else {
            $script:InputSince = $startInput
            $script:InteractiveStartDT = Normalize-DateString -Value $startInput -Kind 'start'
            $endInput = Read-TimeInputLoop '>>> FIM do incidente (YYYY-MM-DD HH:MM) ou ENTER para agora' $true
            if (-not [string]::IsNullOrWhiteSpace($endInput)) {
                $script:InputUntil = $endInput
                $script:InteractiveEndDT = Normalize-DateString -Value $endInput -Kind 'end'
            } else {
                $script:InteractiveEndDT = $null
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($App)) {
        $script:App = Read-Host '>>> (Opcional) Aplicacao impactada (ex: IIS, Apache, Nginx, etc.)'
    }
    if ([string]::IsNullOrWhiteSpace($CaseId)) {
        $script:CaseId = Read-Host '>>> No do chamado/incidente (ENTER para pular)'
    }
    if ([string]::IsNullOrWhiteSpace($Unit)) {
        $script:Unit = Read-Host '>>> Unidade provider/service para filtrar (ex: WinRM, DNS, TermService) ou ENTER para todos'
    }
    if ([string]::IsNullOrWhiteSpace($Port)) {
        $script:Port = Read-Host '>>> Checagem de Portas especificas (ex: 3389,5985,443) ou ENTER para todas'
    }
}

function Resolve-TimeWindow {
    if ($script:InputMonthly) {
        $start = Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0
        $start = $start.AddMonths(-1)
        $end = ($start.AddMonths(1)).AddSeconds(-1)
    } elseif ($script:InputHours -gt 0) {
        $end = Get-Date
        $start = $end.AddHours(-1 * $script:InputHours)
    } elseif ($script:InteractiveStartDT) {
        $start = $script:InteractiveStartDT
        if ($script:InputDurationMinutes -gt 0) {
            $end = $start.AddMinutes($script:InputDurationMinutes)
        } elseif ($script:InteractiveEndDT) {
            $end = $script:InteractiveEndDT
        } else {
            $end = Get-Date
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($script:InputSince) -and $script:InputDurationMinutes -gt 0) {
        $start = Normalize-DateString -Value $script:InputSince -Kind 'start'
        $end = $start.AddMinutes($script:InputDurationMinutes)
    } elseif (-not [string]::IsNullOrWhiteSpace($script:InputSince) -or -not [string]::IsNullOrWhiteSpace($script:InputUntil)) {
        $start = Normalize-DateString -Value $script:InputSince -Kind 'start'
        $end = Normalize-DateString -Value $script:InputUntil -Kind 'end'
        if (-not $start -and $end) { $start = $end.AddHours(-24) }
        if ($start -and -not $end) { $end = Get-Date }
    } else {
        $end = Get-Date
        $start = $end.AddHours(-24)
        Write-Info $script:Messages.DefaultLast24
    }

    if (-not $start) { throw 'Nao foi possivel resolver o inicio da janela.' }
    if (-not $end) { $end = Get-Date }
    if ($end -lt $start) { throw 'Invalid time window: Until is earlier than Since.' }
    if (($end - $start).TotalHours -gt 168) {
        $script:WindowWarning = 'large_window'
        Write-WarnMsg $script:Messages.LargeWindow
    }

    [pscustomobject]@{
        Since = $start
        Until = $end
        SinceDisplay = $start.ToString('yyyy-MM-dd HH:mm:ss')
        UntilDisplay = $end.ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Confirm-ContinueWithoutAnalyst {
    while ($true) {
        $answer = Read-Host $script:Messages.ContinueWithoutAnalyst
        if ($answer -match '^(y|yes|s|sim)$') {
            return $script:Messages.NotInformed
        }
        if ($answer -match '^(n|no|nao|não)$') {
            throw $script:Messages.Cancelled
        }
        Write-WarnMsg $script:Messages.InvalidAnswer
    }
}

function New-OutputLayout([datetime]$SinceDt) {
    $stamp = $SinceDt.ToString('ddMMyyyyHHmm')
    if ([string]::IsNullOrWhiteSpace($OutDir)) {
        $baseName = if ([string]::IsNullOrWhiteSpace($CaseId)) { $stamp } else { $CaseId }
        if (-not (Test-Path -LiteralPath "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }
        $resolved = Join-Path "C:\Temp" ("analise-{0}" -f $baseName)
    } else {
        $resolved = $OutDir
    }
    if (-not (Test-Path -LiteralPath $resolved)) {
        New-Item -ItemType Directory -Path $resolved -Force | Out-Null
    }
    $script:StampBase = $stamp
    $script:Report = Join-Path $resolved ("relatorio-principal_{0}.log" -f $stamp)
    $script:JsonOut = Join-Path $resolved ("resumo-estruturado_{0}.json" -f $stamp)
    $script:EvidenceFiles = [ordered]@{
        host_identity = Join-Path $resolved ("host_identity_{0}.log" -f $stamp)
        virtualization = Join-Path $resolved ("virtualizacao_{0}.log" -f $stamp)
        events_raw = Join-Path $resolved ("events_raw_{0}.log" -f $stamp)
        events_filtered = Join-Path $resolved ("erros_filtrados_{0}.log" -f $stamp)
        services = Join-Path $resolved ("services_{0}.log" -f $stamp)
        network = Join-Path $resolved ("network_{0}.log" -f $stamp)
        dns = Join-Path $resolved ("dns_{0}.log" -f $stamp)
        time = Join-Path $resolved ("tempo_{0}.log" -f $stamp)
        event_stats = Join-Path $resolved ("event_stats_{0}.log" -f $stamp)
        collection_status = Join-Path $resolved ("collection_status_{0}.log" -f $stamp)
        role_context = Join-Path $resolved ("role_context_{0}.log" -f $stamp)
        listening = Join-Path $resolved ("servicos_escuta_{0}.log" -f $stamp)
        memory = Join-Path $resolved ("memoria_{0}.log" -f $stamp)
        storage = Join-Path $resolved ("storage_{0}.log" -f $stamp)
        logons = Join-Path $resolved ("ultimos_logons_{0}.log" -f $stamp)
        power = Join-Path $resolved ("ultimo_evento_energia_{0}.log" -f $stamp)
        changes = Join-Path $resolved ("mudancas_{0}.log" -f $stamp)
        timeline = Join-Path $resolved ("timeline_{0}.log" -f $stamp)
        ports = Join-Path $resolved ("portas_{0}.log" -f $stamp)
    }
    return $resolved
}

function Out-Utf8File {
    param([string]$Path, [object]$InputObject)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $text = if ($InputObject -is [string]) { $InputObject } else { $InputObject | Out-String }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $text, $utf8NoBom)
}

function Set-CollectionStepStatus([string]$Step,[string]$Status) {
    $script:CollectionStatus[$Step] = $Status
}
function Write-CollectionStatusFile {
    $lines = @()
    foreach ($kv in $script:CollectionStatus.GetEnumerator()) {
        $lines += ('{0}: {1}' -f $kv.Key, $kv.Value)
    }
    Out-Utf8File -Path $script:EvidenceFiles.collection_status -InputObject ($lines -join [Environment]::NewLine)
}

function Safe-Run {
    param([scriptblock]$ScriptBlock, $Default)
    try { & $ScriptBlock } catch { $Default }
}

function Collect-HostIdentity {
    $cs = Safe-Run { Get-CimInstance Win32_ComputerSystem } $null
    $os = Safe-Run { Get-CimInstance Win32_OperatingSystem } $null
    $bios = Safe-Run { Get-CimInstance Win32_BIOS } $null
    $netCfg = Safe-Run { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' } @()
    $fqdn = $script:Messages.Na
    try {
        $domain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
        if ($domain) { $fqdn = "{0}.{1}" -f $env:COMPUTERNAME, $domain } else { $fqdn = $env:COMPUTERNAME }
    } catch { $fqdn = $env:COMPUTERNAME }
    $ipv4 = @($netCfg | ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.' }) -join '; '
    $ipv6 = @($netCfg | ForEach-Object { $_.IPAddress } | Where-Object { $_ -match ':' }) -join '; '
    $userSid = Safe-Run { ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value } $script:Messages.Na
    $lastBoot = $null
    try {
        if ($os -and $os.LastBootUpTime) {
            if ($os.LastBootUpTime -is [datetime]) {
                $lastBoot = $os.LastBootUpTime
            } else {
                $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime([string]$os.LastBootUpTime)
            }
        }
    } catch {}

    if (-not $lastBoot) {
        $evt6013 = Safe-Run { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6013 } -MaxEvents 1 -ErrorAction Stop } $null
        try {
            if ($evt6013 -and $evt6013.Properties.Count -gt 0) {
                $secs = [int]$evt6013.Properties[0].Value
                if ($secs -gt 0) { $lastBoot = (Get-Date).AddSeconds(-1 * $secs) }
            }
        } catch {}
    }

    if ($lastBoot) {
        $ts = New-TimeSpan -Start $lastBoot -End (Get-Date)
        $uptime = ('{0}d {1}h {2}m' -f [int]$ts.TotalDays, $ts.Hours, $ts.Minutes)
    } else {
        $uptime = $script:Messages.Na
    }
    $psVersionValue = Safe-Run { $PSVersionTable.PSVersion.ToString() } $script:Messages.Na
    $psEditionValue = Safe-Run { if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' } } $script:Messages.Na
    $psHostName = Safe-Run { $Host.Name } $script:Messages.Na
    $identity = [ordered]@{
        hostname_short = $env:COMPUTERNAME
        hostname_fqdn = $fqdn
        host_ipv4 = $(if ($ipv4) { $ipv4 } else { $script:Messages.Na })
        host_ipv6 = $(if ($ipv6) { $ipv6 } else { $script:Messages.Na })
        os_pretty = $(if ($os) { '{0} build {1}' -f $os.Caption, $os.BuildNumber } else { $script:Messages.Na })
        kernel_info = $(if ($os) { $os.Version } else { $script:Messages.Na })
        uptime_info = $uptime
        timezone_info = Safe-Run { (Get-TimeZone).Id } $script:Messages.Na
        current_time_info = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        hw_vendor = $(if ($cs) { $cs.Manufacturer } else { $script:Messages.Na })
        hw_product = $(if ($cs) { $cs.Model } else { $script:Messages.Na })
        hw_version = $(if ($bios) { $bios.SMBIOSBIOSVersion } else { $script:Messages.Na })
        exec_user = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
        exec_uid = $userSid
        powershell_version = $psVersionValue
        powershell_edition = $psEditionValue
        powershell_host = $psHostName
        is_windows_powershell = ($psEditionValue -eq 'Desktop')
        is_powershell_core = ($psEditionValue -eq 'Core')
    }
    Out-Utf8File -Path $script:EvidenceFiles.host_identity -InputObject (($identity.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join [Environment]::NewLine)
    return [pscustomobject]$identity
}

function Detect-VirtualizationContext {
    param([object]$HostIdentity)
    $cs = Safe-Run { Get-CimInstance Win32_ComputerSystem } $null
    $manufacturer = [string]$(if ($cs) { $cs.Manufacturer } else { '' })
    $model = [string]$(if ($cs) { $cs.Model } else { '' })
    $signals = New-Object System.Collections.Generic.List[string]
    $isVm = $false
    $isVirtHost = $false
    $virtTech = 'none'

    if ($manufacturer -match 'Microsoft Corporation' -and $model -match 'Virtual Machine') { $isVm = $true; $virtTech = 'Hyper-V'; $signals.Add('hyper-v-guest') }
    elseif ($manufacturer -match 'VMware' -or $model -match 'VMware') { $isVm = $true; $virtTech = 'VMware'; $signals.Add('vmware-guest') }
    elseif ($manufacturer -match 'innotek|Oracle' -or $model -match 'VirtualBox') { $isVm = $true; $virtTech = 'VirtualBox'; $signals.Add('virtualbox-guest') }
    elseif ($manufacturer -match 'Google' -or $model -match 'Google') { $isVm = $true; $virtTech = 'GCP'; $signals.Add('gcp-guest') }
    elseif ($manufacturer -match 'Amazon EC2' -or $model -match 'HVM domU') { $isVm = $true; $virtTech = 'AWS'; $signals.Add('aws-guest') }
    elseif ($manufacturer -match 'Microsoft Corporation' -and $model -match 'Virtual Machine') { $isVm = $true; $virtTech = 'Azure'; $signals.Add('azure-guest') }

    $vmmsSvc = Get-Service -Name vmms -ErrorAction SilentlyContinue
    $vmcomputeSvc = Get-Service -Name vmcompute -ErrorAction SilentlyContinue
    if ($vmmsSvc -and $vmmsSvc.Status -eq 'Running') { $isVirtHost = $true; $virtTech = if ($virtTech -eq 'none') { 'Hyper-V' } else { $virtTech }; $signals.Add('hyper-v-host') }
    if ($vmcomputeSvc -and (($vmcomputeSvc.Status -eq 'Running') -or ($vmmsSvc -and $vmmsSvc.Status -eq 'Running'))) { $signals.Add('hyper-v-compute') }
    if (Get-Service -Name VMTools -ErrorAction SilentlyContinue) { $signals.Add('vmware-tools') }
    if (Get-Process -Name vmtoolsd -ErrorAction SilentlyContinue) { $signals.Add('vmware-tools-process') }

    switch ($script:Profile) {
        'Auto' {
            if ($isVirtHost) { $script:ProfileResolved = 'Virt-Host' }
            else { $script:ProfileResolved = 'Generic' }
        }
        'Generic' { $script:ProfileResolved = 'Generic' }
        'Virt-Host' { $script:ProfileResolved = 'Virt-Host' }
    }

    if ($isVirtHost -or $script:ProfileResolved -eq 'Virt-Host') {
        $script:DetectedExecutionContext = 'virtualization-host'
        $script:HostRole = 'virtualization host'
        $script:HypervisorContext = 'yes'
    } elseif ($isVm) {
        $script:DetectedExecutionContext = 'vm'
        $script:HostRole = 'guest vm'
        $script:HypervisorContext = 'no - guest vm'
    } else {
        $script:DetectedExecutionContext = 'physical'
        $script:HostRole = 'generic windows host'
        $script:HypervisorContext = 'no'
    }

    $script:VirtTech = $virtTech
    $script:VirtStack = if ($signals.Count -gt 0) { ($signals -join ', ') } else { 'none' }
    $obj = [ordered]@{
        profile_requested = $script:Profile
        profile_resolved = $script:ProfileResolved
        execution_context = $script:DetectedExecutionContext
        virt_tech = $script:VirtTech
        virt_stack = $script:VirtStack
        host_role = $script:HostRole
        hypervisor_context = $script:HypervisorContext
        manufacturer = $manufacturer
        model = $model
    }
    Out-Utf8File -Path $script:EvidenceFiles.virtualization -InputObject (($obj.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join [Environment]::NewLine)
    return [pscustomobject]$obj
}

function Get-LogNamesToQuery {
    $logs = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('System','Application','Microsoft-Windows-DNS-Client/Operational','Microsoft-Windows-WinRM/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-Hyper-V-Hypervisor-Admin','Microsoft-Windows-Hyper-V-VMMS/Admin','Microsoft-Windows-Hyper-V-Worker-Admin','Directory Service','DNS Server')) {
        try {
            if (Get-WinEvent -ListLog $name -ErrorAction Stop) { $logs.Add($name) }
        } catch {}
    }
    return $logs
}

function Get-EventPerLogLimit {
    param([datetime]$Start, [datetime]$End)
    if ($EventCapPerLog -gt 0) { return $EventCapPerLog }
    return 0
}

function Collect-EventEvidence {
    param([datetime]$Start, [datetime]$End)
    $filterLogs = Get-LogNamesToQuery
    $perLogLimit = Get-EventPerLogLimit -Start $Start -End $End
    if ($perLogLimit -gt 0) {
        if ($script:Lang -eq 'pt') {
            Write-WarnMsg ("Limitando eventos brutos por log a {0} em modo best-effort." -f $perLogLimit)
        } elseif ($script:Lang -eq 'es') {
            Write-WarnMsg ("Limitando eventos brutos por log a {0} en modo best-effort." -f $perLogLimit)
        } else {
            Write-WarnMsg ("Limiting raw events per log to {0} in best-effort mode." -f $perLogLimit)
        }
    }

    $allEvents = New-Object System.Collections.Generic.List[object]
    foreach ($logName in $filterLogs) {
        try {
            Write-Step ("Get-WinEvent -> {0}" -f $logName)
            $fh = @{ LogName = $logName; StartTime = $Start; EndTime = $End }
            if ($perLogLimit -gt 0) {
                $events = Get-WinEvent -FilterHashtable $fh -MaxEvents $perLogLimit -ErrorAction Stop
            } else {
                $events = Get-WinEvent -FilterHashtable $fh -ErrorAction Stop
            }
            foreach ($evt in $events) { $allEvents.Add($evt) }
        } catch {}
    }

    $preUnitCount = $allEvents.Count
    if ($Unit) {
        $allEvents = [System.Collections.Generic.List[object]]@($allEvents | Where-Object {
            $_.ProviderName -match [regex]::Escape($Unit) -or $_.LogName -match [regex]::Escape($Unit) -or $_.Message -match [regex]::Escape($Unit)
        })
    }

    $zeroReason = ''
    if ($allEvents.Count -eq 0) {
        if ($Unit -and $preUnitCount -gt 0) {
            $zeroReason = ('No events matched the informed unit/provider filter: {0}' -f $Unit)
        } else {
            $zeroReason = 'No events were returned for the selected window.'
        }
    }

    $script:FullErrorRegex = $script:BaseErrorRegex
    if ($Regex) { $script:FullErrorRegex = "({0}|{1})" -f $script:BaseErrorRegex, $Regex }

    $importantIds = @(41,51,55,1014,1074,1076,129,153,157,6008,7000,7001,7009,7011,7023,7024,7026,7031,7034,4625,4771,4776,1001)
    if ($zeroReason) {
        Out-Utf8File -Path $script:EvidenceFiles.events_raw -InputObject $zeroReason
        Out-Utf8File -Path $script:EvidenceFiles.events_filtered -InputObject $zeroReason
        Out-Utf8File -Path $script:EvidenceFiles.timeline -InputObject $zeroReason
        Out-Utf8File -Path $script:EvidenceFiles.event_stats -InputObject $zeroReason
        return [pscustomobject]@{
            Count = 0
            FilteredCount = 0
            RawLines = @()
            FilteredLines = @()
            FilteredObjects = @()
            TimelineLines = @()
            ProviderTop = @()
            IdTop = @()
            ZeroReason = $zeroReason
        }
    }

    $rows = foreach ($e in $allEvents | Sort-Object TimeCreated) {
        $msg = (($e.Message -replace '[\r\n]+',' ') -replace '\s{2,}',' ').Trim()
        [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            Id = [int]$e.Id
            Level = [string]$e.LevelDisplayName
            Provider = [string]$e.ProviderName
            LogName = [string]$e.LogName
            Message = $msg
            Line = "{0} | {1} | Id={2} | Level={3} | Provider={4} | {5}" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $e.LogName, $e.Id, $e.LevelDisplayName, $e.ProviderName, $msg
        }
    }

    Out-Utf8File -Path $script:EvidenceFiles.events_raw -InputObject (($rows | ForEach-Object { $_.Line }) -join [Environment]::NewLine)

    $filteredRows = @($rows | Where-Object {
        ($_.Level -match 'Error|Erro|Critical|Crítico|Warning|Aviso') -or
        ($importantIds -contains $_.Id) -or
        ($_.Message -match $script:FullErrorRegex)
    })

    $filteredRows = @($filteredRows | Where-Object {
        $_.Provider -notmatch 'Microsoft-Windows-HttpService' -and
        $_.Message -notmatch '^Tentativa de adicionar URL' -and
        $_.Message -notmatch '^URL \(http://\*:' -and
        $_.Message -notmatch '^Uma conta foi acessada com sucesso'
    })

    $filtered = @($filteredRows | ForEach-Object { $_.Line })
    Out-Utf8File -Path $script:EvidenceFiles.events_filtered -InputObject ($filtered -join [Environment]::NewLine)

    $timelineLines = @($filteredRows | Sort-Object TimeCreated | Select-Object -Last 500 | ForEach-Object { $_.Line })
    Out-Utf8File -Path $script:EvidenceFiles.timeline -InputObject ($timelineLines -join [Environment]::NewLine)

    $providerTop = @($filteredRows | Group-Object Provider | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    $idTop = @($filteredRows | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })

    $statsContent = @()
    $statsContent += ('RawEventsCount: {0}' -f $allEvents.Count)
    $statsContent += ('FilteredEventsCount: {0}' -f @($filteredRows).Count)
    $statsContent += ''
    $statsContent += '==== Top providers ===='
    $statsContent += ($providerTop -join [Environment]::NewLine)
    $statsContent += ''
    $statsContent += '==== Top event IDs ===='
    $statsContent += ($idTop -join [Environment]::NewLine)
    Out-Utf8File -Path $script:EvidenceFiles.event_stats -InputObject ($statsContent -join [Environment]::NewLine)

    return [pscustomobject]@{
        Count = $allEvents.Count
        FilteredCount = @($filtered).Count
        RawLines = @($rows | ForEach-Object { $_.Line })
        FilteredLines = $filtered
        FilteredObjects = @($filteredRows)
        TimelineLines = $timelineLines
        ProviderTop = $providerTop
        IdTop = $idTop
    }
}
function Collect-ServiceEvidence {
    param([datetime]$Start, [datetime]$End)
    $svcCim = Safe-Run { Get-CimInstance Win32_Service } @()
    $failed = @($svcCim | Where-Object { $_.State -ne 'Running' -and $_.StartMode -eq 'Auto' } | Sort-Object Name)
    $svcEvents = Safe-Run {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Start; EndTime = $End; ProviderName = 'Service Control Manager' } |
            Where-Object { $_.Id -in 7000,7001,7009,7011,7023,7024,7026,7031,7034,7036 } |
            Sort-Object TimeCreated -Descending | Select-Object -First 200
    } @()
    $content = @()
    $content += ('AutomaticServicesDownCount: {0}' -f $failed.Count)
    $content += ('RelevantScmEventsCount: {0}' -f @($svcEvents).Count)
    $content += ''
    $content += '==== Services (automatic services not running) ===='
    $content += ($failed | Select-Object Name, DisplayName, StartMode, State, ExitCode | Format-Table -AutoSize | Out-String)
    $content += ''
    $content += '==== Relevant Service Control Manager events ===='
    $content += ($svcEvents | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Format-List | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.services -InputObject ($content -join [Environment]::NewLine)
    return [pscustomobject]@{ Failed = $failed; ScmEvents = $svcEvents }
}
function Collect-NetworkEvidence {
    $content = @()
    $content += '==== Interfaces ===='
    $content += (Safe-Run { Get-NetIPConfiguration | Format-List | Out-String } (ipconfig /all | Out-String))
    $content += '==== Routes ===='
    $content += (Safe-Run { Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix | Format-Table -AutoSize | Out-String } (route print | Out-String))
    $content += '==== DNS client ===='
    $content += (Safe-Run { Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String } ($script:Messages.Na))
    $content += '==== Connections summary ===='
    $content += (Safe-Run { Get-NetTCPConnection | Group-Object State | Sort-Object Name | Format-Table Name,Count -AutoSize | Out-String } (netstat -an | Out-String))
    Out-Utf8File -Path $script:EvidenceFiles.network -InputObject ($content -join [Environment]::NewLine)
}


function Collect-DnsEvidence {
    $content = @()
    $content += '==== DNS servers ===='
    $content += (Safe-Run { Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String } (ipconfig /all | Out-String))
    $content += '==== DNS cache (best-effort) ===='
    $content += (Safe-Run { Get-DnsClientCache | Select-Object -First 100 Entry, Data, Status, Section, TimeToLive | Format-Table -AutoSize | Out-String } (ipconfig /displaydns | Out-String))
    Out-Utf8File -Path $script:EvidenceFiles.dns -InputObject ($content -join [Environment]::NewLine)
}

function Collect-TimeEvidence {
    param([object]$HostIdentity)
    $content = @()
    $content += ('CurrentTime: {0}' -f $HostIdentity.current_time_info)
    $content += ('TimeZone: {0}' -f $HostIdentity.timezone_info)
    $content += ('Uptime: {0}' -f $HostIdentity.uptime_info)
    $content += ''
    $content += '==== Time zone ===='
    $content += (Safe-Run { Get-TimeZone | Format-List | Out-String } ($script:Messages.Na))
    $content += '==== W32Time status ===='
    $content += (Safe-Run { w32tm /query /status | Out-String } ($script:Messages.Na))
    $content += '==== W32Time configuration ===='
    $content += (Safe-Run { w32tm /query /configuration | Out-String } ($script:Messages.Na))
    $content += '==== Recent time service events ===='
    $content += (Safe-Run { Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Time-Service' } -MaxEvents 30 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Format-List | Out-String } ($script:Messages.Na))
    Out-Utf8File -Path $script:EvidenceFiles.time -InputObject ($content -join [Environment]::NewLine)
}

function Get-ListeningPortObjects {
    $list = @()
    try {
        $list = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Sort-Object LocalPort -Unique |
            ForEach-Object {
                $proc = Safe-Run { Get-Process -Id $_.OwningProcess -ErrorAction Stop } $null
                [pscustomobject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    ProcessId = $_.OwningProcess
                    ProcessName = if ($proc) { $proc.ProcessName } else { $script:Messages.Na }
                }
            }
    } catch {
        $netstat = netstat -ano | Select-String 'LISTENING'
        foreach ($line in $netstat) {
            $parts = ($line.ToString() -replace '\s+',' ').Trim().Split(' ')
            if ($parts.Length -ge 5) {
                $local = $parts[1]
                $pid = [int]$parts[-1]
                $portNum = ($local.Split(':')[-1])
                if ($portNum -as [int]) {
                    $proc = Safe-Run { Get-Process -Id $pid -ErrorAction Stop } $null
                    $list += [pscustomobject]@{
                        LocalAddress = $local
                        LocalPort = [int]$portNum
                        ProcessId = $pid
                        ProcessName = if ($proc) { $proc.ProcessName } else { $script:Messages.Na }
                    }
                }
            }
        }
        $list = $list | Sort-Object LocalPort -Unique
    }
    return $list
}

function Collect-PortEvidence {
    $listening = Get-ListeningPortObjects
    $testedPorts = @()
    if ([string]::IsNullOrWhiteSpace($Port) -or $Port.ToLowerInvariant() -eq 'all') {
        $portsToTest = @($listening | Select-Object -ExpandProperty LocalPort -Unique)
        $portScopeDesc = if ($portsToTest.Count -gt 0) { 'all listening TCP ports on the host' } else { 'no listening ports identified' }
    } else {
        $portsToTest = @($Port -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
        $portScopeDesc = "specific ports informed: $Port"
    }

    foreach ($p in $portsToTest) {
        $isListening = [bool]($listening | Where-Object { $_.LocalPort -eq $p })
        $owner = $listening | Where-Object { $_.LocalPort -eq $p } | Select-Object -First 1
        $testedPorts += [pscustomobject]@{
            Port = $p
            Status = if ($isListening) { 'OK' } else { 'FAILED' }
            ProcessName = if ($owner) { $owner.ProcessName } else { $script:Messages.Na }
            ProcessId = if ($owner) { $owner.ProcessId } else { $script:Messages.Na }
        }
    }

    $content = @()
    $content += "Port scope: $portScopeDesc"
    $content += ''
    $content += '==== Listening services ===='
    $content += ($listening | Format-Table -AutoSize | Out-String)
    $content += '==== Tested ports ===='
    $content += ($testedPorts | Format-Table -AutoSize | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.listening -InputObject ($listening | Format-Table -AutoSize | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.ports -InputObject ($content -join [Environment]::NewLine)

    return [pscustomobject]@{
        Scope = $portScopeDesc
        Listening = $listening
        Tested = $testedPorts
    }
}

function Infer-EnvironmentRole {
    param([object]$HostIdentity, [object]$PortInfo)
    $signals = New-Object System.Collections.Generic.List[string]
    $role = 'workstation'
    $ports = @($PortInfo.Tested | Select-Object -ExpandProperty Port)
    $isServer = [string]$HostIdentity.os_pretty -match 'Windows Server'
    $dcPorts = @(53,88,389,445,464,636,3268,3269,9389)
    $dcHit = @($ports | Where-Object { $_ -in $dcPorts })
    $coreServices = Safe-Run { Get-Service -Name NTDS,DNS,Netlogon,KDC,ADWS -ErrorAction Stop } @()
    $runningCore = @($coreServices | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name)

    if ($isServer) { $signals.Add('os=server') }
    if ($dcHit.Count -ge 4) { $signals.Add('ports=ad-dns') }
    if ($HostIdentity.hostname_fqdn -match '\.') { $signals.Add('fqdn=domain') }
    if ($runningCore.Count -ge 2) { $signals.Add('services=ad-core') }
    if ($runningCore -contains 'DNS') { $signals.Add('service=dns') }

    if ($isServer -and (($dcHit.Count -ge 4) -or ($runningCore.Count -ge 2))) {
        $role = 'domain-controller-dns'
    } elseif ($isServer) {
        $role = 'server'
    } else {
        $role = 'workstation'
    }

    $content = @()
    $content += ('InferredRole: {0}' -f $role)
    $content += ('Signals: {0}' -f $(if ($signals.Count -gt 0) { $signals -join '; ' } else { 'none' }))
    $content += ('PortsObserved: {0}' -f $(if ($ports.Count -gt 0) { $ports -join ', ' } else { 'none' }))
    $content += ('RunningCoreServices: {0}' -f $(if ($runningCore.Count -gt 0) { $runningCore -join ', ' } else { 'none' }))
    Out-Utf8File -Path $script:EvidenceFiles.role_context -InputObject ($content -join [Environment]::NewLine)

    return [pscustomobject]@{
        Role = $role
        Signals = @($signals)
    }
}

function Collect-MemoryEvidence {
    $os = Safe-Run { Get-CimInstance Win32_OperatingSystem } $null
    $totalGB = if ($os) { [math]::Round($os.TotalVisibleMemorySize / 1MB, 2) } else { 0 }
    $freeGB = if ($os) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
    $usedGB = [math]::Round(($totalGB - $freeGB), 2)
    $freePct = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 2) } else { 0 }
    $page = Safe-Run { Get-CimInstance Win32_PageFileUsage } @()
    $topCpu = Safe-Run { Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name, Id, CPU, WS, PM } @()
    $cpuSample = Safe-Run { (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue } $null
    $content = @()
    $content += "TotalMemoryGB: $totalGB"
    $content += "UsedMemoryGB: $usedGB"
    $content += "FreeMemoryGB: $freeGB"
    $content += "FreeMemoryPercent: $freePct"
    $content += "CPUPercentSample: $([math]::Round([double]($cpuSample | ForEach-Object { $_ }),2))"
    $content += ''
    $content += '==== Page file ===='
    $content += ($page | Format-Table -AutoSize | Out-String)
    $content += '==== Top CPU/Memory processes ===='
    $content += ($topCpu | Format-Table -AutoSize | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.memory -InputObject ($content -join [Environment]::NewLine)
    return [pscustomobject]@{ TotalGB = $totalGB; FreeGB = $freeGB; FreePct = $freePct; CpuSample = $cpuSample; TopProcesses = $topCpu }
}

function Collect-StorageEvidence {
    $logical = Safe-Run { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' } @()
    $physical = Safe-Run { Get-CimInstance Win32_DiskDrive } @()
    $rows = foreach ($d in $logical) {
        $sizeGB = if ($d.Size) { [math]::Round($d.Size / 1GB, 2) } else { 0 }
        $freeGB = if ($d.FreeSpace) { [math]::Round($d.FreeSpace / 1GB, 2) } else { 0 }
        $freePct = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB) * 100, 2) } else { 0 }
        [pscustomobject]@{ Drive = $d.DeviceID; Label = $d.VolumeName; FileSystem = $d.FileSystem; SizeGB = $sizeGB; FreeGB = $freeGB; FreePercent = $freePct }
    }
    $content = @()
    $content += '==== Physical disks ===='
    $content += ($physical | Select-Object Model, InterfaceType, SerialNumber, Size | Format-Table -AutoSize | Out-String)
    $content += '==== Volumes ===='
    $content += ($rows | Format-Table -AutoSize | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.storage -InputObject ($content -join [Environment]::NewLine)
    return $rows
}

function Collect-LogonEvidence {
    param([datetime]$Start, [datetime]$End)
    $safeMax = if ($LogonMaxEvents -gt 0) { $LogonMaxEvents } else { 200 }

    $logons = Safe-Run {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $Start; EndTime = $End; Id = 4624,4625 } -MaxEvents $safeMax -ErrorAction Stop
    } @()

    $interactive = @($logons | Where-Object {
        $_.Id -eq 4624 -and (
            $_.Message -match 'Logon Type:\s+(2|7|10|11)' -or
            $_.Message -match 'Tipo de Logon:\s+(2|7|10|11)'
        )
    } | Select-Object -First 50)

    $failed = @($logons | Where-Object { $_.Id -eq 4625 } | Select-Object -First 30)

    $summaryRows = foreach ($evt in $interactive) {
        $msg = [string]$evt.Message
        $account = ''
        $logonType = ''
        $source = ''
        if ($msg -match 'Account Name:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
        elseif ($msg -match 'Nome da Conta:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
        if ($msg -match 'Logon Type:\s+([0-9]+)') { $logonType = $matches[1].Trim() }
        elseif ($msg -match 'Tipo de Logon:\s+([0-9]+)') { $logonType = $matches[1].Trim() }
        if ($msg -match 'Workstation Name:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        elseif ($msg -match 'Nome da Estação de trabalho:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        if (-not $source) {
            if ($msg -match 'Source Network Address:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
            elseif ($msg -match 'Endereço da rede de origem:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        }
        [pscustomobject]@{ TimeCreated = $evt.TimeCreated; Id = $evt.Id; Account = $account; LogonType = $logonType; Source = $source; ProviderName = $evt.ProviderName }
    }

    $failedRows = foreach ($evt in $failed) {
        $msg = [string]$evt.Message
        $account = ''
        $source = ''
        if ($msg -match 'Account Name:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
        elseif ($msg -match 'Nome da Conta:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
        if ($msg -match 'Workstation Name:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        elseif ($msg -match 'Nome da Estação de trabalho:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        if (-not $source) {
            if ($msg -match 'Source Network Address:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
            elseif ($msg -match 'Endereço da rede de origem:\s+([^\r\n]+)') { $source = $matches[1].Trim() }
        }
        [pscustomobject]@{ TimeCreated = $evt.TimeCreated; Id = $evt.Id; Account = $account; Source = $source; ProviderName = $evt.ProviderName }
    }

    $typeSummary = @($summaryRows | Group-Object LogonType | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    $preferredInteractive = @($summaryRows | Where-Object {
        $_.Account -and
        $_.Account -notmatch '\$$' -and
        $_.Account -notmatch '^(ANONYMOUS LOGON|DWM-|UMFD-)'
    })
    $preferredFailed = @($failedRows | Where-Object {
        $_.Account -and
        $_.Account -notmatch '\$$' -and
        $_.Account -notmatch '^(ANONYMOUS LOGON|DWM-|UMFD-)'
    })
    if ($preferredInteractive.Count -eq 0) {
        $lsm = Safe-Run {
            Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; StartTime = $Start; EndTime = $End } -MaxEvents 50 -ErrorAction Stop
        } @()
        $lsmRows = foreach ($evt in $lsm) {
            $msg = [string]$evt.Message
            $account = ''
            if ($msg -match 'User:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
            elseif ($msg -match 'Usuário:\s+([^\r\n]+)') { $account = $matches[1].Trim() }
            if ($account -and $account -notmatch '\$$') {
                [pscustomobject]@{ TimeCreated = $evt.TimeCreated; Id = $evt.Id; Account = $account; LogonType = 'LSM'; Source = 'LocalSessionManager'; ProviderName = $evt.ProviderName }
            }
        }
        if ($lsmRows.Count -gt 0) { $preferredInteractive = @($lsmRows | Sort-Object TimeCreated -Descending | Select-Object -First 20) }
        else { $preferredInteractive = $summaryRows }
    }
    if ($preferredFailed.Count -eq 0) { $preferredFailed = $failedRows }

    $topAccounts = @($preferredInteractive | Where-Object { $_.Account } | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    $failedAccounts = @($preferredFailed | Where-Object { $_.Account } | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })

    $lastLoginSummary = $script:Messages.Na
    $lastLoginKind = 'none'
    if ($preferredInteractive.Count -gt 0) {
        $first = $preferredInteractive | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $lastLoginKind = if ($first.Account -match '\$$') { 'machine' } else { 'human' }
        $lastLoginSummary = ('{0} | account={1} | type={2} | source={3}' -f $first.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $(if ($first.Account) { $first.Account } else { $script:Messages.Na }), $(if ($first.LogonType) { $first.LogonType } else { $script:Messages.Na }), $(if ($first.Source) { $first.Source } else { $script:Messages.Na }))
    } elseif ($preferredFailed.Count -gt 0) {
        $firstFail = $preferredFailed | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $lastLoginKind = if ($firstFail.Account -match '\$$') { 'machine-failed' } else { 'failed-only' }
        $lastLoginSummary = ('failed-only | {0} | account={1} | source={2}' -f $firstFail.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $(if ($firstFail.Account) { $firstFail.Account } else { $script:Messages.Na }), $(if ($firstFail.Source) { $firstFail.Source } else { $script:Messages.Na }))
    }

    $content = @()
    $content += ("==== Logon query status ==== MaxEvents={0}" -f $safeMax)
    $content += ("InteractiveCount: {0}" -f $summaryRows.Count)
    $content += ("FailedCount: {0}" -f $failedRows.Count)
    $content += ("Types: {0}" -f $(if ($typeSummary.Count -gt 0) { $typeSummary -join '; ' } else { 'none' }))
    $content += ("TopAccounts: {0}" -f $(if ($topAccounts.Count -gt 0) { $topAccounts -join '; ' } else { 'none' }))
    $content += ("TopFailedAccounts: {0}" -f $(if ($failedAccounts.Count -gt 0) { $failedAccounts -join '; ' } else { 'none' }))
    $content += ("LastLoginSummary: {0}" -f $lastLoginSummary)
    $content += ("LastLoginKind: {0}" -f $lastLoginKind)
    $content += ''
    $content += '==== Successful interactive logons (summary) ===='
    $content += ($summaryRows | Select-Object TimeCreated, Id, Account, LogonType, Source, ProviderName | Format-Table -AutoSize | Out-String)
    $content += ''
    $content += '==== Failed logons (summary) ===='
    $content += ($failedRows | Select-Object TimeCreated, Id, Account, Source, ProviderName | Format-Table -AutoSize | Out-String)
    if (($interactive.Count -eq 0) -and ($failed.Count -eq 0)) {
        $content += ''
        $content += '==== Notes ===='
        $content += 'No recent interactive or failed logons were returned in the bounded Security query (best-effort).'
    }
    Out-Utf8File -Path $script:EvidenceFiles.logons -InputObject ($content -join [Environment]::NewLine)
    return [pscustomobject]@{
        Interactive = $summaryRows
        Failed = $failedRows
        LastLoginSummary = $lastLoginSummary
        SuccessCount = $summaryRows.Count
        FailedCount = $failedRows.Count
        TypeSummary = $typeSummary
        TopAccounts = $topAccounts
        TopFailedAccounts = $failedAccounts
        LastLoginKind = $lastLoginKind
    }
}
function Collect-PowerEvidence {
    param([datetime]$Start, [datetime]$End)
    $lookupStart = $End.AddDays(-30)
    $events = Safe-Run {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $lookupStart; EndTime = $End; Id = 41,1074,1076,6005,6006,6008 } |
            Sort-Object TimeCreated -Descending
    } @()
    $content = @()
    $content += ('PowerEventsCount: {0}' -f @($events).Count)
    $content += '==== Recent reboot/shutdown events ===='
    $content += ($events | Select-Object TimeCreated, Id, ProviderName, Message | Format-List | Out-String)
    Out-Utf8File -Path $script:EvidenceFiles.power -InputObject ($content -join [Environment]::NewLine)
    return $events
}
function Collect-RecentChangesEvidence {
    param([datetime]$Start, [datetime]$End)
    $hotfix = Safe-Run { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 } @()
    $msi = Safe-Run { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object InstallDate -Descending | Select-Object -First 30 } @()
    $content = @()
    $content += '==== Hotfixes ===='
    $content += ($hotfix | Format-Table -AutoSize | Out-String)
    if ($script:Collection -eq 'Detailed') {
        $content += '==== Recent installed software (registry best-effort) ===='
        $content += ($msi | Format-Table -AutoSize | Out-String)
    }
    Out-Utf8File -Path $script:EvidenceFiles.changes -InputObject ($content -join [Environment]::NewLine)
}

function Get-MainClueCandidateMeta {
    param([object]$Candidate,[string]$Role)
    $line = [string]$Candidate.Line
    $provider = [string]$Candidate.Provider
    $level = [string]$Candidate.Level
    $eventId = 0
    try { $eventId = [int]$Candidate.Id } catch { $eventId = 0 }
    $score = 0
    $category = 'generic'

    if ($level -match 'Critical|Crítico') { $score += 120 }
    elseif ($level -match 'Error|Erro') { $score += 95 }
    elseif ($level -match 'Warning|Aviso') { $score += 45 }
    else { $score += 5 }

    if (($eventId -in 7000,7009,7011,7031,7034) -or $line -match '(failed to start|service control manager)') { $score += 55; $category = 'service' }
    if (($eventId -in 1014,4013,4015,5774) -or $line -match '(dns server|name resolution|dynamic registration)') { $score += 50; if ($category -eq 'generic') { $category = 'dns' } }
    if (($eventId -in 4625,4771,4776,6038) -or $line -match '(kerberos|kdc|netlogon|directory service|active directory|lsasrv)') { $score += 45; if ($category -eq 'generic') { $category = 'auth-ad' } }
    if (($eventId -in 51,55,129,153,264) -or $line -match '(\bdisk\b|ntfs|storahci|reset to device|storage optimizer|optimizer)') { $score += 55; if ($category -eq 'generic') { $category = 'disk' } }
    if ($eventId -in 41,6008,1074,1076) { $score += 55; if ($category -eq 'generic') { $category = 'power' } }
    if ($line -match '(unexpected shutdown|bugcheck)') { $score += 35; if ($category -eq 'generic') { $category = 'power' } }
    if ($line -match '(resource-exhaustion|out of memory|oom|memory)') { $score += 50; if ($category -eq 'generic') { $category = 'memory' } }
    if (($eventId -in 13,8193,8194,12289,12293) -or $line -match '(VSS |Volume Shadow Copy|SW_PROV|access denied)') { $score += 35; $category = 'vss' }
    if ($eventId -in 142,161) { $score += 30; if ($category -eq 'generic') { $category = 'winrm' } }

    if ($provider -match 'Microsoft-Windows-DistributedCOM' -and $eventId -eq 10016) { $score -= 85 }
    if ($provider -match 'Microsoft-Windows-Defrag') { $score += 20; if ($category -eq 'generic') { $category = 'disk' } }
    if ($provider -match '^VSS$') { $score += 15; $category = 'vss' }
    if ($provider -match 'Windows Error Reporting') { $score -= 70 }
    if ($provider -match 'Microsoft-Windows-Kernel-General') { $score -= 90 }
    if ($provider -match 'Microsoft-Windows-HttpService') { $score -= 70 }
    if ($provider -match 'TPM-WMI') { $score -= 70 }
    if ($provider -match 'Microsoft-Windows-Security-SPP') { $score -= 55 }
    if ($provider -match 'Microsoft-Windows-Perflib') { $score -= 35 }
    if ($provider -match 'Microsoft-Windows-WindowsUpdateClient') { $score -= 25 }
    if ($provider -match 'Microsoft-Windows-System-Restore') { $score -= 30 }
    if ($eventId -eq 7036) { $score -= 90 }
    if ($eventId -eq 1 -and $provider -match 'Kernel-General') { $score -= 120 }
    if ($eventId -eq 5504 -and $level -match 'Information|Inform') { $score -= 100 }
    if ($eventId -eq 6038 -or $line -match '(NTLM authentication is presently being used|authenticação NTLM está sendo usada)') { $score -= 40 }

    if ($Role -eq 'domain-controller-dns') {
        if ($provider -match 'NETLOGON' -or $eventId -eq 5774) { $score += 50; $category = 'dns' }
        if ($provider -match 'DNS-Server|DNS Server' -or $eventId -in 4013,4015,5501,5504) { $score += 45; $category = 'dns-server' }
        if ($provider -match 'ActiveDirectory|Directory Service|KDC' -or $eventId -in 2886,2887,2889,2092,2042) { $score += 40; if ($category -eq 'generic') { $category = 'ad-core' } }
        if ($provider -match 'Security-SPP') { $score -= 25 }
        if ($provider -match 'Perflib') { $score -= 20 }
    } elseif ($Role -eq 'server') {
        if ($provider -match 'Service Control Manager') { $score += 20; if ($category -eq 'generic') { $category = 'service' } }
        if ($provider -match 'DNS') { $score += 15 }
    }

    if ($category -eq 'generic' -and $score -gt 110) { $score -= 25 }
    $confidence = if ($score -ge 150) { 'high' } elseif ($score -ge 100) { 'medium' } else { 'low' }
    [pscustomobject]@{ Score = $score; Category = $category; Confidence = $confidence; Line = $line; Provider = $provider; Id = $eventId }
}

function Build-ExecutiveSummary {
    param(
        [object]$MemoryInfo,
        [object]$StorageInfo,
        [object]$ServiceInfo,
        [object]$PortInfo,
        [object]$PowerInfo,
        [object]$EventInfo,
        [object]$RoleContext
    )

    $cpuStatus = if ($MemoryInfo.CpuSample -ge 85) { "attention (CPU sample=$([math]::Round($MemoryInfo.CpuSample,2))%)" } else { "normal (CPU sample=$([math]::Round($MemoryInfo.CpuSample,2))%)" }
    $memStatus = if ($MemoryInfo.FreePct -lt 10) { "critical (free memory=$($MemoryInfo.FreePct)%)" } elseif ($MemoryInfo.FreePct -lt 20) { "attention (free memory=$($MemoryInfo.FreePct)%)" } else { "normal (free memory=$($MemoryInfo.FreePct)%)" }
    $criticalDisks = @($StorageInfo | Where-Object { $_.FreePercent -lt 10 -and $_.FileSystem -ne 'exFAT' })
    $diskStatus = if ($criticalDisks.Count -gt 0) { 'attention (' + (($criticalDisks | ForEach-Object { "{0} free={1}%" -f $_.Drive, $_.FreePercent }) -join '; ') + ')' } else { 'normal' }
    $failedServices = @($ServiceInfo.Failed | Select-Object -First 10 -ExpandProperty Name)
    $failedSvcStatus = if ($failedServices.Count -gt 0) { "{0} automatic service(s) with problem" -f $failedServices.Count } else { 'no obvious failed automatic services' }
    $failedPorts = @($PortInfo.Tested | Where-Object { $_.Status -eq 'FAILED' } | Select-Object -ExpandProperty Port)
    $portStatus = if ($PortInfo.Tested.Count -eq 0) { 'no port test performed' } elseif ($failedPorts.Count -gt 0) { "{0} OK / {1} failed" -f (@($PortInfo.Tested | Where-Object Status -eq 'OK').Count), $failedPorts.Count } else { "{0} OK / 0 failed" -f $PortInfo.Tested.Count }
    $lastPower = $script:Messages.Na
    if ($PowerInfo.Count -gt 0) { $lastPower = "{0} | Id={1} | {2}" -f $PowerInfo[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $PowerInfo[0].Id, $PowerInfo[0].ProviderName }

    $roleName = if ($RoleContext) { $RoleContext.Role } else { 'unknown' }
    $scoredCandidates = @($EventInfo.FilteredObjects | ForEach-Object { Get-MainClueCandidateMeta -Candidate $_ -Role $roleName } | Sort-Object Score -Descending)
    $bestCandidate = $scoredCandidates | Select-Object -First 1
    $mainClueConfidence = 'low'
    $mainClueCategory = 'none'

    if ($bestCandidate -and $bestCandidate.Score -ge 90) {
        $script:MainClue = $bestCandidate.Line
        $mainClueConfidence = $bestCandidate.Confidence
        $mainClueCategory = $bestCandidate.Category
    }
    elseif ($EventInfo.ZeroReason) {
        $script:MainClue = $EventInfo.ZeroReason
        $mainClueConfidence = 'low'
        $mainClueCategory = 'filter-zero'
    }
    else {
        $script:MainClue = 'No strong evidence was identified. Best-effort summary only.'
        $mainClueConfidence = 'low'
        $mainClueCategory = 'best-effort'
    }

    return [ordered]@{
        cpu_status = $cpuStatus
        mem_status = $memStatus
        disk_status = $diskStatus
        failed_units_status = $failedSvcStatus
        failed_units_list = if ($failedServices.Count -gt 0) { $failedServices -join ', ' } else { $script:Messages.None }
        port_status = $portStatus
        failed_ports_summary = if ($failedPorts.Count -gt 0) { ($failedPorts -join ', ') } else { $script:Messages.None }
        last_power = $lastPower
        main_clue = $script:MainClue
        window_warning = $script:WindowWarning
        tested_ports_summary = if ($PortInfo.Tested.Count -gt 0) { (($PortInfo.Tested | Select-Object -ExpandProperty Port) -join ', ') } else { $script:Messages.None }
        port_scope_desc = $PortInfo.Scope
        events_raw_count = $EventInfo.Count
        events_filtered_count = $EventInfo.FilteredCount
        top_providers = if ($EventInfo.ProviderTop.Count -gt 0) { $EventInfo.ProviderTop -join '; ' } else { $script:Messages.None }
        top_event_ids = if ($EventInfo.IdTop.Count -gt 0) { $EventInfo.IdTop -join '; ' } else { $script:Messages.None }
        inferred_environment_role = $(if ($RoleContext) { $RoleContext.Role } else { 'unknown' })
        role_signals = $(if ($RoleContext -and $RoleContext.Signals.Count -gt 0) { $RoleContext.Signals -join '; ' } else { 'none' })
        events_zero_reason = $(if ($EventInfo.ZeroReason) { $EventInfo.ZeroReason } else { '' })
        main_clue_confidence = $mainClueConfidence
        main_clue_category = $mainClueCategory
    }
}
function Write-MainReport {
    param(
        [object]$HostIdentity,
        [object]$VirtContext,
        [object]$Window,
        [hashtable]$Summary,
        [object]$Logons,
        [object]$PowerInfo,
        [object]$StorageInfo,
        [object]$MemoryInfo,
        [object]$PortInfo
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($script:ToolName) $($script:Version)")
    $lines.Add(('=' * 72))
    $lines.Add('')
    $lines.Add($script:Messages.HeadingExec)
    $lines.Add("Analyst: $(if ($Analyst) { $Analyst } else { $script:Messages.NotInformed })")
    $lines.Add("Execution user: $($HostIdentity.exec_user)")
    $lines.Add("Execution SID: $($HostIdentity.exec_uid)")
    $lines.Add("Administrator: $($script:IsAdmin)")
    $lines.Add('')
    $lines.Add($script:Messages.HeadingHost)
    $lines.Add("PowerShell version: $($HostIdentity.powershell_version)")
    $lines.Add("PowerShell edition: $($HostIdentity.powershell_edition)")
    $lines.Add("PowerShell host: $($HostIdentity.powershell_host)")
    $lines.Add("IsWindowsPowerShell: $($HostIdentity.is_windows_powershell)")
    $lines.Add("IsPowerShellCore: $($HostIdentity.is_powershell_core)")
    foreach ($p in $HostIdentity.PSObject.Properties) { $lines.Add("$($p.Name): $($p.Value)") }
    $lines.Add('')
    $lines.Add($script:Messages.HeadingVirt)
    foreach ($p in $VirtContext.PSObject.Properties) { $lines.Add("$($p.Name): $($p.Value)") }
    $lines.Add('')
    $lines.Add($script:Messages.HeadingWindow)
    $lines.Add("since: $($Window.SinceDisplay)")
    $lines.Add("until: $($Window.UntilDisplay)")
    if ($App) { $lines.Add("app: $App") }
    if ($CaseId) { $lines.Add("case_id: $CaseId") }
    if ($Unit) { $lines.Add("unit: $Unit") }
    if ($Regex) { $lines.Add("regex: $Regex") }
    $lines.Add('')
    $lines.Add($script:Messages.HeadingSummary)
    foreach ($k in $Summary.Keys) { $lines.Add("${k}: $($Summary[$k])") }
    $lines.Add('')
    $lines.Add($script:Messages.HeadingLogons)
    $lines.Add(("LastLoginSummary: {0}" -f $Logons.LastLoginSummary))
    $lines.Add(("LastLoginKind: {0}" -f $Logons.LastLoginKind))
    $lines.Add(("SuccessfulInteractiveCount: {0}" -f $Logons.SuccessCount))
    $lines.Add(("FailedLogonCount: {0}" -f $Logons.FailedCount))
    $lines.Add(("TopAccounts: {0}" -f $(if ($Logons.TopAccounts.Count -gt 0) { $Logons.TopAccounts -join '; ' } else { 'none' })))
    $lines.Add(("TopFailedAccounts: {0}" -f $(if ($Logons.TopFailedAccounts.Count -gt 0) { $Logons.TopFailedAccounts -join '; ' } else { 'none' })))
    $lines.Add((($Logons.Interactive | Select-Object -First 10 TimeCreated, Id, Account, LogonType, Source | Format-Table -AutoSize | Out-String).TrimEnd()))
    $lines.Add('')
    $lines.Add($script:Messages.HeadingPower)
    $lines.Add((($PowerInfo | Select-Object -First 10 TimeCreated, Id, ProviderName | Format-Table -AutoSize | Out-String).TrimEnd()))
    $lines.Add('')
    $lines.Add($script:Messages.HeadingErrors)
    $lines.Add((Get-Content -LiteralPath $script:EvidenceFiles.events_filtered -ErrorAction SilentlyContinue | Select-Object -First 40) -join [Environment]::NewLine)
    $lines.Add('')
    $lines.Add($script:Messages.HeadingStorage)
    $lines.Add((($StorageInfo | Format-Table -AutoSize | Out-String).TrimEnd()))
    $lines.Add('')
    $lines.Add($script:Messages.HeadingMemory)
    $lines.Add("TotalGB: $($MemoryInfo.TotalGB)")
    $lines.Add("FreeGB: $($MemoryInfo.FreeGB)")
    $lines.Add("FreePercent: $($MemoryInfo.FreePct)")
    $lines.Add("CpuSample: $([math]::Round([double]$MemoryInfo.CpuSample,2))")
    $lines.Add('')
    $lines.Add($script:Messages.HeadingPorts)
    $lines.Add((($PortInfo.Tested | Format-Table -AutoSize | Out-String).TrimEnd()))
    $lines.Add('')
    $lines.Add($script:Messages.HeadingRefs)
    foreach ($k in $script:EvidenceFiles.Keys) { $lines.Add("${k}: $($script:EvidenceFiles[$k])") }
    Out-Utf8File -Path $script:Report -InputObject ($lines -join [Environment]::NewLine)
}

function Write-JsonSummary {
    param(
        [object]$HostIdentity,
        [object]$VirtContext,
        [object]$Window,
        [hashtable]$Summary,
        [object]$PowerInfo,
        [object]$Logons
    )
    $payload = [ordered]@{
        version = $script:Version
        build_date = $script:BuildDate
        profile_requested = $script:Profile
        profile_resolved = $script:ProfileResolved
        coleta = $script:Collection
        analyst_name = $(if ($Analyst) { $Analyst } else { $script:Messages.NotInformed })
        exec_user = $HostIdentity.exec_user
        exec_uid = $HostIdentity.exec_uid
        hostname_short = $HostIdentity.hostname_short
        hostname_fqdn = $HostIdentity.hostname_fqdn
        host_ipv4 = $HostIdentity.host_ipv4
        host_ipv6 = $HostIdentity.host_ipv6
        os_pretty = $HostIdentity.os_pretty
        kernel_info = $HostIdentity.kernel_info
        uptime_info = $HostIdentity.uptime_info
        timezone_info = $HostIdentity.timezone_info
        current_time_info = $HostIdentity.current_time_info
        since = $Window.SinceDisplay
        until = $Window.UntilDisplay
        app_name = $App
        case_id = $CaseId
        outdir = (Split-Path -Parent $script:Report)
        unit_filter = $Unit
        extra_regex = $Regex
        execution_context = $script:DetectedExecutionContext
        virt_tech = $script:VirtTech
        virt_stack = $script:VirtStack
        host_role = $script:HostRole
        hypervisor_context = $script:HypervisorContext
        hw_vendor = $HostIdentity.hw_vendor
        hw_product = $HostIdentity.hw_product
        hw_version = $HostIdentity.hw_version
        powershell_version = $HostIdentity.powershell_version
        powershell_edition = $HostIdentity.powershell_edition
        powershell_host = $HostIdentity.powershell_host
        is_windows_powershell = $HostIdentity.is_windows_powershell
        is_powershell_core = $HostIdentity.is_powershell_core
        cpu_status = $Summary.cpu_status
        mem_status = $Summary.mem_status
        disk_status = $Summary.disk_status
        failed_units_status = $Summary.failed_units_status
        failed_units_list = $Summary.failed_units_list
        port_status = $Summary.port_status
        failed_ports_summary = $Summary.failed_ports_summary
        main_clue = $Summary.main_clue
        main_clue_confidence = $Summary.main_clue_confidence
        main_clue_category = $Summary.main_clue_category
        window_warning = $Summary.window_warning
        events_raw_count = $Summary.events_raw_count
        events_filtered_count = $Summary.events_filtered_count
        top_providers = $Summary.top_providers
        top_event_ids = $Summary.top_event_ids
        inferred_environment_role = $Summary.inferred_environment_role
        role_signals = $Summary.role_signals
        events_zero_reason = $Summary.events_zero_reason
        tested_ports_summary = $Summary.tested_ports_summary
        port_scope_desc = $Summary.port_scope_desc
        last_power = $(if ($PowerInfo.Count -gt 0) { $PowerInfo[0].Message } else { $script:Messages.Na })
        last_login = $Logons.LastLoginSummary
        logon_count = $Logons.SuccessCount
        failed_logon_count = $Logons.FailedCount
        logon_top_accounts = $(if ($Logons.TopAccounts.Count -gt 0) { $Logons.TopAccounts -join '; ' } else { 'none' })
        last_login_kind = $Logons.LastLoginKind
        power_event_count = @($PowerInfo).Count
        logon_max_events = $(if ($LogonMaxEvents -gt 0) { $LogonMaxEvents } else { 200 })
        event_cap_per_log = $(if ($EventCapPerLog -gt 0) { $EventCapPerLog } else { 0 })
        collection_status_file = $script:EvidenceFiles.collection_status
        evidence_files = $script:EvidenceFiles
    }
    Out-Utf8File -Path $script:JsonOut -InputObject ($payload | ConvertTo-Json -Depth 6)
}

function Show-ClosingMessage {
    Write-Host ''
    Write-Host ('-' * 69)
    Write-Host "$($script:ToolName) $($script:Version)"
    Write-Host ''
    Write-Host $script:Messages.Closing
    if ($script:Lang -eq 'pt') {
        Write-Host ("Os arquivos gerados foram salvos em: {0}" -f (Split-Path -Parent $script:Report))
        Write-Host ''
        Write-Host ("Relatorio principal: {0}" -f $script:Report)
        Write-Host ("Resumo estruturado JSON: {0}" -f $script:JsonOut)
        Write-Host ''
        Write-Host 'Em caso de duvidas, sugestoes de melhoria ou necessidade de suporte,'
        Write-Host 'entre em contato pelo e-mail: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'Se o Technova IncidentScope agregou valor ao seu dia a dia,'
        Write-Host 'considere contribuir com qualquer valor via PIX: technova.sti@outlook.com'
    } elseif ($script:Lang -eq 'es') {
        Write-Host ("Los archivos generados fueron guardados en: {0}" -f (Split-Path -Parent $script:Report))
        Write-Host ''
        Write-Host ("Informe principal: {0}" -f $script:Report)
        Write-Host ("Resumen estructurado JSON: {0}" -f $script:JsonOut)
        Write-Host ''
        Write-Host 'En caso de dudas, sugerencias de mejora o necesidad de soporte,'
        Write-Host 'contacte por correo electronico: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'Si Technova IncidentScope aporto valor a su rutina,'
        Write-Host 'considere contribuir con cualquier monto via PIX: technova.sti@outlook.com'
    } else {
        Write-Host ("The generated files were saved in: {0}" -f (Split-Path -Parent $script:Report))
        Write-Host ''
        Write-Host ("Main report: {0}" -f $script:Report)
        Write-Host ("Structured JSON summary: {0}" -f $script:JsonOut)
        Write-Host ''
        Write-Host 'For questions, improvement suggestions or support needs,'
        Write-Host 'please contact: technova.sti@outlook.com'
        Write-Host ''
        Write-Host 'If Technova IncidentScope added value to your daily work,'
        Write-Host 'please consider contributing any amount via PIX: technova.sti@outlook.com'
    }
    Write-Host ('-' * 69)
}

try {
    Set-ConsoleUtf8
    Initialize-Localization
    Resolve-ShortcutParameters
    $script:InputMonthly = $Monthly
    $script:InputSince = $Since
    $script:InputUntil = $Until
    $script:InputHours = $Hours
    $script:InputDurationMinutes = $DurationMinutes

    if ($Manual) {
        Show-ManualText
        return
    }

    Show-StartupBanner
    Show-StartupDisclaimer
    Show-QuickGuidance
    Assert-AdministratorFlag
    if (-not $script:IsAdmin) { Write-WarnMsg $script:Messages.AdminPartial }

    Write-Info ("{0}: {1}" -f $(if ($script:Lang -eq 'pt') { 'Nivel de coleta' } elseif ($script:Lang -eq 'es') { 'Nivel de recoleccion' } else { 'Collection level' }), $script:Collection)
    Write-Info ("{0}: {1}" -f $(if ($script:Lang -eq 'pt') { 'Perfil solicitado' } elseif ($script:Lang -eq 'es') { 'Perfil solicitado' } else { 'Requested profile' }), $script:Profile)

    if (-not $NonInteractive) {
        Prompt-InteractiveInputsLikeLinux
    } elseif ([string]::IsNullOrWhiteSpace($Analyst)) {
        $Analyst = $script:Messages.NotInformed
    }

    $window = Resolve-TimeWindow
    $resolvedOutDir = New-OutputLayout -SinceDt $window.Since
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando identidade do host...' } elseif ($script:Lang -eq 'es') { 'Recolectando identidad del host...' } else { 'Collecting host identity...' }))
    $hostIdentity = Collect-HostIdentity
    Set-CollectionStepStatus -Step 'host_identity' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando contexto de tempo...' } elseif ($script:Lang -eq 'es') { 'Recolectando contexto de tiempo...' } else { 'Collecting time context...' }))
    Collect-TimeEvidence -HostIdentity $hostIdentity
    Set-CollectionStepStatus -Step 'time' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Detectando contexto de virtualizacao...' } elseif ($script:Lang -eq 'es') { 'Detectando contexto de virtualizacion...' } else { 'Detecting virtualization context...' }))
    $virtContext = Detect-VirtualizationContext -HostIdentity $hostIdentity
    Set-CollectionStepStatus -Step 'virtualization' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando eventos e timeline...' } elseif ($script:Lang -eq 'es') { 'Recolectando eventos y timeline...' } else { 'Collecting events and timeline...' }))
    $eventInfo = Collect-EventEvidence -Start $window.Since -End $window.Until
    Set-CollectionStepStatus -Step 'events' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando servicos...' } elseif ($script:Lang -eq 'es') { 'Recolectando servicios...' } else { 'Collecting services...' }))
    $serviceInfo = Collect-ServiceEvidence -Start $window.Since -End $window.Until
    Set-CollectionStepStatus -Step 'services' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando rede...' } elseif ($script:Lang -eq 'es') { 'Recolectando red...' } else { 'Collecting network...' }))
    Collect-NetworkEvidence
    Set-CollectionStepStatus -Step 'network' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando DNS...' } elseif ($script:Lang -eq 'es') { 'Recolectando DNS...' } else { 'Collecting DNS...' }))
    Collect-DnsEvidence
    Set-CollectionStepStatus -Step 'dns' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando portas...' } elseif ($script:Lang -eq 'es') { 'Recolectando puertos...' } else { 'Collecting ports...' }))
    $portInfo = Collect-PortEvidence
    Set-CollectionStepStatus -Step 'ports' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Inferindo perfil do ambiente...' } elseif ($script:Lang -eq 'es') { 'Infiriendo perfil del entorno...' } else { 'Inferring environment role...' }))
    $roleContext = Infer-EnvironmentRole -HostIdentity $hostIdentity -PortInfo $portInfo
    Set-CollectionStepStatus -Step 'role_context' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando memoria e CPU...' } elseif ($script:Lang -eq 'es') { 'Recolectando memoria y CPU...' } else { 'Collecting memory and CPU...' }))
    $memoryInfo = Collect-MemoryEvidence
    Set-CollectionStepStatus -Step 'memory' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando storage...' } elseif ($script:Lang -eq 'es') { 'Recolectando storage...' } else { 'Collecting storage...' }))
    $storageInfo = Collect-StorageEvidence
    Set-CollectionStepStatus -Step 'storage' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando logons...' } elseif ($script:Lang -eq 'es') { 'Recolectando inicios de sesion...' } else { 'Collecting logons...' }))
    $logonInfo = Collect-LogonEvidence -Start $window.Since -End $window.Until
    Set-CollectionStepStatus -Step 'logons' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando reboot/shutdown...' } elseif ($script:Lang -eq 'es') { 'Recolectando reinicio/apagado...' } else { 'Collecting reboot/shutdown...' }))
    $powerInfo = Collect-PowerEvidence -Start $window.Since -End $window.Until
    Set-CollectionStepStatus -Step 'power' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Coletando mudancas recentes...' } elseif ($script:Lang -eq 'es') { 'Recolectando cambios recientes...' } else { 'Collecting recent changes...' }))
    Collect-RecentChangesEvidence -Start $window.Since -End $window.Until
    Set-CollectionStepStatus -Step 'changes' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Montando resumo executivo...' } elseif ($script:Lang -eq 'es') { 'Construyendo resumen ejecutivo...' } else { 'Building executive summary...' }))
    $summary = Build-ExecutiveSummary -MemoryInfo $memoryInfo -StorageInfo $storageInfo -ServiceInfo $serviceInfo -PortInfo $portInfo -PowerInfo $powerInfo -EventInfo $eventInfo -RoleContext $roleContext
    Set-CollectionStepStatus -Step 'summary' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Gerando relatorio principal...' } elseif ($script:Lang -eq 'es') { 'Generando informe principal...' } else { 'Generating main report...' }))
    Write-MainReport -HostIdentity $hostIdentity -VirtContext $virtContext -Window $window -Summary $summary -Logons $logonInfo -PowerInfo $powerInfo -StorageInfo $storageInfo -MemoryInfo $memoryInfo -PortInfo $portInfo
    Set-CollectionStepStatus -Step 'main_report' -Status 'ok'
    Write-Step ($(if ($script:Lang -eq 'pt') { 'Gerando resumo JSON...' } elseif ($script:Lang -eq 'es') { 'Generando resumen JSON...' } else { 'Generating JSON summary...' }))
    Write-JsonSummary -HostIdentity $hostIdentity -VirtContext $virtContext -Window $window -Summary $summary -PowerInfo $powerInfo -Logons $logonInfo
    Set-CollectionStepStatus -Step 'json_summary' -Status 'ok'
    Write-CollectionStatusFile
    Show-ClosingMessage
}
catch {
    Write-ErrMsg $_.Exception.Message
    Write-ErrMsg $_.ScriptStackTrace
    throw
}
