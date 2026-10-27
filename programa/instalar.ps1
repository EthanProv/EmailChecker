param([switch]$PrepararWSL, [switch]$NoAbrir, [switch]$Empaquetar)
$ErrorActionPreference = 'Stop'
$raiz = Split-Path $PSScriptRoot -Parent
Set-Location $raiz
$datos = Join-Path $raiz 'datos'
$utf8 = [Text.UTF8Encoding]::new($false)

function Actualizar-Path {
    $rutas = @([Environment]::GetEnvironmentVariable('Path','Machine'), [Environment]::GetEnvironmentVariable('Path','User'), $env:Path)
    $rutas += @((Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin'), (Join-Path $env:ProgramFiles 'Docker/Docker/resources/bin'))
    $env:Path = $rutas -join ';'
}
function Buscar-Thunderbird {
    $rutas = @((Join-Path $env:ProgramFiles 'Mozilla Thunderbird/thunderbird.exe'), (Join-Path $env:LOCALAPPDATA 'Programs/Mozilla Thunderbird/thunderbird.exe'), (Join-Path $env:LOCALAPPDATA 'Mozilla Thunderbird/thunderbird.exe'))
    foreach ($ruta in $rutas) { if (Test-Path $ruta) { return $ruta } }
    foreach ($registro in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\thunderbird.exe','HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\thunderbird.exe')) {
        if (Test-Path $registro) { $ruta = (Get-Item $registro).GetValue(''); if ($ruta -and (Test-Path $ruta)) { return $ruta } }
    }
}
function Instalar-Paquete($Id, $Opciones) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'Falta App Installer de Microsoft. Instalalo desde Microsoft Store y vuelve a abrir EmailChecker.' }
    Write-Host "Instalando $Id... Puede aparecer una confirmacion de Windows."
    $antes = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; & winget install --id $Id --exact --source winget --silent --no-upgrade --accept-source-agreements --accept-package-agreements --disable-interactivity @Opciones; $codigo = $LASTEXITCODE }
    finally { $ErrorActionPreference = $antes }
    if ($codigo -ne 0) { throw "No se pudo instalar $Id. Revisa el mensaje anterior y vuelve a ejecutar EmailChecker." }
    Actualizar-Path
}
function Configurar-Modelo($Gpu) {
    $ruta = Join-Path $PSScriptRoot '.env'
    $lineas = @()
    if (Test-Path $ruta) { $lineas = @(Get-Content $ruta) }
    # Respetar un modelo que el usuario ya haya elegido.
    if (-not ($lineas | Where-Object { $_ -match '^\s*OLLAMA_MODEL\s*=\s*\S+' })) {
        $modelo = 'qwen3:0.6b'
        if ($Gpu) { $modelo = 'qwen3:4b' }
        $lineas += "OLLAMA_MODEL=$modelo"
        [IO.File]::WriteAllLines($ruta, [string[]]$lineas, $utf8)
        return $true
    }
    return $false
}
function Comprobar-WSL {
    $antes = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $version = & wsl.exe --version 2>$null
    $codigo = $LASTEXITCODE
    $ErrorActionPreference = $antes
    if ($codigo -eq 0 -and (($version -join ' ') -match '(\d+\.\d+\.\d+)') -and [version]$Matches[1] -ge [version]'2.1.5') { return }
    Write-Host 'Preparando WSL 2. Windows pedira permiso de administrador.'
    $argumentos = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -PrepararWSL'
    $proceso = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList $argumentos -Wait -PassThru
    if ($proceso.ExitCode -eq 3010) { throw 'WSL necesita un reinicio. Reinicia Windows cuando puedas y vuelve a abrir EmailChecker.cmd. No se reiniciara automaticamente.' }
    if ($proceso.ExitCode -ne 0) { throw 'No se pudo preparar WSL. Revisa datos/resultados/instalacion-wsl.log.' }
}
try {
    if ($Empaquetar) {
        $temporal = Join-Path $datos ('resultados/paquete-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path (Join-Path $temporal 'programa'),(Join-Path $temporal 'datos/ejemplos') | Out-Null
        foreach ($nombre in @('EmailChecker.cmd','README.md','.gitignore','.gitattributes')) { Copy-Item -LiteralPath (Join-Path $raiz $nombre) -Destination $temporal }
        Get-ChildItem $PSScriptRoot -File -Force | Where-Object { $_.Extension -in @('.py','.ps1','.sh','.yaml') -or $_.Name -in @('Dockerfile','.env.example','.dockerignore') } | Copy-Item -Destination (Join-Path $temporal 'programa')
        foreach ($nombre in @('01_legitimate','02_attachment','03_phishing','04_mismatch','05_injection','06_mime')) { Copy-Item -LiteralPath (Join-Path $datos "ejemplos/$nombre.eml") -Destination (Join-Path $temporal 'datos/ejemplos') }
        $zip = Join-Path $datos 'resultados/EmailChecker.zip'
        # Usar rutas ZIP estandar e incluir los archivos con punto.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Add-Type -AssemblyName System.IO.Compression
        $flujo = [IO.File]::Open($zip, 'Create', 'ReadWrite', 'None')
        $archivo = [IO.Compression.ZipArchive]::new($flujo, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($item in Get-ChildItem $temporal -Recurse -File -Force) {
                $relativo = $item.FullName.Substring($temporal.Length + 1).Replace('\','/')
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archivo,$item.FullName,$relativo) | Out-Null
            }
        } finally { $archivo.Dispose() }
        $carpetaResultados = [IO.Path]::GetFullPath((Join-Path $datos 'resultados'))
        if (-not $temporal.StartsWith($carpetaResultados + [IO.Path]::DirectorySeparatorChar) -or [IO.Path]::GetFileName($temporal) -notmatch '^paquete-[a-f0-9]{32}$') { throw 'Ruta temporal inesperada.' }
        Remove-Item -LiteralPath $temporal -Recurse -Force
        Write-Host "Paquete limpio para compartir: $zip"
        exit 0
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $datos 'cuentas'),(Join-Path $datos 'resultados') | Out-Null
    if ($PrepararWSL) {
        $registro = Join-Path $datos 'resultados/instalacion-wsl.log'
        $ErrorActionPreference = 'Continue'
        & wsl.exe --install --no-distribution --web-download >> $registro 2>&1
        $codigo = $LASTEXITCODE
        if ($codigo -notin @(0,3010)) { exit 1 }
        if ($codigo -eq 3010) { exit 3010 }
        & wsl.exe --update --web-download >> $registro 2>&1
        if ($LASTEXITCODE -ne 0) { exit 1 }
        $pendiente = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction Stop
        if ($pendiente.State -ne 'Enabled') { exit 3010 }
        exit 0
    }
    Write-Host 'EmailChecker: instalacion automatica para Windows de 64 bits.'
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { throw 'Se necesita Windows y PowerShell de 64 bits.' }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Este instalador esta preparado para Windows x64, no para ARM.' }
    $sistema = Get-CimInstance Win32_OperatingSystem
    if ($sistema.ProductType -ne 1 -or [int]$sistema.BuildNumber -lt 19045) { throw 'Se necesita una version compatible y actualizada de Windows 10/11, no Windows Server.' }
    if ([long]$sistema.TotalVisibleMemorySize -lt 7GB/1KB) { throw 'Se necesitan al menos 8 GB de RAM para Docker y la IA.' }
    Actualizar-Path
    $motorListo = $false
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $ErrorActionPreference = 'Continue'; & docker info *> $null; $motorListo = $LASTEXITCODE -eq 0; $ErrorActionPreference = 'Stop'
    }
    if (-not $motorListo) {
        $equipo = Get-CimInstance Win32_ComputerSystem
        $procesadores = Get-CimInstance Win32_Processor
        if (-not $equipo.HypervisorPresent -and -not ($procesadores | Where-Object VirtualizationFirmwareEnabled)) { throw 'Activa la virtualizacion en la BIOS/UEFI del ordenador y vuelve a intentarlo.' }
        Comprobar-WSL
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Instalar-Paquete 'Docker.DockerDesktop' @('--override','install --user --quiet --accept-license --backend=wsl-2') }
    $thunderbird = Buscar-Thunderbird
    if (-not $thunderbird) { Instalar-Paquete 'Mozilla.Thunderbird' @('--architecture','x64'); $thunderbird = Buscar-Thunderbird }
    if (-not $thunderbird) { throw 'Thunderbird no aparece instalado. Vuelve a abrir EmailChecker.' }
    $gpu = $false
    if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
        $ErrorActionPreference = 'Continue'
        $memorias = & nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -eq 0) { $gpu = [bool]($memorias | Where-Object { $_ -match '^\s*\d+\s*$' -and [int]$_.Trim() -ge 6000 }) }
        $ErrorActionPreference = 'Stop'
    }
    $modeloAutomatico = Configurar-Modelo $gpu
    $inicio = @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'inicio.ps1'),'start')
    if (-not $gpu) { $inicio += '-Cpu' }
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @inicio
    if ($LASTEXITCODE -ne 0 -and $gpu) {
        Write-Host 'La GPU no esta disponible para Docker. Se usara CPU.'
        $gpu = $false
        if ($modeloAutomatico) {
            $ruta = Join-Path $PSScriptRoot '.env'
            [IO.File]::WriteAllText($ruta, ([IO.File]::ReadAllText($ruta) -replace '(?m)^OLLAMA_MODEL=.*$', 'OLLAMA_MODEL=qwen3:0.6b'), $utf8)
        }
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @inicio -Cpu
    }
    if ($LASTEXITCODE -ne 0) { throw 'No se pudieron preparar los servicios. Revisa datos/resultados/operaciones.log.' }
    & (Join-Path $PSScriptRoot 'thunderbird.ps1') -ThunderbirdExe $thunderbird
    $instalacion = @{version=1;gpu=$gpu;thunderbird=$thunderbird;perfil=(Join-Path $datos 'thunderbird');fecha=(Get-Date -Format o)}
    [IO.File]::WriteAllText((Join-Path $datos 'cuentas/instalacion.json'), ($instalacion | ConvertTo-Json), $utf8)
    $config = Join-Path $PSScriptRoot '.env'
    if (-not ((Get-Content $config) -match '^\s*VT_API_KEY\s*=\s*\S+')) {
        Write-Host 'VirusTotal es opcional. Cada persona debe usar su propia clave.'
        if ((Read-Host 'Quieres configurarlo ahora? s/N') -eq 's') {
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'inicio.ps1') virustotal
            if ($LASTEXITCODE -ne 0) { Write-Host 'Puedes configurarlo despues con la opcion 7.' }
        }
    }
    if (-not $NoAbrir) { & (Join-Path $PSScriptRoot 'thunderbird.ps1') -ThunderbirdExe $thunderbird -SoloAbrir }
    Write-Host 'Instalacion terminada: cuentas y contrasenas configuradas.' -ForegroundColor Green
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
