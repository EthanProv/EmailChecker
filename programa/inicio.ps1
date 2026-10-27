param([string]$Action = 'menu', [switch]$Cpu)
Set-Location (Split-Path $PSScriptRoot -Parent)
$compose = @('compose','-f','programa/compose.yaml')
$instalado = Join-Path (Get-Location) 'datos/cuentas/instalacion.json'
$gpu = [bool](Get-Command nvidia-smi -ErrorAction SilentlyContinue)
if (Test-Path $instalado) { $gpu = [bool](Get-Content -Raw $instalado | ConvertFrom-Json).gpu }
if (-not $Cpu -and $gpu) { $compose += @('-f','programa/compose.gpu.yaml') }
$datos = Join-Path (Get-Location) 'datos'
$log = Join-Path $datos 'resultados/operaciones.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null

function Ejecutar-Docker {
    param([string[]]$Comando, [switch]$Mostrar)
    if ($Mostrar) {
        & docker @Comando
    } else {
        & docker @Comando 2>&1 | ForEach-Object { $_.ToString() } | Out-File $log -Append
    }
    if ($LASTEXITCODE -ne 0) { throw 'La operacion ha fallado. El detalle esta en datos/resultados/operaciones.log.' }
}

function Iniciar {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Primero instala Docker Desktop.' }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Abriendo Docker Desktop...'
        Ejecutar-Docker @('desktop','start')
        $limite = (Get-Date).AddMinutes(3)
        do {
            Start-Sleep -Seconds 3
            & docker info *> $null
            if ($LASTEXITCODE -eq 0) { break }
        } while ((Get-Date) -lt $limite)
        if ($LASTEXITCODE -ne 0) { throw 'Espera a que Docker Desktop este listo y vuelve a intentarlo.' }
    }
    Write-Host 'Preparando correo e IA...'
    Ejecutar-Docker ($compose + @('build','analyzer','milter'))
    Ejecutar-Docker ($compose + @('up','-d','--wait','--wait-timeout','180','ollama'))
    $config = & docker @compose config --format json
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo leer la configuracion.' }
    $modelo = ($config | ConvertFrom-Json).services.analyzer.environment.OLLAMA_MODEL
    $modelos = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 15
    if (-not ($modelos.models | Where-Object { $_.name -eq $modelo })) {
        Write-Host 'Descargando la IA por primera vez...'
        Ejecutar-Docker ($compose + @('exec','-T','ollama','ollama','pull',$modelo))
    }
    Ejecutar-Docker ($compose + @('run','--rm','--no-deps','--volume',($datos + '/cuentas:/app/mail-config'),'analyzer','python','preparar.py'))
    if (-not ((Test-Path datos/cuentas/cert.pem) -and (Test-Path datos/cuentas/key.pem))) {
        Ejecutar-Docker ($compose + @('run','--rm','--no-deps','--entrypoint','openssl','mailserver','req','-x509','-newkey','rsa:2048','-nodes','-days','365','-keyout','/tmp/docker-mailserver/key.pem','-out','/tmp/docker-mailserver/cert.pem','-subj','/CN=localhost','-addext','basicConstraints=critical,CA:false','-addext','keyUsage=critical,digitalSignature,keyEncipherment','-addext','extendedKeyUsage=serverAuth','-addext','subjectAltName=DNS:localhost,DNS:mail.empresa.lab,IP:127.0.0.1,IP:::1'))
    }
    $cuentas = Get-Content -Raw -Encoding UTF8 datos/cuentas/credentials.json | ConvertFrom-Json
    foreach ($cuenta in $cuentas.PSObject.Properties) {
        $existe = (Test-Path datos/cuentas/postfix-accounts.cf) -and (Select-String -Path datos/cuentas/postfix-accounts.cf -SimpleMatch ($cuenta.Name + '|') -Quiet)
        if (-not $existe) {
            Ejecutar-Docker ($compose + @('run','--rm','--no-deps','mailserver','setup','email','add',$cuenta.Name,$cuenta.Value))
        }
    }
    Ejecutar-Docker ($compose + @('up','-d','--wait','--wait-timeout','240','milter','mailserver'))
    Write-Host 'EmailChecker esta listo.' -ForegroundColor Green
}

function Configurar-VirusTotal {
    $segura = Read-Host 'Pega tu clave API de VirusTotal (no se mostrara)' -AsSecureString
    $puntero = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($segura)
    try {
        $clave = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($puntero)
        if ($clave -notmatch '^[A-Za-z0-9_-]{16,200}$') { throw 'La clave tiene un formato invalido.' }
        $enlaces = '0'
        if ((Read-Host 'Consultar tambien enlaces? Se enviaran sus URLs completas a VirusTotal. s/N') -eq 's') { $enlaces = '1' }
        $ruta = Join-Path $PSScriptRoot '.env'
        $lineas = @()
        if (Test-Path $ruta) { $lineas = @(Get-Content $ruta) }
        $lineas = @($lineas | Where-Object { $_ -notmatch '^\s*(?:export\s+)?(VT_API_KEY|REPUTATION_HASHES|REPUTATION_URLS)\s*=' })
        $lineas += @("VT_API_KEY=$clave", 'REPUTATION_HASHES=1', "REPUTATION_URLS=$enlaces")
        [IO.File]::WriteAllLines($ruta, [string[]]$lineas, [Text.UTF8Encoding]::new($false))
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($puntero)
        $clave = $null
        $segura.Dispose()
    }
    Iniciar
    Write-Host 'VirusTotal configurado para adjuntos y las opciones elegidas.' -ForegroundColor Green
}

function Ejecutar {
    param([string]$Opcion)
    switch ($Opcion) {
        'start' { Iniciar }
        'thunderbird' {
            if (-not (Test-Path $instalado)) { throw 'Primero ejecuta EmailChecker.cmd install.' }
            Iniciar
            $configuracion = Get-Content -Raw $instalado | ConvertFrom-Json
            & (Join-Path $PSScriptRoot 'thunderbird.ps1') -ThunderbirdExe $configuracion.thunderbird -SoloAbrir
        }
        'virustotal' { Configurar-VirusTotal }
        'analyze' {
            Iniciar
            Ejecutar-Docker ($compose + @('run','--rm','--no-deps','analyzer','python','analizar.py'))
            Write-Host 'El informe esta listo. Elige Ver informe.'
        }
        'results' {
            if (-not (Test-Path datos/resultados/informe.html)) { throw 'Primero analiza los archivos.' }
            Invoke-Item datos/resultados/informe.html
        }
        'queue' { Ejecutar-Docker ($compose + @('exec','-T','mailserver','postqueue','-p')) -Mostrar }
        'stop' { Ejecutar-Docker ($compose + @('stop')); Write-Host 'Programa detenido. Los correos se conservan.' }
        'check' {
            Iniciar
            Ejecutar-Docker ($compose + @('run','--rm','--no-deps','analyzer','python','pruebas.py'))
            Get-Content -Raw programa/probar.py | & docker @compose exec -T -w /tmp/docker-mailserver mailserver python3 - >> $log 2>&1
            if ($LASTEXITCODE -ne 0) { throw 'La prueba de correo ha fallado. Consulta datos/resultados/operaciones.log.' }
            Write-Host 'Correo normal recibido y correo sospechoso retenido.' -ForegroundColor Green
        }
        default { throw 'Opcion desconocida.' }
    }
}

if ($Action -ne 'menu') {
    try { Ejecutar $Action; exit 0 } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
}
while ($true) {
    Write-Host "`nEmailChecker`n1. Iniciar`n2. Probar`n3. Analizar archivos`n4. Ver informe`n5. Ver cuarentena`n6. Detener`n7. Configurar VirusTotal`n8. Abrir correo en Thunderbird`n0. Salir"
    $opcion = Read-Host 'Elige un numero'
    if ($opcion -eq '0') { exit 0 }
    $acciones = @{'1'='start';'2'='check';'3'='analyze';'4'='results';'5'='queue';'6'='stop';'7'='virustotal';'8'='thunderbird'}
    if ($acciones.ContainsKey($opcion)) {
        try { Ejecutar $acciones[$opcion] } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
        Read-Host 'Pulsa Intro para volver al menu' | Out-Null
    }
}
