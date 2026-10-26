param([ValidateSet('start','analyze','test','logs','stop','queue','status')][string]$Action = 'start', [switch]$Cpu)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$composeArgs = @('compose','-f','compose.yaml')
if (-not $Cpu) { $composeArgs += @('-f','compose.gpu.yaml') }
$composeArgs += @('-f','compose.mail.yaml')
switch ($Action) {
  'start' { & docker @composeArgs up -d ollama milter mailserver }
  'analyze' { & docker @composeArgs run --rm analyzer python -m antiphishing --batch samples --output results/manual }
  'test' { & docker @composeArgs run --rm analyzer python -m unittest discover -s tests -v }
  'logs' { & docker @composeArgs logs --tail 80 }
  'stop' { & docker @composeArgs stop }
  'queue' { & docker @composeArgs exec -T mailserver postqueue -p }
  'status' { & docker @composeArgs ps }
}
if ($LASTEXITCODE -ne 0) { throw "Docker terminó con código $LASTEXITCODE" }
