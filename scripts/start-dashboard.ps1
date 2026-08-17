param(
    [string]$HostAddress = '127.0.0.1',
    [int]$Port = 8787
)

$repoRoot = Split-Path -Parent $PSScriptRoot
python (Join-Path $repoRoot 'dashboard/server.py') --repo $repoRoot --host $HostAddress --port $Port
exit $LASTEXITCODE
