param(
  [string[]]$Ports = @("3000", "4000")
)

$ErrorActionPreference = "Stop"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

foreach ($rawPort in $Ports) {
  $portValues = $rawPort -split ","
  foreach ($portValue in $portValues) {
    if ([string]::IsNullOrWhiteSpace($portValue)) { continue }
    $port = [int]$portValue.Trim()

  $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  foreach ($connection in $connections) {
    $ownerPid = [int]$connection.OwningProcess
    if ($ownerPid -eq $PID) {
      continue
    }

    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$ownerPid" -ErrorAction SilentlyContinue
    if ($null -eq $processInfo) {
      continue
    }

    $commandLine = [string]$processInfo.CommandLine
    if ($commandLine -notlike "*$workspaceRoot*") {
      Write-Host "Port $port is used by PID $ownerPid outside this workspace; leaving it running."
      continue
    }

    Write-Host "Stopping SideraScan dev process PID $ownerPid on port $port."
      Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue
    }
  }
}
