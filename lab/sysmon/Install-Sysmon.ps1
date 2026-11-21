#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (or reconfigures) Sysmon in the lab VM with lab/sysmon/sysmonconfig-lab.xml.

.DESCRIPTION
    Downloads the current Sysmon from Sysinternals, verifies its Authenticode
    signature, and installs it with the lab config. If Sysmon is already
    installed, only the configuration is updated (sysmon -c).

.EXAMPLE
    # inside the VM, from a copy of the repo:
    .\lab\sysmon\Install-Sysmon.ps1
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'sysmonconfig-lab.xml'),
    [string] $InstallDir = 'C:\Tools\Sysmon'
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$exe = Join-Path $InstallDir 'Sysmon64.exe'
if (-not (Test-Path $exe)) {
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    $zip = Join-Path $env:TEMP 'Sysmon.zip'
    Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
}

$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw "Sysmon64.exe signature check failed: $($sig.Status) $($sig.SignerCertificate.Subject)"
}

if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    & $exe -c $ConfigPath
} else {
    & $exe -accepteula -i $ConfigPath
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon exited with $LASTEXITCODE" }

# Smoke test: generate a process-creation event and read it back.
Start-Process cmd.exe -ArgumentList '/c echo sysmon-smoke-test' -WindowStyle Hidden -Wait
Start-Sleep -Seconds 2
$evt = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50 |
       Where-Object { $_.Id -eq 1 -and $_.Message -match 'sysmon-smoke-test' } | Select-Object -First 1
if ($evt) { Write-Host "OK: Sysmon logged Event ID 1 with CommandLine at $($evt.TimeCreated)" }
else      { Write-Warning 'Sysmon is running but the smoke-test Event ID 1 was not found.' }
