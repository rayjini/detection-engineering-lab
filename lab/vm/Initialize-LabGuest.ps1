#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-time hardening-for-visibility of the lab guest. Run INSIDE the VM.

.DESCRIPTION
    * Enables PowerShell Script Block + Module logging (Microsoft-Windows-PowerShell/Operational
      4104/4103) so decoded -EncodedCommand payloads are visible, not just the base64.
    * Enables command-line capture in Security 4688 (useful when Sysmon is missing).
    * Excludes C:\AtomicRedTeam from Microsoft Defender so atomic payloads are not
      deleted before they run. The rest of Defender stays on - its alerts are
      useful telemetry too.

    LAB ONLY. Never run this on a machine you care about.
#>
$ErrorActionPreference = 'Stop'

$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force "$ps\ScriptBlockLogging" | Out-Null
Set-ItemProperty "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item -Force "$ps\ModuleLogging\ModuleNames" | Out-Null
Set-ItemProperty "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*'

$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Force $audit | Out-Null
Set-ItemProperty $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null

New-Item -ItemType Directory -Force C:\AtomicRedTeam | Out-Null
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'

Write-Host 'Guest configured: PowerShell logging on, 4688 command lines on, Defender exclusion for C:\AtomicRedTeam.'
Write-Host 'Next: lab\sysmon\Install-Sysmon.ps1, then lab\elastic\Install-Winlogbeat.ps1'
