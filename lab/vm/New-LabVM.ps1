#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
<#
.SYNOPSIS
    Creates the Windows victim VM for the detection lab on Hyper-V.

.DESCRIPTION
    Generation 2 VM with Secure Boot + virtual TPM (required by Windows 11),
    attached to the Hyper-V "Default Switch" so it can reach the Elastic stack
    running on the host. Boots from the supplied Windows ISO; finish the
    install interactively, then run lab/vm/Initialize-LabGuest.ps1 inside it.

    Use a Windows 11 Enterprise *evaluation* ISO (90-day, free):
    https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise

.EXAMPLE
    .\lab\vm\New-LabVM.ps1 -IsoPath C:\ISO\Win11_Enterprise_Eval.iso
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateScript({ Test-Path $_ -PathType Leaf })] [string] $IsoPath,
    [string] $Name = 'LAB-WIN11',
    [string] $VmRoot = (Join-Path $env:PUBLIC 'Documents\Hyper-V\DetectionLab'),
    [int64]  $MemoryBytes = 4GB,
    [int64]  $DiskBytes = 64GB,
    [int]    $Cpus = 2,
    [string] $Switch = 'Default Switch'
)
$ErrorActionPreference = 'Stop'

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM '$Name' already exists." }

$vhd = Join-Path $VmRoot "$Name.vhdx"
New-Item -ItemType Directory -Force -Path $VmRoot | Out-Null

New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryBytes `
       -NewVHDPath $vhd -NewVHDSizeBytes $DiskBytes -SwitchName $Switch -Path $VmRoot | Out-Null
Set-VM -Name $Name -ProcessorCount $Cpus -StaticMemory -AutomaticCheckpointsEnabled $false
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
Enable-VMTPM -VMName $Name
Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

$dvd = Add-VMDvdDrive -VMName $Name -Path $IsoPath -Passthru
Set-VMFirmware -VMName $Name -FirstBootDevice $dvd

Write-Host "Created $Name ($([math]::Round($MemoryBytes/1GB)) GB RAM, $Cpus vCPU, $vhd)."
Write-Host "Next: Start-VM $Name; vmconnect localhost $Name   (press a key to boot the ISO)"
Write-Host "After setup + Initialize-LabGuest.ps1: Checkpoint-VM -Name $Name -SnapshotName clean-baseline"
