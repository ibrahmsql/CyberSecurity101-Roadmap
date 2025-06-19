<#
.SYNOPSIS
  WinEnum.ps1 – Minimal Windows enumeration script for labs
.DESCRIPTION
  Collects basic host information: OS details, running processes, installed patches, open TCP ports.
.NOTES
  Tested on Windows 10/11 PowerShell 5.1 and PowerShell 7+
#>

Write-Host "[+] Gathering system info…"
Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsProductName

Write-Host "`n[+] Running processes (top 10 by memory)…"
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name, Id, @{n='MB';e={[math]::round($_.WorkingSet/1MB)}}

Write-Host "`n[+] Installed patches (last 15)…"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 Description, HotFixID, InstalledOn

Write-Host "`n[+] Listening TCP ports…"  
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort

Write-Host "`n[+] Done."
