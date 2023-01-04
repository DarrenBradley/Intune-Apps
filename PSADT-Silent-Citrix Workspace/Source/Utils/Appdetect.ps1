<#
Version: 1.0
Author: (Darren Bradley)
Script: AppDetect.ps1
Description:
The script runs on the client and detects the installed applications to get the properites of the MSI codes and files for use with Intune Detections
Release notes:
Version 1.0: Original published version. 
#>

Clear-Host
$Hive = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
$Hive2 = Get-ChildItem -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
Write-Host -ForegroundColor Green "x64 Registry Hive - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall "
$Hive | Get-ItemProperty | Select-Object -Property PSChildName, DisplayName, DisplayVersion, UninstallString | Sort-Object DisplayName | Format-Table -AutoSize -Wrap
Write-Host -ForegroundColor Cyan "x86 Registry Hive - HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$Hive2 | Get-ItemProperty | Select-Object -Property PSChildName, DisplayName, DisplayVersion, UninstallString | Sort-Object DisplayName | Format-Table -AutoSize -Wrap