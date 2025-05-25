$ErrorActionPreference = 'silentlycontinue'

function Get-Services() {
    $hkservices = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | Select-Object Name 
    $services = foreach ($service in $hkservices) {
        $test = Get-Service $service.Name.replace('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\', '') 2>$null
        if ($test) {
            $data = Get-ItemProperty $service.Name.replace('HKEY_LOCAL_MACHINE', 'HKLM:') | Select-Object ImagePath, Name 2>$null

            New-Object PSObject -Property (@{
                    "Reg"       = $service.name
                    "ImagePath" = $data.ImagePath
                    "Name"      = $service.Name.replace('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\', '')
                })
        }
    }
    return $services
}

function SCQC($name) {
    $data = sc.exe qc $name | Out-String
    $keys = @("START_TYPE", "ERROR_CONTROL", "BINARY_PATH_NAME", "DISPLAY_NAME", "SERVICE_START_NAME")
    
    $obj = New-Object PSObject
    $data -split '\r\n' |
    ForEach-Object {
        foreach ($key in $keys) {
            if ($_.contains($key)) {
                Add-Member -InputObject $obj -NotePropertyName $key -NotePropertyValue $_.split(":")[-1].Trim()
            }
        }
    }
    Add-Member -InputObject $obj -NotePropertyName "Name" -NotePropertyValue $name
    return $obj
}

function SCQuery($obj) {
    $data = sc.exe query $obj.Name | Out-String
    $keys = @("STATE")

    $data -split '\r\n' |
    ForEach-Object {
        foreach ($key in $keys) {
            if ($_.contains($key)) {
                Add-Member -InputObject $obj -NotePropertyName $key -NotePropertyValue $_.split(":")[-1].Trim()
                
            }
        }
    }
    return $obj
}

function InstallElevated() {
    write-output ""
    write-output "[!] Checking if AlwaysInstallElevated is enabled"
    reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
}

function UserEnum() {
    write-output ""
    write-output "[!] Getting Users"
    Get-LocalUser | Format-Table -AutoSize

    write-output "[!] Whoami /all"
    whoami /all

    write-output "[!] Query user"
    query user

    write-output "[!] net localgroup administrators"
    net localgroup administrators
    
}

function InstalledSoftware() {
    write-output ""
    write-output "[!] Installed Software"
    $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
    $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
    $INSTALLED | ? { $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
}

function PasswordPolicy() {
    write-output ""
    write-output "[!] Password Policy"
    net accounts
}

function SySinfo() {
    write-output ""
    write-output "[!] Systeminfo"
    systeminfo
}

function ServicesAsSystem() {
    write-output ""
    write-output "[!] System Services"
    $services = Get-Services
    $usable = foreach ($service in $services) {
        $serv = SCQC($service.Name)
        if (($serv.PSobject.Properties.Name -contains "SERVICE_START_NAME" ) -and ($serv.SERVICE_START_NAME.Contains("LocalSystem")) -and ($serv.BINARY_PATH_NAME -notlike "*system32\svchost.exe*")) {
            SCQuery($serv)
        }
    }
    $usable | Select-Object START_TYPE, ERROR_CONTROL, Name, STATE, SERVICE_START_NAME, BINARY_PATH_NAME | Format-Table -AutoSize   
}

function UAC(){
    write-output ""
    write-output "[!] UAC"
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
}

function AutoRun(){
    write-output ""
    write-output "[!] Autorun"
    Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

}

function StickyNotes(){
    write-output ""
    write-output "[!] Sticky notes, for this user!"
    if (Test-Path "C:\Users\%USERNAME%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite" ){
        gci "C:\Users\%USERNAME%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\"
    }
}

function SavedCreds(){
    write-output ""
    write-output "[!] Saved Credentials"
    cmdkey /list
}

function Tasks(){
    write-output ""
    write-output "[!] Scheduled Tasks"
    Get-ScheduledTask | select TaskName,State
}

function DefaultUser(){
    write-output ""
    write-output "[!] Default User"
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"
}

function DomainTrust(){
    write-output ""
    write-output "[!] Domain Trusts"
    nltest /trusted_domains
}

function NeworkShares(){
    write-output ""
    write-output "[!] Network Shares"
    net share
}


function ClearTextCredentials(){
    write-output ""
    write-output "[!] Clear Text Credentials"
    findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
    findstr /spin "password" *.*
    Select-String -Path C:\*.txt -Pattern password
}

function PowerShellHistory(){
    write-output ""
    write-output "[!] PowerShell History"
    foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
}

function TreeUsers(){
    write-output ""
    write-output "[!] Tree from C:\Users"
    tree C:\Users /a /f
}



SySinfo
DomainTrust
UserEnum
NeworkShares
UAC
AutoRun
DefaultUser
StickyNotes
SavedCreds
InstallElevated
Tasks
PasswordPolicy
InstalledSoftware
ServicesAsSystem
# ClearTextCredentials
PowerShellHistory
TreeUsers

