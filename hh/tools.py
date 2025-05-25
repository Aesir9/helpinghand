import hh.utils
import subprocess
import os
import log


class ThirdPartyTool:
    """
    not only thirdparty but also my own tools???
    """
    def __init__(self, name, file_name, source=None, subfolder='dist'):
        self.name = name
        self.file_name = file_name
        self.source = source

        # override folderpath
        self.subfolder = subfolder

    def verify(self):
        """
        Verifies that the file exists, will raise an error
        """
        if not os.path.exists(self.fullpath):
            log.warning(f'Missing file for {self.name}, expected: {self.fullpath}, go grab it at {self.source}')

    @property
    def url(self):
        """
        Returns a url which hosts the binary
        """
        return hh.utils.get_web() + f'{self.subfolder}/{self.file_name}'

    @property
    def fullpath(self):
        current_folder = hh.utils.get_hh_folder()
        return os.path.join(current_folder, 'app', self.subfolder, self.file_name)

    @property
    def folder_path(self):
        current_folder = hh.utils.get_hh_folder()
        return os.path.join(current_folder, 'app', 'dist')


Twin_chisel = ThirdPartyTool('win-chisel', 'chisel.exe', 'https://github.com/jpillora/chisel')
Tlin_chisel = ThirdPartyTool('lin-chisel', 'chisel', 'https://github.com/jpillora/chisel')

Twin_ligolo_agent = ThirdPartyTool('win-ligolo-agent', 'agent.exe', 'https://github.com/nicocha30/ligolo-ng')
Twin_ligolo_proxy = ThirdPartyTool('win-ligolo-proxy', 'proxy.exe', 'https://github.com/nicocha30/ligolo-ng')
Tlin_ligolo_agent = ThirdPartyTool('lin-ligolo-agent', 'agent', 'https://github.com/nicocha30/ligolo-ng')
Tlin_ligolo_proxy = ThirdPartyTool('lin-ligolo-proxy', 'proxy', 'https://github.com/nicocha30/ligolo-ng')

Twinpeas_ps1 = ThirdPartyTool('winpeas-exe', 'winPEAS.ps1', 'https://github.com/peass-ng/PEASS-ng')
Twinpeas_exe = ThirdPartyTool('winpeas-ps1', 'winPEASany.exe', 'https://github.com/peass-ng/PEASS-ng')
Twinpeas_obf = ThirdPartyTool('winpeas-obf', 'winPEASany_ofs.exe', 'https://github.com/peass-ng/PEASS-ng')
Tlinpeas = ThirdPartyTool('linpeas', 'linpeas.sh', 'https://github.com/peass-ng/PEASS-ng')

Tlinse = ThirdPartyTool('linlse', 'linlse.sh', 'https://github.com/diego-treitos/linux-smart-enumeration')
Tpspy = ThirdPartyTool('pspy', 'pspy', 'https://github.com/DominicBreuker/pspy')
Tsuidenum = ThirdPartyTool('suid3num', 'suid3num.py', 'https://github.com/Anon-Exploiter/SUID3NUM')
Ttraitor = ThirdPartyTool('traitor', 'traitor', 'https://github.com/liamg/traitor')

Tprivesccheck = ThirdPartyTool('PrivescCheck', 'PrivescCheck.ps1', 'https://github.com/itm4n/PrivescCheck')
Tpowerupsql = ThirdPartyTool('PowerUpSQL', 'PowerUpSQL.ps1', 'https://github.com/NetSPI/PowerUpSQL')
Tpowerview = ThirdPartyTool('PowerView', 'PowerView.ps1',
                            'https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1')
Tpowerup = ThirdPartyTool('PowerUp.ps1', 'PowerUp.ps1', 'https://github.com/PowerShellMafia/PowerSploit/')

Tmimikatz = ThirdPartyTool('Mimikatz', 'mimikatz.exe', 'https://github.com/gentilkiwi/mimikatz')
Tmimidrv = ThirdPartyTool('mimidrv', 'mimidrv.sys', 'https://github.com/gentilkiwi/mimikatz')

Twin_powermad = ThirdPartyTool('Powermad', 'Powermad.ps1', 'https://github.com/Kevin-Robertson/Powermad')
Twin_oneforall = ThirdPartyTool('OneForAll', 'OneForAll.exe', 'your-own-gitlab')
Twin_pillage_stage1 = ThirdPartyTool('Pillage', 'TEMPLATE_Pillage.ps1', '', subfolder='custom')
Twin_pillage_stage2 = ThirdPartyTool('Pillage Stage2', 'TEMPLATE_Pillage-Stage2.ps1', '', subfolder='custom')
Tlin_pillage_stage1 = ThirdPartyTool('Pillage - Linux', 'TEMPLATE_Pillage.sh', '', subfolder='custom')
Tgodpotato = ThirdPartyTool('GodPotato', 'GodPotato.exe', 'https://github.com/BeichenDream/GodPotato')
Twinpwn = ThirdPartyTool('WinPwn', 'WinPwn.ps1', 'https://github.com/S3cur3Th1sSh1t/WinPwn')
Tnightmare = ThirdPartyTool('PrintNightmare', 'PrintNightmare.ps1', 'https://github.com/calebstewart/CVE-2021-1675')
Tlinenum = ThirdPartyTool('HHCompanion.sh', 'HHCompanion.sh', 'local', subfolder='custom')
Tmssqland = ThirdPartyTool('MSSQLand', 'MSSQLand.exe', 'https://github.com/n3rada/MSSQLand')
Twinvpncheck = ThirdPartyTool('vpn-healtcheck-client', 'vpn-healtcheck-client.exe',
                              'https://gitlab.a5r.local/d5k/pen-300')
Tsharphound = ThirdPartyTool('SharpHound', 'SharpHound.exe', 'https://github.com/SpecterOps/BloodHound')
Tpowerphound = ThirdPartyTool('SharpHound PowerShell', 'SharpHound.ps1', 'https://github.com/SpecterOps/BloodHound')
Tapplocker_awl = ThirdPartyTool('applocker-awl.exe', 'applocker-awl.exe', 'https://gitlab.a5r.local/d5k/pen-300')
Trubeus = ThirdPartyTool('Rubeus', 'Rubeus.exe', 'rubeus')
Tprintspoofer = ThirdPartyTool('PrintSpoofer', 'PrintSpoofer.exe', 'PrintSpoofer.exe')
Tpsexec = ThirdPartyTool('PsExec64', 'PsExec64.exe', 'PsExec64.exe')
Twinenum = ThirdPartyTool('HHCompanion.ps1', 'HHCompanion.ps1', 'local', subfolder='custom')
Tspoolsample = ThirdPartyTool('SpoolSample', 'SpoolSample.exe', 'https://github.com/leechristensen/SpoolSample')
Teverything = ThirdPartyTool('Everything', 'everything.exe', 'https://www.voidtools.com/downloads/')
Tlazagne = ThirdPartyTool('LaZagne', 'LaZagne.exe', '')
Tuacps1 = ThirdPartyTool(
    'uac', 'uac.ps1', 'https://freedium.cfd/https://medium.com/@harikrishnanp006/uac-bypass-on-windows-abe21d74f050')
Twuffamsi = ThirdPartyTool('wuff - amsi bypass', 'wuff.ps1', '')
Tsigmapotato = ThirdPartyTool('SigmaPotato.exe', 'SigmaPotato.exe',
                              'https://github.com/tylerdotrar/SigmaPotato/releases/tag/v1.2.6')

all_tools = [
    Twin_chisel, Tlin_chisel, Twin_ligolo_agent, Twin_ligolo_proxy, Tlin_ligolo_agent, Tlin_ligolo_proxy, Twinpeas_ps1,
    Twinpeas_exe, Twinpeas_obf, Tlinpeas, Tlinse, Tpspy, Tsuidenum, Ttraitor, Tprivesccheck, Tpowerupsql, Tpowerview,
    Tpowerup, Tmimikatz, Tmimidrv, Twin_powermad, Twin_oneforall, Twin_pillage_stage1, Twin_pillage_stage2, Tgodpotato,
    Twinpwn, Tnightmare, Tlinenum, Tmssqland, Twinvpncheck, Tsharphound, Tpowerphound, Tapplocker_awl, Trubeus,
    Tprintspoofer, Tpsexec, Twinenum, Tspoolsample, Tlazagne, Tuacps1, Twuffamsi, Tsigmapotato
]
