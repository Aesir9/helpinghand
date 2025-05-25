import base64
import os
import re
from collections import namedtuple
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen
from typing import List, Union

import pyperclip
import questionary
import prettytable
from colorama import Back, Fore, Style, init
import log
from app import db
from config import cfg
from models import Credentials, Host

call_result = namedtuple('call_result', ['stdout', 'stderr', 'status', 'status_code'])


def empty_if_none(thing, newlines=False, delimiter=','):
    """
    :params: `thing` just a string
    :params: `newlines` if string should be split by delimiter and joined by newlines
    :params: `delimiter` see above
    """
    if thing is None:
        return ''

    if newlines:
        return '\n'.join(thing.split(delimiter))
    return thing


def services_to_string(services, truncate=False):
    """
    This adds a new line if more than 8 ports are on one line
    """
    if not truncate:
        return ', '.join([str(x) for x in services])

    out = ''
    for i, port in enumerate(services):
        append = ''
        if i != 0:
            append = ', '
        if not i % 8:
            append += '\n'
        out += append + str(port)
    return out.strip()


def get_hh_folder():
    """
    if you move this function verify the that it 
    returns the correct path
    """
    this_file = Path(__file__).resolve()
    return this_file.parent.parent


def get_ip(ignore_cfg=False):
    if cfg.OVERRIDE_IP is not None and ignore_cfg == False:
        return cfg.OVERRIDE_IP

    if os.name == 'nt':
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # doesn't even have to be reachable
            s.connect(('10.254.254.254', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    cr = os_call(['ip', '-4', '-br', 'address'])
    ip = None

    for line in cr.stdout.split('\n'):
        if 'tun0' in line:
            p = line.strip().split(' ')
            ip = p[-1].split('/')[0]
    return ip


def get_web():
    """
    Returns an http url with the correct ip
    
    :returns: an url with the trailing slash!
    """
    return f'http://{get_ip()}:{cfg.PORT}/'


def win_encode(cmd):
    cr = cmd.encode('utf-16le')
    enc = base64.b64encode(cr).decode('utf-8')
    powershell_enc = 'powershell -enc ' + enc
    pandc(powershell_enc)

    return powershell_enc


def pandc(cmd):
    print('\n' + cmd + '\n')
    try:
        pyperclip.copy(cmd)
    except:
        log.debug('Pyperclip error')


def to_clipboard(str, p=True, c=True):
    raise NotImplemented('use pyperclip')
    if p:
        # primary
        p = Popen(['xsel', '-pi'], stdin=PIPE)
        p.communicate(input=str.encode())
    if c:
        # secondary
        p = Popen(['xsel', '-bi'], stdin=PIPE)
        p.communicate(input=str.encode())


def os_call_realtime(command):
    process = Popen(command, stdout=PIPE, shell=True, stderr=STDOUT)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
        line = line.decode('utf-8')
        yield line


def os_call(args):
    try:
        process = Popen(args, stdout=PIPE, stderr=STDOUT)
    except FileNotFoundError as e:
        return call_result(None, None, 'failed', 1)

    _stdout, _stderr = process.communicate()

    stdout = _stdout.decode('utf-8')
    try:
        stderr = _stderr.decode('utf-8')
    except AttributeError as e:
        stderr = None

    if process.returncode == 0:
        return call_result(stdout, stderr, 'successful', process.returncode)
    return call_result(stdout, stderr, 'failed', process.returncode)


def cli_select_credentials(message, credentials: List[Credentials]) -> Credentials:
    selection = questionary.select(
        message,
        choices=[f'{str(c.id).ljust(4)}{c.domain}'.ljust(20) + c.username for c in credentials],
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()

    if not selection:
        return

    selected_id = int(selection.split(' ')[0].strip())
    creds = db.session.query(Credentials).filter_by(id=selected_id).first()
    return creds


def cli_select_host(message, hosts: List[Host]) -> Host:
    def gen_name(h):
        name = f'{str(h.id).ljust(4)}{h.address}'
        if h.name:
            name = name.ljust(20) + h.name
        return name

    selection = questionary.select(
        message,
        choices=[gen_name(h) for h in hosts],
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()

    if not selection:
        return

    selected_id = int(selection.split(' ')[0].strip())
    host = db.session.query(Host).filter_by(id=selected_id).first()
    return host


def questionary_text(prompt, value):
    """opinionated questionary text prompt, which returns a value or None"""
    answer = questionary.text(prompt, default='' if not value else value).ask()
    if answer == '':
        return None
    return answer


def print_creds_table(credentials: List[Credentials],
                      fields=['ID', 'Domain', 'Username', 'Password', 'NTLM', 'Source']):
    table = prettytable.PrettyTable(fields)
    table.set_style(prettytable.SINGLE_BORDER)
    table.align['Domain'] = 'l'
    table.align['Username'] = 'l'
    table.align['Password'] = 'l'
    for cred in credentials:
        table.add_row([
            empty_if_none(cred.id),
            empty_if_none(cred.domain),
            empty_if_none(cred.username),
            empty_if_none(cred.password),
            empty_if_none(cred.ntlm),
            empty_if_none(cred.source)
        ])

    print(table)


def get_current_last_cred_id():
    """
    Best function name ever
    """
    last_entry = Credentials.query.order_by(Credentials.id.desc()).first()

    if last_entry:
        return last_entry.id
    return 0


def print_hosts_table(hosts: List[Host], full=False):
    """
    :param: `full` Will print all columns
    """
    def gen_host_color(host: Host, string_to_color):
        """
        Normal: not compromised
        Green: user compromised
        Red: root compromised
        """
        if host.admin_compromised:
            return Fore.RED + string_to_color + Fore.RESET
        if host.user_compromised:
            return Fore.GREEN + string_to_color + Fore.RESET
        return string_to_color

    fields = ['ID', 'Address', 'Name', 'FQDN', 'Services']
    if full:
        fields.extend(['NICS', 'Local Users', 'User Profiles'])

    table = prettytable.PrettyTable(fields)

    table.set_style(prettytable.SINGLE_BORDER)
    table.align['Services'] = 'l'
    table.align['Local Users'] = 'l'
    table.align['User Profiles'] = 'l'

    for host in hosts:

        columns = [
            empty_if_none(host.id),
            gen_host_color(host, empty_if_none(host.address)),
            gen_host_color(host, empty_if_none(host.name)),
            gen_host_color(host, empty_if_none(host.fqdn)),
            services_to_string(host.service_targets, truncate=full)
        ]

        if full:
            columns.extend([
                empty_if_none(host.nics, newlines=True),
                empty_if_none(host.local_users, newlines=True),
                empty_if_none(host.user_profiles, newlines=True),
            ])

        table.add_row(columns)

    print(table)


def research(pattern, str) -> Union[str | None]:
    match = re.match(pattern, str)
    if match:
        return match
    return None


def ligolo_server_help():

    # ligolo server
    log.success('Server Tunnel Setup')
    print('ip tuntap add user kali mode tun ligolo')
    print('ip link set ligolo up\n')
    print('sudo /opt/ligolo-ng/proxy -selfcert\n')

    log.success('Double Pivot?')
    print('ip tuntap add user kali mode tun ligolo2')
    print('ip link set ligolo2 up\n')
    print('sudo /opt/ligolo-ng/proxy -selfcert -laddr 0.0.0.0:11602\n')

    log.success('Default Listeners')
    print(f'listener_add --addr 0.0.0.0:{cfg.PORT} --to 127.0.0.1:{cfg.PORT} --tcp')
    print('listener_add --addr 0.0.0.0:9001 --to 127.0.0.1:9001 --tcp\n')

    log.success('Sliver Listeners')
    print(f'listener_add --addr 0.0.0.0:{cfg.SLIVER_MTLS_PORT} --to 127.0.0.1:{cfg.SLIVER_MTLS_PORT} --tcp')
    print(f'listener_add --addr 0.0.0.0:{cfg.SLIVER_STAGER_PORT_32} --to 127.0.0.1:{cfg.SLIVER_STAGER_PORT_32} --tcp')
    print(f'listener_add --addr 0.0.0.0:{cfg.SLIVER_STAGER_PORT_64} --to 127.0.0.1:{cfg.SLIVER_STAGER_PORT_64} --tcp\n')
