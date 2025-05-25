import questionary
import sys
from libnmap.parser import NmapParser
# from questionary import Style
from prompt_toolkit.styles import Style

import hh.mimi_parser
import hh.utils
from typing import List

from app import db, nmap_store, nmap_queue
from models import Host, Credentials
from colorama import Fore

from .win import *
from .lin import *
from .creds import *
from .host import *
from .misc import *

choices = []


class MenuChoice:
    def __init__(self, path, validator, function, help=''):
        self.path = path
        self.validator = validator
        self.function = function
        self.help = help

    def validate(self, selection):
        match = hh.utils.research(self.validator, selection)
        if match:

            # remove None keys
            kwargs = match.groupdict()
            for key in list(kwargs.keys()):
                if kwargs[key] is None:
                    del kwargs[key]

            self.function(**kwargs)
            return True


class MenuSection:
    def __init__(self, name):
        self.name = name


def gen_help():
    """Tries to generate a help menu from the choices"""
    lines = []
    for i, choice in enumerate(choices):
        if type(choice) is MenuSection:
            if i == 0:
                lines.append('[*] ' + choice.name)
            else:
                lines.append('\n[*] ' + choice.name)
        else:
            lines.append(f'{choice.path.ljust(20)}{choice.help}')
    print('\n'.join(lines))


def get_nmap_progress():
    """Calulcates how many tasks are running"""
    all_tasks = 0
    finished_tasks = 0
    running_tasks = 0
    queued_tasks = nmap_queue.qsize()

    for taskid, task in nmap_store.items():
        if task.finished:
            finished_tasks += 1
        elif task.started and not task.failed and not task.finished:
            running_tasks += 1

        all_tasks += 1

    # do not print anything if all tasks are completed
    if finished_tasks == all_tasks:
        return ''

    return f'[Q:{queued_tasks}/R:{running_tasks}/F:{finished_tasks}]'


def exit():
    sys.exit(0)


def menu():
    global choices

    custom_style = Style.from_dict({
        "question": "default",
        "answer": "#fff nobold",
        "highlighted": "#fff nobold",
        "completion-menu.completion.current": "bg:#1D1D1D #ef9f76",  # Style for selected item
        "completion-menu.completion": "bg:#303042 #ef9f76",  # Style for non-selected items
    })

    # yapf: disable
    choices = [
        MenuSection('Misc'),
        MenuChoice('sliver setup', r'sliver setup', gen_sliver_jobs, help='Basic Sliver setup'),
        MenuChoice('clear', r'^clear$', clear, help='Clears the database'),
        MenuChoice('help', r'^(help|h)$', gen_help, help='Displays this help menu'),
        MenuChoice('verify tools', r'^verify tools$', verify_tools, help='Verify third party tools'),
        MenuChoice('change-octet', r'^change-octet$', change_octet, help='Hyper specific to OSEP'),
        MenuChoice('override ip', r'^override ip$', override_ip, help='Changes the IP in all of the tools to the new specified one'),
        MenuChoice('hostsfile', r'^hostsfile$', gen_hosts, help='Generates a /etc/hosts file template'),
        MenuChoice('gen markdown', r'^gen markdown$', gen_mdnotes, help='Generates Markdown Templates for Hosts'),
        MenuChoice('gen mdtable', r'^gen mdtable$', gen_mdtable, help='Generates Markdown Table for Obsidian'),
        MenuChoice('discover network', r'^discover network$', discover_network, help='Discovers the targeted network'),
        MenuChoice('exit', r'^exit$', exit),

        # TODO think about this
        MenuChoice('serve', r'serve', None, help='New way to serve files?'),
        MenuSection('Windows'),
        MenuChoice('win powerview', r'win powerview', win_powerview),
        MenuChoice('win powerup', r'win powerup', win_powerup),
        MenuChoice('win privesccheck', r'win privesccheck', win_privesccheck, 'itm4n PrivescCheck'),
        MenuChoice('win shell', r'win shell ?(?P<port>.+)?', win_shell, help='Optional port'),
        MenuChoice('win pillage', r'^win pillage$', win_pillage),
        MenuChoice('win peas', r'win peas', win_peas),
        MenuChoice('win enum', r'win enum', win_enum),
        MenuChoice('win ligolo', r'^win ligolo$', win_ligolo),
        MenuChoice('win powermad', r'^win powermad$', win_powermad),
        MenuChoice('win sharphound', r'^win sharphound$', win_sharphound),
        MenuChoice('win powerhound', r'^win powerhound$', win_powerhound, help='executes SharpHound.ps1'),
        MenuChoice('win autohound', r'^win autohound$', win_autohound, help='Executes SharpHound and exfiltrates the zip file'),
        MenuChoice('win beacon', r'^win beacon$', win_beacon, help='Deploys OneForAll stager'),
        MenuChoice('win godpotato', r'^win godpotato$', win_godpotato, help='Exploits SeImpersonatePrivilege'),
        MenuChoice('win printspoofer', r'^win printspoofer$', win_printspoofer, help='Exploits SeImpersonatePrivilege'),
        MenuChoice('win pwn', r'^win pwn$', win_pwn, help='Mutli Enum Script'),
        MenuChoice('win nightmare', r'^win nightmare$', win_nightmare, help='CVE-2021-1675'),
        MenuChoice('win mssqland', r'^win mssqland$', win_mssqland),
        MenuChoice('win sliverhound', r'^win sliverhound$', win_sliverhound, help='Run bloodhound via sliver beacon'),
        MenuChoice('win vpn_healtcheck', r'^win vpn_healtcheck$', win_vpn_healtcheck, help='Hyper specific for OffSec VPN'),
        MenuChoice('win applocker', r'^win applocker$', win_applocker, help='Custom AWL InstallUtil bypass gain access to a unconstrained PowerShell with Amsi Bypass'),
        MenuChoice('win rubeus', r'^win rubeus$', win_rubeus),
        MenuChoice('win serve', r'^win serve ?(?P<filepath>.+)$', None, help='win serve <file> | Hosts any file and generates a command to download it'),
        MenuChoice('win psexec', r'^win psexec$', win_psexec, help='Sysinternals PSExec'),
        MenuChoice('win fodhelper', r'^win fodhelper$', win_fodhelper, help='Abuse Fodhelper to bypass UAC'),
        MenuChoice('win download', r'^win download$', win_download, help='Exfiltrates the current working directory'),
        MenuChoice('win spoolsample', r'^win spoolsample$', win_spoolsample, help='SpoolSample to coerce spooler service'),
        MenuChoice('win everything', r'^win everything$', win_everything, help='Everything Binary to search for files'),
        MenuChoice('win lazagne', r'^win lazagne$', win_lazagne),
        MenuChoice('win sigmapotato', r'^win sigmapotato$', win_sigmapotato),
        MenuChoice('win amsibypass', r'^win amsibypass$', win_amsibypass, help='Basic Amsi Bypass for PowerShell'),
        MenuChoice('win uac', r'^win uac$', win_uac),
        MenuChoice('win local', r'^win local$', win_local),
        MenuChoice('win proof', r'^win proof$', win_proof),
        MenuSection('Linux'),
        MenuChoice('lin shell', r'^lin shell ?(?P<port>.+)?', lin_shell, help='lin shell <port=4444> | Optional port defaults to 4444'),
        MenuChoice('lin beacon', r'^lin beacon$', lin_beacon),
        MenuChoice('lin pillage', r'^lin pillage$', lin_pillage),
        MenuChoice('lin pspy', r'^lin pspy$', lin_pspy),
        MenuChoice('lin peas', r'^lin peas$', lin_peas),
        MenuChoice('lin enum', r'^lin enum$', lin_enum, help='My own enum script for Linux'),
        MenuChoice('lin ligolo', r'^lin ligolo$', lin_ligolo),
        MenuChoice('lin traitor', r'^lin traitor$', lin_traitor),
        MenuChoice('lin download', r'^lin download$', lin_download, help='Exfiltrates the current working directory'),
        MenuChoice('lin local', r'^lin local$', lin_local),
        MenuChoice('lin proof', r'^lin proof$', lin_proof),
        MenuSection('Credentials'),
        MenuChoice('creds add', r'^creds add$', creds_add),
        MenuChoice('creds edit', r'^creds edit$', creds_edit),
        MenuChoice('creds delete', r'^creds delete$', creds_delete),
        MenuChoice('creds use', r'^creds use$', creds_use),
        MenuChoice('creds spray username allproto', r'^creds spray username allproto$', creds_spray_username_allproto, help='This will spray the username for all protocals: ssh, smb, rdp, winrm'),
        MenuChoice('creds spray username', r'^creds spray username$', creds_spray_username),
        MenuChoice('creds', r'^creds ?(?P<filter>.+)?$', creds, help='creds <filter:str> | Optional filter searches in domain, username'),
        MenuSection('Host'),
        MenuChoice('host full', r'^host full$', host_full),
        MenuChoice('host add', r'^host add$', host_add),
        MenuChoice('host edit', r'^host edit$', host_edit),
        MenuChoice('host delete', r'^host delete$', host_delete),
        MenuChoice('host info', r'^host info (?P<id>.+)$', host_info, help='host info <id> | displays nmap scan results'),
        MenuChoice('host scan', r'^host scan$', host_scan, help='Adds a new host and scans it with nmap, you can specify multiple IPs delimited by a comma'),
        MenuChoice('host ffuf', r'^host ffuf$', host_ffuf),
        MenuChoice('host mark', r'^host mark$', host_mark, help='Mark host as compromised'),
        MenuChoice('host web', r'^host web$', host_web, help='Shows all possible websites'),
        MenuChoice('host', r'^host ?(?P<filter>.+)?$', host, help='host <filter:str> | Optional filter searches in ports, ip, name, users'),
    ]
    # yapf: enable

    autoselection_choices = [c for c in choices if type(c) is MenuChoice]

    try:
        last_selection = None
        while True:
            prefix = ''
            if cfg.OVERRIDE_IP:
                prefix = f'[{cfg.OVERRIDE_IP}] '

            prefix += get_nmap_progress()
            selection = questionary.autocomplete(prefix + '->',
                                                 choices=[c.path for c in autoselection_choices],
                                                 qmark='★',
                                                 style=custom_style).unsafe_ask()  # unsafe needed for keyboard interupt

            if selection == '!!':
                selection = last_selection

            # what happenss when multiple match?
            for choice in autoselection_choices:
                result = choice.validate(selection)
                if result:
                    last_selection = selection
                    break

    except KeyboardInterrupt:
        return
