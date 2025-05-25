import questionary
import os
import re
from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess
import shlex

from app import db, nmap_queue
import hh.tmux
from models import Host
import hh.diff
import hh.utils
import hh.worker

import log


def host(filter=None):
    if filter:
        log.debug(f'Using filter on hosts: {filter}')

        hosts_filtered1 = db.session.query(Host).filter(
            (Host.name.icontains(filter) | Host.local_users.icontains(filter) | Host.address.icontains(filter) |
             Host.user_profiles.icontains(filter))).all()

        # filter ports
        hosts = [x for x in hosts_filtered1]
        hosts_filtered2 = db.session.query(Host).all()
        for host in hosts_filtered2:
            if filter in ' '.join([str(x) for x in host.service_targets]):
                hosts.append(host)

    else:
        hosts = Host.query.all()
    hh.utils.print_hosts_table(hosts)


def host_full():
    hosts = Host.query.all()
    hh.utils.print_hosts_table(hosts, full=True)


def host_add(file=None, automerge=False):
    """
    Add a new host
    TODO: parse directory structure to identify xml 
          and ask the user which  one he want's to index.
    """
    if not file:
        file = questionary.text('Nmap File').ask()

    if not file:
        return

    with open(file) as f:
        nmap_data = f.read()

    nmap_report = NmapParser.parse_fromstring(nmap_data)
    host = nmap_report.hosts

    for host in nmap_report.hosts:
        # ip is the unique identifier?

        host_db = Host.query.filter_by(address=host.address).first()

        if host_db:
            log.info('Already found data for this host, diff from  the new scan:')
            hh.diff.print_diff(nmap_report, NmapParser.parse_fromstring(host_db.nmap_xml))

            if not automerge:
                answer = questionary.confirm('Override with new scan results?').ask()
            else:
                answer = automerge

            if answer:
                host_db.nmap_xml = nmap_data
                db.session.commit()
                hh.utils.print_hosts_table([host_db])
        else:
            h = Host.from_nmap(host, nmap_data)

            db.session.add(h)
            db.session.commit()

            log.success('Added a new host!')
            hh.utils.print_hosts_table([h])


def host_edit():
    hosts = db.session.query(Host).all()
    hh.utils.print_hosts_table(hosts)

    host = hh.utils.cli_select_host('Select entry to edit', hosts)
    if not host:
        return

    host_id = host.id
    # no change address!
    # address = questionary.text('Address', default=host.address).ask()
    name = hh.utils.questionary_text('Name', host.name)
    fqdn = hh.utils.questionary_text('FQDN', host.fqdn)

    host.name = name
    host.fqdn = fqdn
    db.session.commit()

    log.success('Updated host infos!')
    host = db.session.query(Host).filter_by(id=host_id).first()
    hh.utils.print_hosts_table([host])


def host_delete():
    hosts = db.session.query(Host).all()
    hh.utils.print_hosts_table(hosts)
    host = hh.utils.cli_select_host('Select entry to edit', hosts)
    answer = questionary.confirm('Are you sure?').ask()
    if answer:
        db.session.delete(host)
        db.session.commit()

        log.info('Deleted the host')


def host_info(id):
    """displays the host by id"""
    host = db.session.query(Host).filter_by(id=id).first()
    if host:
        print_scan(NmapParser.parse_fromstring(host.nmap_xml))
    else:
        print.log(f'No host found for id {id}')


def host_scan():
    """
    Adds a new host and scans it
    Will create a new folder in the current directory.

    cwd/<TARGET>/fast.xml
    """

    ip = questionary.text('IP to scan').ask()
    if not ip:
        return

    delimiters = ',|\n'
    ips = re.split(delimiters, ip.strip())

    scan_type = questionary.select('Scan Mode', choices=['fast', 'full'], use_search_filter=True,
                                   use_jk_keys=False).ask()

    if not scan_type:
        return

    # check if multiple
    if len(ips) > 1:
        log.debug('Identified multiple IPs')

    for ip in ips:
        task = hh.worker.NmapTask(scan_type, ip)
        nmap_queue.put(task)


def host_ffuf():
    """
    1) Select a host
    2) It will generate a list of http/s services
    3) start ffuf for each one of those
    """
    blacklisted_ports = [5985]
    # host.services[0].service == 'http'
    # get all services with http
    hosts = db.session.query(Host).all()
    hh.utils.print_hosts_table(hosts)
    host = hh.utils.cli_select_host('Host to scan', hosts)
    if not host:
        return

    services = []
    for service in host.nmap.services:
        if service.service == 'http':

            # check if in blackist
            if service.port in blacklisted_ports:
                continue

            services.append(service)

    if len(services) == 0:
        log.debug('No services identified!')
        return

    # build output directory
    current_folder = os.getcwd()
    target_folder = os.path.join(current_folder, host.address)
    output = os.path.join(target_folder, 'ffuf')
    os.makedirs(target_folder, exist_ok=True)

    log.debug(f'Idenfitied http services: {services}')

    ENUM_TYPES = 'ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -u {}/FUZZ -e .php,.html,.aspx,.asp -o {}-fingerprint.txt'
    BASIC_ENUM = 'ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u "{}/FUZZ" -o {}-basicenum.txt'

    for service in services:
        target = f'http://{host.address}:{service.port}'
        cmd = ';'.join([ENUM_TYPES.format(target, output), BASIC_ENUM.format(target, output)])

        # create new pane and execute
        pane = hh.tmux.get_hh_pane(tmux_window_name='hh-ffuf', select_window=True)
        hh.tmux.pane_send_keys(pane, cmd)


def host_mark():
    """
    Mark host as comrpmised, user or admin
    """
    hosts = db.session.query(Host).all()
    hh.utils.print_hosts_table(hosts)
    host = hh.utils.cli_select_host('Host to mark', hosts)

    if not host:
        return

    level = questionary.select(
        'Compromise level',
        choices=['user', 'root'],
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()

    if not level:
        return

    if level == 'user':
        host.user_compromised = True
    elif level == 'root':
        host.admin_compromised = True
    db.session.commit()
    log.success('Host marked as compromised!')


def host_web():
    """
    Prints all web targets
    """
    hosts = db.session.query(Host).all()

    blacklisted_ports = [5985]
    urls = []
    for host in hosts:
        services = []
        for service in host.nmap.services:
            if service.service == 'http':
                # check if in blackist
                if service.port in blacklisted_ports:
                    continue

                services.append(service)

        if services:
            # print(f'[+] {host.address} {host.name} {host.fqdn}')

            for service in services:
                if service.port == 443:
                    urls.append(f'https://{host.address}')
                    print(f'https://{host.address}')
                    if host.fqdn:
                        urls.append(f'https://{host.fqdn}')
                        print(f'https://{host.fqdn}')
                else:
                    urls.append(f'http://{host.address}:{service.port}')
                    print(f'http://{host.address}:{service.port}')
                    if host.fqdn:
                        urls.append(f'http://{host.fqdn}:{service.port}')
                        print(f'http://{host.fqdn}:{service.port}')

    # we now have all possible urls
    with open('http-targets.txt', 'w') as f:
        f.write('\n'.join(urls))

    # running eyewitness
    pane = hh.tmux.get_hh_pane(select_window=True)
    cmd = 'eyewitness -f http-targets.txt'
    hh.tmux.pane_send_keys(pane, cmd)


def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options, safe_mode=False)
    rc = nmproc.run()
    if rc != 0:
        log.critical("nmap scan failed: {0}".format(nmproc.stderr))


def print_scan(nmap_report):
    """
    Print scan results from a nmap report
    """
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(nmap_report.version, nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(tmp_host, host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(str(serv.port), serv.protocol, serv.state, serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)
