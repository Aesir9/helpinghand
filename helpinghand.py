#!/bin/python3

import argparse
import hashlib
import os
import sys
import threading
from datetime import datetime
import base64
from colorama import Fore, init
from hh.utils import get_ip
from config import config_file
try:
    import readline  # noqa
except:
    pass

import requests

from app import create_app, nmap_queue, nmap_store
from config import cfg
from hh.worker import NmapScanner


def http_enum(url):
    """
    This method will try every http method and displays
    the return headers of the request
    """
    session = requests.session()
    methods = ['get', 'head', 'post', 'put', 'delete', 'connect', 'options', 'trace', 'patch', 'track']
    responses = {}
    count_per_header = {}

    for method in methods:
        req = session.request(method, url, verify=False)
        print(Fore.CYAN + f'[*] {method}: {req.status_code}')
        for k, v in req.headers.items():
            print(f'{k}: {v}')
        print('')
        responses[method] = req.headers
        for k, v in req.headers.items():
            if k in count_per_header:
                count_per_header[k] += 1
            else:
                count_per_header[k] = 1

    for header_name, count in count_per_header.items():
        if 0 < count < 3:
            # lookup where this header is
            for verb, headers in responses.items():
                if header_name in headers:
                    print(Fore.RED + f'Irregular header in {verb}: {header_name}: {headers[header_name]}')


def create_config():
    with open(config_file, 'w') as f:
        f.write('[hh]\nOVERRIDE_IP = None')
    print(Fore.GREEN + '[+] Config file written.')


if __name__ == "__main__":
    init(autoreset=True)

    parser = argparse.ArgumentParser(description='Helping Hand', conflict_handler='resolve')
    parser.add_argument('-p', '--port', default=7999)
    parser.add_argument('-f', '--serve-file', default=None)
    parser.add_argument('-a', '--arch', default='win')  # win or lin
    parser.add_argument('--ip', action='store_true', default=None)
    parser.add_argument('--http', help='Test all HTTP verbs for webpage')

    args = parser.parse_args()

    # does this work?
    cfg.PORT = args.port

    if args.ip:
        ip = get_ip(ignore_cfg=True)
        print(ip)
        # to_clipboard(ip)
        sys.exit(0)

    if args.http:
        http_enum(args.http)
        sys.exit(0)

    def start_flask(app):
        app.run('0.0.0.0', args.port)

    app = create_app(cfg)
    app_t = threading.Thread(target=start_flask, daemon=True, args=[app])
    app_t.start()

    nmap_worker = NmapScanner(nmap_queue, nmap_store, app)
    nmap_worker.start()

    try:
        import hh.cli
        hh.cli.menu()
    except KeyboardInterrupt:
        print('\n')
        sys.exit(0)
