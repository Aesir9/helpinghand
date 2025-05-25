import re
import os
import sys
from app import db
from models import Credentials
import log


def process_logon_passwords(data: str):
    """
    This processes  "sekurlsa::logonPasswords full"
    """
    lines = data.splitlines()

    current = {'Source': 'sekurlsa::logonPasswords'}

    for line in lines:
        val = re.match(r'^\s*\*\s+Username\s+:\s+(.+)\s*$', line.strip())
        if val != None:
            insert_into_db(current)
            current = {'Source': 'sekurlsa::logonPasswords'}
            current['Username'] = val.group(1).strip()
            continue

        val = re.match(r'^\s*\*\s+(Domain|NTLM|SHA1|Password)\s+:\s+(.+)\s*$', line.strip())
        if val != None:
            current[val.group(1).strip()] = val.group(2)


def process_lsadump(data: str):
    """
    this processes lsadump::sam
    """
    domain = 'n/a'
    re_domain = re.search(r'lsadump::sam\nDomain\s+:\s+(.+)\s*$', data, re.MULTILINE)
    if re_domain:
        domain = re_domain.group(1).strip()

    blocks = data.split('\n\n')
    for block in blocks:
        lines = block.splitlines()
        current = {'Source': 'lsadump::sam'}
        for line in lines:
            re_user = re.match(r'^User\s+:\s+(.+)$', line.strip())
            if re_user:
                current['Username'] = re_user.group(1).strip()

            re_ntlm = re.match(r'^Hash NTLM:\s+(.+)\s*$', line.strip())
            if re_ntlm:
                current['ntlm'] = re_ntlm.group(1)

        insert_into_db_sam(domain, current)


def process_secrets(data: str):
    """
    This processes lsadump::secrets
    """
    domain = 'n/a'
    re_domain = re.search(r'lsadump::secrets\nDomain\s+:\s+(.+)\s*$', data, re.MULTILINE)
    if re_domain:
        domain = re_domain.group(1).strip()

    blocks = data.split('\n\n')

    for block in blocks:
        lines = block.splitlines()

        current = {'Source': 'lsadump::secrets'}
        for line in lines:
            re_user = re.match(r'^Secret\s+:\s+(.+)\s*$', line.strip())
            if re_user:
                # some more filtering on the username
                username = re_user.group(1).strip()
                if 'with username' in username:
                    # for cases like this
                    # > Secret  : _SC_MSSQL$SQLEXPRESS / service 'MSSQL$SQLEXPRESS' with username : sqlsvc11@final.com
                    username = username.split(' : ')[-1]

                current['Username'] = username

            re_pass = re.match(r'^(cur|old)\/text:\s+(.+)\s*$', line.strip())
            if re_pass:
                current[re_pass.group(1).strip()] = re_pass.group(2)

        insert_into_db_secrets(domain, current)


def insert_into_db_sam(domain, current):
    """
    Opinionated db input
    
    a) only add if username + ntlm
    b) if cur + old: create two entries
    """

    username = current.get('Username', None)
    ntlm = current.get('ntlm', None)

    if not ntlm:
        return

    # no need for this account
    # WDAGUtilityAccount is part of Application Guard, beginning
    # with Windows 10, version 1709 (Fall Creators Update).
    # It remains disabled by default, unless Application Guard
    # is enabled on your device. WDAGUtilityAccount is used to
    # sign in to the Application Guard container as a standard
    # user with a random password.
    if username == 'WDAGUtilityAccount':
        return

    creds = Credentials.query.filter_by(domain=domain, username=username, ntlm=ntlm).first()

    if not creds:
        db.session.add(Credentials(domain=domain, username=username, ntlm=ntlm, source=current.get('Source', None)))
        db.session.commit()


def insert_into_db_secrets(domain, current):
    """
    Opinionated db input
    
    a) only add if username + password
    b) if cur + old: create two entries
    """

    username = current.get('Username', None)
    password_cur = current.get('cur', None)
    password_old = current.get('old', None)

    if not (password_cur or password_old):
        return

    if password_cur:
        creds = Credentials.query.filter_by(
            domain=domain,
            username=username,
            password=password_cur,
        ).first()

        if type(password_cur) is str and len(password_cur) > 100:
            log.debug(f'Got a password that is longer than 100 characters, ignoring...')
            return

        if not creds:
            db.session.add(
                Credentials(domain=domain, username=username, password=password_cur, source=current['Source']))
            db.session.commit()

    if password_old:
        creds = Credentials.query.filter_by(domain=domain, username=username, password=password_old).first()

        if type(password_old) is str and len(password_old) > 100:
            log.debug(f'Got a password that is longer than 100 characters, ignoring...')
            return

        if not creds:
            db.session.add(
                Credentials(domain=domain, username=username, password=password_old, source=current['Source']))
            db.session.commit()


def insert_into_db(current):
    fields = ['Domain', 'Username', 'NTLM', 'SHA1', 'Password', 'Source']
    for f in fields:
        if f in current:
            if current[f] == '(null)':
                current[f] = None
        else:
            current[f] = None

    # sanity  check if Password or NTLM is none discard entry
    if current['NTLM'] is None and current['Password'] is None:
        return

    # sanity check 2 - check if data could be hex in the best possible way
    if current['Password'] and current['Password'].count(' ') > 40:
        return

    creds = Credentials.query.filter_by(domain=current['Domain'],
                                        username=current['Username'],
                                        password=current['Password'],
                                        ntlm=current['NTLM'],
                                        sha1=current['SHA1']).first()
    if not creds:
        pw = current.get('Password', None)
        #very good veryn ice
        if type(pw) is str:
            if len(pw) > 100:
                log.debug(f'Got a password that is longer than 100 characters, ignoring...')
                return

        db.session.add(
            Credentials(domain=current['Domain'],
                        username=current['Username'],
                        password=current['Password'],
                        ntlm=current['NTLM'],
                        sha1=current['SHA1'],
                        source=current['Source']))
        db.session.commit()
