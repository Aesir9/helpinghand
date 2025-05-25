"""
Does NMAP scanning in another thread
"""
import threading
import random
import os

from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess
import log

import hh.host

rnd_store = []


def get_rnd():
    rnd = random.randint(0, 100000)
    if rnd not in rnd_store:
        rnd_store.append(rnd)
        return rnd
    else:
        get_rnd()


class NmapTask:
    def __init__(self, scan_type: str, target):
        """
        :params: `scan_type` either `fast` or `full`
        """

        self.job_id = get_rnd()
        self.scan_type = scan_type

        # calc required things
        current_folder = os.getcwd()
        target_folder = os.path.join(current_folder, target)
        output = os.path.join(target_folder, scan_type)

        if scan_type == 'fast':
            args = f'-v -Pn -oX {output}.xml -oN {output} -sCV '
        elif scan_type == 'full':
            args = f'-v --reason -T4 --version-all --osscan-guess -A -Pn -p- -oX {output}.xml -oN {output} -sCV '
        else:
            log.critical('Wrong scan_type')
            return

        os.makedirs(target_folder, exist_ok=True)
        log.debug(f'nmap args: {args}')

        self.output_folder = target_folder
        self.output_xml = f'{output}.xml'
        self.target = target
        self.nmap_args = args

        self.started = False
        self.failed = False
        self.finished = False


class NmapScanner(threading.Thread):
    def __init__(self, queue, store, app):
        threading.Thread.__init__(self)
        self.queue = queue
        self.store = store
        self.app = app
        self.daemon = True

    def run(self):
        while True:
            task = self.queue.get()
            self.store[task.job_id] = task

            task.started = True

            nmproc = NmapProcess(task.target, task.nmap_args, safe_mode=False)
            rc = nmproc.run()
            if rc != 0:
                log.critical("nmap scan failed: {0}".format(nmproc.stderr))
                task.finished = True
                task.failed = True
                self.queue.task_done()
                continue

            with self.app.app_context():
                report = NmapParser.parse_fromfile(task.output_xml)
                hh.host.print_scan(report)

                automerge = False
                if task.scan_type == 'full':
                    automerge = True
                hh.host.host_add(file=task.output_xml, automerge=automerge)

            task.failed = False
            task.finished = True
            self.queue.task_done()
