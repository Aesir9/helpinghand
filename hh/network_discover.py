import subprocess
import re
import log


class NetworkHost:
    def __init__(self, ip, name=None, domain=None):
        self.ip = ip
        self.name = name.lower()

        if domain == '':
            domain = None
        self.domain = domain

    @property
    def fqdn(self):
        if self.domain:
            return f'{self.name}.{self.domain}'.lower()
        return None


def run_command(command):
    """Run a shell command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def parse_output(output, protocol):
    """Parse the output based on the protocol and return formatted lines."""
    lines = output.splitlines()
    formatted_lines = []

    hosts = []

    for line in lines:
        if protocol.lower() in line.lower():
            if protocol.lower() == "ldap":
                # For LDAP, we want to extract the IP, machine name, and domain not sure why there are no results shown now
                match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[.*?\(name:(.*?)\)\s+\(domain:(.*?)\)',
                                  line)
                if match:
                    ip = match.group(1)
                    machine_name = match.group(2)
                    domain = match.group(4) if match.group(4) else ""
                    hosts.append(NetworkHost(ip, machine_name, domain))
                    formatted_line = f"{ip} {machine_name} {machine_name}.{domain}" if domain else f"{ip} {machine_name} "
                    formatted_lines.append(formatted_line)

            elif protocol.lower() == "ssh":
                # For SSH, we only want the IP address
                match = re.search(r'SSH\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    formatted_lines.append(f"{ip} ")
                    entry = NetworkHost(ip)
                    hosts.append(entry)
            elif protocol.lower() == "wmi":
                # For WMI, we want to extract the IP, machine name, and domain
                match = re.search(r'RPC\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[.*?\(name:(.*?)\)\s+\( domain:(.*?)\)',
                                  line)
                if match:
                    ip = match.group(1)
                    machine_name = match.group(3)
                    domain = match.group(4) if match.group(4) else ""
                    formatted_line = f"{ip} {machine_name} {machine_name}.{domain}" if domain else f"{ip} {machine_name} "
                    formatted_lines.append(formatted_line)
                    hosts.append(NetworkHost(ip, machine_name, domain))
            else:
                # For other protocols, extract IP, machine name, and domain
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\S+)\s+\[.*?\(name:(.*?)\)\s+\(domain:(.*?)\)', line)
                if match:
                    ip = match.group(1)
                    machine_name = match.group(3)
                    domain = match.group(4) if match.group(4) else ""
                    formatted_line = f"{ip} {machine_name} {machine_name}.{domain}" if domain else f"{ip} {machine_name} "
                    formatted_lines.append(formatted_line)
                    hosts.append(NetworkHost(ip, machine_name, domain))

    return hosts


def discover(target):
    protocols = ["smb", "winrm", "rdp"]

    # key is the ip
    data = {}

    for protocol in protocols:
        log.debug(f'Discovering {protocol}...')
        command = f"netexec --no-progress {protocol} {target}"
        output = run_command(command)

        # Parse the output and write to /etc/hosts
        network_hosts = parse_output(output, protocol)

        # Write a comment line for the protocol
        if network_hosts:
            # hosts_file.write(f"# Found via {protocol}\n")
            for network_host in network_hosts:
                data[network_host.ip] = network_host

    return data
