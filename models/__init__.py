from sqlalchemy import create_engine, Column, Integer, String, Boolean
from libnmap.parser import NmapParser, NmapHost

from app import db


# Define a User model
class Host(db.Model):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True, index=True)
    address = Column(String, nullable=False)
    name = Column(String, nullable=True)
    fqdn = Column(String, nullable=True)
    nmap_xml = Column(String, unique=True, nullable=True)
    user_compromised = Column(Boolean, default=False, nullable=True)
    admin_compromised = Column(Boolean, default=False, nullable=True)

    # list of users from "net user"
    local_users = Column(String, nullable=True)

    # list of users from "dir C:\Users"
    user_profiles = Column(String, nullable=True)

    # List of network interfaces, just the IP
    nics = Column(String, nullable=True)

    @property
    def nmap(self) -> NmapHost:
        """
        This will return the parsed nmap xml
        As the xml can include multiple hosts we filter it by address
        """
        report = NmapParser.parse_fromstring(self.nmap_xml)

        for host in report.hosts:
            if host.address == self.address:
                return host

    @property
    def service_targets(self):
        """
        Returns a list of possible service which can be attacked
        """
        # ssh, smb, mssql, rdp, winrm
        services = [22, 445, 1433, 3389, 5985]
        has_services = []
        if not self.nmap:
            return has_services

        # does only show filtered services
        # for host_service in self.nmap.services:
        #     if host_service.protocol == 'tcp' and host_service.port in services:
        #         has_services.append(host_service.port)
        has_services = [service.port for service in self.nmap.services]
        return has_services

    @classmethod
    def from_nmap(cls, host, nmap_xml):
        return cls(address=host.address, nmap_xml=nmap_xml)


class Credentials(db.Model):
    __tablename__ = 'credentials'

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=True)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    ntlm = Column(String, nullable=True)
    sha1 = Column(String, nullable=True)
    source = Column(String, nullable=True)
