#!/usr/bin/env python3
#
#    Copyright (C) 2019 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. See <http://www.gnu.org/licenses/gpl.html>

# Inspired by Nikos Fotoulis public domain code and flyte/upnpclient

"""upnp - Find and use devices via UPnP"""

__all__ = [
    'discover',
    'Device',
    'UpnpError',
    'UpnpValueError',
    'SEARCH_TARGET',
]


import enum
import logging
import os.path
import re
import socket
import sys
import urllib.parse

import lxml.etree as ET


SSDP_MAX_MX:        int     = 5  # 2.0 Spec caps value to 5
SSDP_BUFFSIZE:      int     = 8192

log = logging.getLogger(__name__)


class SEARCH_TARGET(str, enum.Enum):
    """Commonly-used device and service types for UPnP discovery"""
    ALL            = 'ssdp:all'
    ROOT           = 'upnp:rootdevice'
    GATEWAY        = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'
    BASIC          = 'urn:schemas-upnp-org:device:Basic:1'
    MEDIA_SERVER   = 'urn:schemas-upnp-org:device:MediaServer:1'
    WAN_CONNECTION = 'urn:schemas-upnp-org:service:WANIPConnection:1'


# Exceptions
class UpnpError(Exception): pass
class UpnpValueError(UpnpError, ValueError): pass


class XMLElement:
    """Wrapper for a common XML API using either LXML, ET or Minidom"""
    @classmethod
    def fromstring(cls, data:str):
        return cls(ET.fromstring(data))

    @classmethod
    def fromurl(cls, url:str):
        return cls(ET.parse(url))

    def __init__(self, element):
        if hasattr(element, 'getroot'):  # ElementTree instead of Element
            element = element.getroot()
        self.e = element

    def findtext(self, tagpath:str) -> str:
        return self.e.findtext(tagpath, namespaces=self.e.nsmap)

    def find(self, tagpath):
        e = self.e.find(tagpath, namespaces=self.e.nsmap)
        if e:
            return self.__class__(e)

    def findall(self, tagpath):
        for e in self.e.findall(tagpath, namespaces=self.e.nsmap):
            yield self.__class__(e)

    @property
    def text(self):
        return self.e.text

    def __repr__(self):
        return repr(self.e)

    def __str__(self):
        return str(self.e)


class SSDP:
    """Device/Service from SSDP M-Search response"""
    def __init__(self, data:str, addr:str=""):
        self.headers = util.parse_headers(data)

        loc = self.headers.get('LOCATION')
        locaddr = util.hostname(loc)
        if addr and addr != locaddr:
            log.warning("Address and Location mismatch: %s, %s", addr, loc)
        self.addr = addr or locaddr

    @property
    def info(self):
        keys = ['SERVER', 'LOCATION', 'USN']
        if not self.is_root:
            keys.append('ST')
        return {_: self.headers.get(_) for _ in keys}

    @property
    def is_root(self):
        return self.headers.get('ST') == SEARCH_TARGET.ROOT

    def __repr__(self):
        desc = ', '.join(('='.join((k.lower(), repr(v))) for k, v in self.info.items()))
        return f'<{self.__class__.__name__}({desc})>'


class Device:
    """UPnP Device"""
    @classmethod
    def from_ssdp(cls, device:SSDP):
        return cls(ssdp=device)

    @classmethod
    def from_ssdp_data(cls, data: str):
        return cls(data=data)

    def __init__(self, url:str="", *, ssdp:SSDP=None, data:str=""):
        self.ssdp     = ssdp or SSDP(data)
        self.location = url or self.ssdp.headers.get('LOCATION')
        self.xmlroot  = XMLElement.fromurl(self.location)
        self.url_base = self.xmlroot.findtext('URLBase') or self.location
        util.attr_tags(self, self.xmlroot, 'device', (
            'deviceType',        # Required
            'friendlyName',      # Required
            'manufacturer',      # Required
            'manufacturerURL',   # Allowed
            'modelDescription',  # Recommended
            'modelName',         # Required
            'modelNumber',       # Recommended
            'modelURL',          # Allowed
            'serialNumber',      # Recommended
            'UDN',               # Required
            'UPC',               # Allowed
        ))

        if url and self.ssdp and url != self.ssdp.headers.get('LOCATION'):
            log.warning("URL and Location mismatch: %s, %s",
                        url, self.ssdp.headers.get('LOCATION'))

        self.services = {}
        for node in self.xmlroot.findall('device//serviceList/service'):
            service = Service(self, node)
            log.debug(service)
            self.services[service.name] = service

    @property
    def name(self):
        return f'{self.friendly_name} @ {self.address}'

    @property
    def fullname(self):
        if self.model_description:
            description = self.model_description
            if self.model_name not in self.model_description:
                description += " " + self.model_name
        else:
            description = self.model_name

        return f"{self.name} ({description}) [{self.manufacturer}]"

    @property
    def address(self):
        return (self.ssdp and self.ssdp.addr) or util.hostname(self.location)

    def __str__(self):
        return self.fullname

    def __repr__(self):
        return f'<{self.__class__.__name__}({self.address!r}, {self.friendly_name!r})>'


class Service:
    def __init__(self, device:Device=None, service:XMLElement=None):
        self.device = device
        util.attr_tags(self, service, '', (
            'serviceType',  # Required
            'serviceId',    # Required
            'controlURL',   # Required
            'eventSubURL',  # Required
            'SCPDURL',      # Required
        ))
        self.xmlroot = XMLElement.fromurl(util.urljoin(self.device.url_base, self.scpdurl))
        #self.actions = tuple(_.text for _ in self.xmlroot.findall('actionList/action/name'))
        self.actions = []
        for action in self.xmlroot.findall('actionList/action'):
            name = action.findtext('name')
            inargs = []
            outargs = []
            for arg in action.findall('argumentList/argument'):
                argname = arg.findtext('name')
                if arg.findtext('direction') == 'in':
                    inargs.append(argname)
                else:
                    outargs.append(argname)
            self.actions.append(f"{name}({', '.join(inargs)}) -> [{', '.join(outargs)}]")

    @property
    def name(self):
        return self.service_id[self.service_id.rindex(":")+1:]

    def __repr__(self):
        return f'<{self.__class__.__name__}({self.name}: {self.actions})>'



class util:
    """A bunch of utility functions and helpers, cos' I'm too lazy for a new module"""
    _re_snake_case = re.compile(r'((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')  # (?!^)([A-Z]+)

    @classmethod
    def snake_case(cls, camelCase: str) -> str:
        return re.sub(cls._re_snake_case, r'_\1', camelCase).lower()

    @classmethod
    def attr_tags(cls, obj, node:XMLElement, tagpath:str="", tags:tuple=()):
        if tagpath: tagpath += '/'
        for tag in tags:
            setattr(obj, cls.snake_case(tag), node.findtext(tagpath+tag) or "")


    @staticmethod
    def parse_headers(data:str) -> dict:
        headers = {}
        for line in data.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().upper()] = v.strip()
        return headers

    @staticmethod
    def hostname(url:str) -> str:
        return urllib.parse.urlparse(url).hostname

    @staticmethod
    def urljoin(base:str, url:str) -> str:
        return urllib.parse.urljoin(base, url)

    @staticmethod
    def clamp(value:int, lbound:int=None, ubound:int=None) -> int:
        if lbound is not None: value = max(value, lbound)
        if ubound is not None: value = min(value, ubound)
        return value


def discover(search_target:str=None, *, timeout:int=SSDP_MAX_MX) -> list:
    addr = ("239.255.255.250", 1900)
    timeout = util.clamp(timeout, 1, SSDP_MAX_MX)
    if not search_target:
        search_target = SEARCH_TARGET.ALL

    data = re.sub('[\t ]*\r?\n[\t ]*', '\r\n', f"""
            M-SEARCH * HTTP/1.1
            HOST: {':'.join(str(_) for _ in addr)}
            MAN: "ssdp:discover"
            MX: {timeout}
            ST: {search_target}
            CPFN.UPNP.ORG: MestreLion UPnP Library

    """.lstrip())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    log.debug("Broadcasting discovery search to %s:\n%s", addr, data)
    sock.sendto(bytes(data, 'ascii'), addr)

    devices = []
    while True:
        try:
            data, (addr, _) = sock.recvfrom(SSDP_BUFFSIZE)
            data = data.decode()
        except socket.timeout:
            break

        log.debug("Incoming search response from %s:\n%s", addr, data)
        ssdp = SSDP(data, addr)

        # Some non-root devices reply to discovery even when setting appropriate ST in M-SEARCH
        if search_target != SEARCH_TARGET.ALL and search_target != ssdp.headers.get('ST'):
            log.warning("Ignoring non-target device: %s", ssdp)
            continue

        try:
            log.info("Found device: %s", ssdp)
            devices.append(Device.from_ssdp(ssdp))
        except UpnpError as e:
            log.error("Error adding device %s: %s", ssdp, e)

    return devices


def main(argv):
    USAGE = """
        Find UPnP devices
        Usage: upnp [-v|-q]
    """
    loglevel = logging.INFO
    if len(argv) > 1:
        if   argv[1] in ('-v', '--verbose'): loglevel = logging.DEBUG
        elif argv[1] in ('-q', '--quiet'):   loglevel = logging.WARN
        else:
            # Assume "-h|--help"
            print('\n'.join(_.strip() for _ in USAGE.strip().splitlines()))
            return
    logging.basicConfig(level=loglevel, format='%(levelname)s: %(message)s')

    devices = discover(timeout=2)

    for device in devices:
        print(f'{device!r}: {device}')

    for dtype in sorted(set(device.device_type for device in devices)):
        print(dtype)

    actions = set()
    for device in devices:
        for service in device.services.values():
            for action in service.actions:
                actions.add(action)
    for action in sorted(actions):
        print(action)


if __name__ == "__main__":
    log = logging.getLogger(os.path.basename(__file__))
    try:
        sys.exit(main(sys.argv))
    except UpnpError as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        raise
