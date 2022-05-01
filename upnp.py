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
    'Action',
    'Device',
    'Service',
    'SEARCH_TARGET',
    'SOAPCall',
    'UpnpError',
    'UpnpValueError',
    'discover',
]


import argparse
import enum
import logging
import os.path
import re
import socket
import sys
import typing as t
import urllib.parse

import lxml.etree as ET
import requests


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


class DIRECTION(str, enum.Enum):
    IN  = 'in'
    OUT = 'out'


# Exceptions
class UpnpError(Exception): pass
class UpnpValueError(UpnpError, ValueError): pass


class XMLElement:
    """Wrapper for a common XML API using either LXML, ET or Minidom"""
    # Note: XML sucks! It's an incredibly complex format, and lxml is *very* picky
    # - Serialized XML is always bytes, not str, per the spec
    # - When converted to str (unicode), there's no <?xml ..?> declaration
    # - pretty_print=True only works if parsed with remove_blank_text=True
    # - Dealing with namespaces, many approaches:
    #     e.find('{fully.qualified.namespace}tag')
    #     e.find('{*}tag'), using a literal *
    #     e.find('X:tag', namespaces=e.nsmap), X being (usually) a single lowercase letter
    @classmethod
    def fromstring(cls, data:t.Union[str, bytes]):
        return cls(ET.fromstring(data, parser=ET.XMLParser(remove_blank_text=True)))

    @classmethod
    def fromurl(cls, url:str):
        log.debug("Parsing %s", url)
        # lxml.etree.parse() chokes on URLs if server sets Content-Type header as
        # 'text/xml; charset="utf-8"', as seen on Ubuntu's MiniDLNA rootDesc.xml
        # So for now we use requests to download and read content
        # return cls(ET.parse(url))
        return cls.fromstring(requests.get(url).text)

    @classmethod
    def prettify(cls, s):
        return cls.fromstring(s).pretty()

    def __init__(self, element):
        if hasattr(element, 'getroot'):  # ElementTree instead of Element
            element = element.getroot()
        self.e = element

    def findtext(self, tagpath:str) -> str:
        return self.e.findtext(tagpath, namespaces=self.e.nsmap)

    def find(self, tagpath):
        e = self.e.find(tagpath, namespaces=self.e.nsmap)
        if e is not None:
            return self.__class__(e)

    def findall(self, tagpath):
        for e in self.e.findall(tagpath, namespaces=self.e.nsmap):
            yield self.__class__(e)

    def pretty(self) -> str:
        # ET.tostring().decode() is not the same as ET.tostring(..., encoding=str)
        # The latter errors when using xml_declaration=True
        return ET.tostring(self.e, pretty_print=True,
                           xml_declaration=True, encoding='utf-8').decode()

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


# noinspection PyUnresolvedReferences
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
        self.url_base = self.xmlroot.findtext('URLBase') or util.urljoin(self.location, '.')
        util.attr_tags(self, self.xmlroot, 'device', '', tags=(
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
            self.services[service.service_type] = service

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
        r = f'{self.address!r}, {self.friendly_name!r}, {self.location!r}, {self.udn!r}'
        return '<{0.__class__.__name__}({1})>'.format(self, r)


# noinspection PyUnresolvedReferences
class Service:
    def __init__(self, device:Device, service:XMLElement):
        self.device = device
        util.attr_tags(self, service, '', device.url_base, tags=(
            'serviceType',  # Required
            'serviceId',    # Required
            'controlURL',   # Required
            'eventSubURL',  # Required
            'SCPDURL',      # Required
        ))
        self.xmlroot = XMLElement.fromurl(util.urljoin(self.device.url_base, self.scpdurl))
        self.actions = {}
        for node in self.xmlroot.findall('actionList/action'):
            action = Action(self, node)
            self.actions[action.name] = action

    @property
    def name(self):
        return self.service_id[self.service_id.rindex(":")+1:]

    def __str__(self):
        return self.service_type

    def __repr__(self):
        attrs = {
            'service_type' : 'type',
            'scpdurl'      : 'SCPD',
            'control_url'  : 'CTRL',
            'event_sub_url': 'EVT',
        }
        r = util.formatdict({attrs[k]: v for k, v in vars(self).items() if k in attrs})
        return f'<{self.__class__.__name__}({r})>'


# noinspection PyUnresolvedReferences
class Action:
    def __init__(self, service:Service=None, action:XMLElement=None):
        self.service = service
        self.name = action.findtext('name')

        self.inputs  = []
        self.outputs = []
        for arg in action.findall('argumentList/argument'):
            argname = arg.findtext('name')
            if arg.findtext('direction') == 'in':
                self.inputs.append(argname)
            else:
                self.outputs.append(argname)

    def call(self, **kwargs):
        xml_root = SOAPCall(self.service.control_url, self.service.service_type, self.name, **kwargs)
        return {k: xml_root.findtext(f'.//{k}') for k in self.outputs}


    def __call__(self, **kwargs):
        return self.call(**kwargs)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<{self.name}({', '.join(self.inputs)}) -> [{', '.join(self.outputs)}]>"


class util:
    """A bunch of utility functions and helpers, cos' I'm too lazy for a new module"""
    _re_snake_case = re.compile(r'((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')  # (?!^)([A-Z]+)

    @classmethod
    def snake_case(cls, camelCase: str) -> str:
        return re.sub(cls._re_snake_case, r'_\1', camelCase).lower()

    @classmethod
    def attr_tags(cls, obj, node:XMLElement, tagpath:str="", baseurl:str='', tags:tuple=()) -> None:
        """Magic method to set attributes from XML tag(name)s

        Tag names must be leafs, not paths, with optional <tagpath> prefix
        Automatically convert names from camelCaseURL to camel_case_url
        URLs, judged by URL-ending tag name, are joined with <baseurl>
        """
        if tagpath: tagpath += '/'
        for tag in tags:
            attr  = cls.snake_case(tag)
            value = node.findtext(tagpath+tag) or ""
            if value and baseurl and attr.endswith('url'):
                value = cls.urljoin(baseurl, value)
            setattr(obj, attr, value)

    @staticmethod
    def formatdict(d:dict, itemsep=', ', pairsep='=', valuefunc=repr) -> str:
        return itemsep.join((pairsep.join((k, valuefunc(v))) for k, v in d.items()))

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
    log.info("Discovering UPnP devices and services: %s", search_target)
    log.debug("Broadcasting discovery search to %s:\n%s", addr, data)
    sock.sendto(bytes(data, 'ascii'), addr)

    devices = {}
    while True:
        try:
            data, (addr, _) = sock.recvfrom(SSDP_BUFFSIZE)
            data = data.decode()
        except socket.timeout:
            break

        log.debug("Incoming search response from %s:\n%s", addr, data)
        ssdp = SSDP(data, addr)
        location = ssdp.headers.get('LOCATION')

        if location in devices:
            #TODO: drop this log after code is mature and skip dupes silently
            log.debug("Ignoring duplicated device: %s", ssdp)
            continue

        # Some unrelated devices reply to discovery even when setting appropriate ST in M-SEARCH
        if search_target != SEARCH_TARGET.ALL and search_target != ssdp.headers.get('ST'):
            log.warning("Ignoring non-target device: %s", ssdp)
            continue

        try:
            log.info("Found device: %s", ssdp)
            yield location, Device.from_ssdp(ssdp)
        except UpnpError as e:
            log.error("Error adding device %s: %s", ssdp, e)


def SOAPCall(url, service, action, **kwargs) -> XMLElement:
    # TODO: Sanitize kwargs!
    xml_args = "\n".join(f"<{k}>{v}</{k}>" for k, v in kwargs.items())
    data = f"""
        <?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <s:Body>
            <u:{action} xmlns:u="{service}">{xml_args}</u:{action}>
        </s:Body>
        </s:Envelope>
    """.strip()
    headers = {
        'SOAPAction': f'"{service}#{action}"',
        'Content-Type': 'text/xml; charset="utf-8"',
    }
    log.info("Executing SOAP Action: %s.%s(%s) @ %s",
             service, action, util.formatdict(kwargs), url)
    log.debug(headers)
    log.debug(XMLElement.prettify(data))
    r = requests.post(url, headers=headers, data=data)
    log.debug(r.request.headers)
    log.debug(r.headers)
    xml_root = XMLElement.fromstring(r.content)
    log.debug(xml_root.pretty())

    # This is very strict. if things go wrong, replace with:
    # return xml_root.find(f'.//{{{service}}}*'), or just return xml_root
    return xml_root.find(f'{{*}}Body/{{{service}}}{action}Response')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-q', '--quiet',
                       dest='loglevel',
                       const=logging.WARNING,
                       default=logging.INFO,
                       action="store_const",
                       help="Suppress informative messages.")

    group.add_argument('-v', '--verbose',
                       dest='loglevel',
                       const=logging.DEBUG,
                       action="store_const",
                       help="Verbose mode, output extra info.")

    parser.add_argument('-a', '--action',
                        default='GetExternalIPAddress',
                        help="Action to perform."
                            " [Default: %(default)s]")

    parser.add_argument(nargs='*',
                        dest='args',
                        help="Arguments to Action")

    args = parser.parse_args(argv)
    args.debug = args.loglevel == logging.DEBUG

    return args


def main(argv):
    args = parse_args(argv or [])
    logging.basicConfig(level=args.loglevel,
                        format='%(levelname)-5.5s: %(message)s')
    log.debug(args)

    ST = ""

    actions = []
    print("Devices:")
    for location, device in discover(ST, timeout=5):
        print(f'{device!r}: {device}')
        for service in device.services.values():
            print('\t' + repr(service))
            for action in service.actions.values():
                print('\t\t' + repr(action))
                if action.name == args.action:
                    log.info("Found action matching %s: '%s':", args.action, action)
                    print(action())
            print()



if __name__ == "__main__":
    log = logging.getLogger(os.path.basename(__file__))
    try:
        sys.exit(main(sys.argv))
    except UpnpError as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        raise
