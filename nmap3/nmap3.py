#  nmap3.py
#
#  Copyright 2019 Wangolo Joel <wangolo@ldap.testlumiotic.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
import csv
import io
import os
import re
import shlex
import subprocess
import sys
from xml.etree import ElementTree as ET
from utils import (get_nmap_path
)
import simplejson as json
import argparse

__author__ = 'Wangolo Joel (info@nmapper.com)'
__version__ = '0.1.1'
__last_modification__ = '2019/11/22'

class Nmap(object):
    """
    This nmap class allows us to use the nmap port scanner tool from within python
    by calling nmap3.Nmap()
    """
    def __init__(self, path=None):
        """
        Module initialization

        :param path: Path where nmap is installed on a user system. On linux system it's typically on /usr/bin/nmap.
        """

        self.nmaptool = path if path else get_nmap_path()
        self.default_args = "{nmap}  {outarg}  -  "
        self.maxport = 65389
        self.host = ""
        self.top_ports = dict()

    def default_command(self):
        """
        Returns the default nmap command
        that will be chained with all others
        eg nmap -oX -
        """
        return self.default_args.format(nmap=self.nmaptool, outarg="-oX")

    def scan_top_ports(self, host, default=10):
        """
        Perform nmap's top ports scan

        :param: host can be IP or domain
        :param: default is the default top port

        This top port requires root previledges
        """

        if(default > self.maxport):
            raise ValueError("Port can not be greater than default 65389")
        self.host = host

        top_port_args = " {host} --top-ports {default}".format(host=host, default=default)
        top_port_command = self.default_command() + top_port_args
        top_port_shlex = shlex.split(top_port_command) # prepare it for popen

        # Run the command and get the output
        output = self.run_command(top_port_shlex)
        if not output:
            # Probaby and error was raise
            raise ValueError("Unable to perform requested command")

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        self.top_ports = self.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_dns_brute_script(self, host, dns_brute="--script dns-brute.nse"):
        """
        Perform nmap scan usign the dns-brute script

        :param: host can be IP or domain
        :param: default is the default top port

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        self.host = host

        dns_brute_args = "{host}  {default}".format(host=host, default=dns_brute)

        dns_brute_command = self.default_command() + dns_brute_args
        dns_brute_shlex = shlex.split(dns_brute_command) # prepare it for popen

        # Run the command and get the output
        output = self.run_command(dns_brute_shlex)

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        subdomains = self.filter_subdomains(xml_root)
        return subdomains

    def nmap_version_detection(self, host, arg="-sV"):
        """
        Perform nmap scan usign the dns-brute script

        :param: host can be IP or domain

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        self.host = host

        command_args = "{host}  {default}".format(host=host, default=arg)
        command = self.default_command() + command_args
        dns_brute_shlex = shlex.split(command) # prepare it for popen

        # Run the command and get the output
        output = self.run_command(dns_brute_shlex)
        xml_root = self.get_xml_et(output)

        services = self.version_parser(xml_root)
        return services

    def run_command(self, cmd):
        """
        Runs the nmap command using popen

        @param: cmd--> the command we want run eg /usr/bin/nmap -oX -  nmmapper.com --top-ports 10
        """
        sub_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        try:
            output, errs = sub_proc.communicate()
        except Exception as e:
            sub_proc.kill()
            raise(e)
        else:
            # Response is bytes so decode the output and return
            return output.decode('utf8').strip()

    def get_xml_et(self, command_output):
        """
        @ return xml ET
        """
        return ET.fromstring(command_output)

    def filter_top_ports(self, xmlroot):
        """
        Given the xmlroot return the all the ports that are open from
        that tree
        """
        try:
            port_results = []

            scanned_host = xmlroot.find("host")
            if(scanned_host):
                ports = scanned_host.find("ports").findall("port")

                # slowly parse what is required
                for port in ports:
                    open_ports = {}

                    open_ports["protocol"]=port.attrib.get("protocol")
                    open_ports["port"]=port.attrib.get("portid")

                    if port.find('state') != None:
                        open_ports["state"]=port.find("state").attrib.get("state")
                        open_ports["reason"]=port.find('state').attrib.get("reason")
                        open_ports["reason_ttl"]=port.find("state").attrib.get("reason_ttl")

                    if  port.find("service") != None:
                        open_ports["service"]=port.find("service").attrib

                    port_results.append(open_ports)

        except Exception as e:
            raise(e)
        else:
            return port_results

    def version_parser(self, xmlroot):
        """
        Parse version detected
        """
        try:
            service_version = []

            host = xmlroot.find("host")
            if(host):
                ports  = host.find("ports")
                port_service = None

                if(ports):
                    port_service = ports.findall("port")

                if(port_service):
                    for port in port_service:
                        service = {}

                        service["protocol"]=port.attrib.get("protocol")
                        service["port"]=port.attrib.get("portid")

                        if(port.find("state")):
                            for s in port.find("state").attrib:
                                service[s]=port.find("state").attrib.get(s)

                        if(port.find("service")):
                            service["service"]=port.find("service").attrib
                            
                            for cp in port.find("service").findall("cpe"):
                                cpe_list = []
                                cpe_list.append({"cpe":cp.text})
                                service["cpe"]=cpe_list
                                
                        service_version.append(service)
                        
        except Exception as e:
            raise(e)
        else:
            return service_version

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="Python3 nmap")
    parser.add_argument('-d', '--d', help='Help', required=True)
    args = parser.parse_args()

    nmap = Nmap()
    result = nmap.nmap_version_detection(args.d)
    print(result)
    #print(json.dumps(result, indent=4, sort_keys=True))
