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
from nmap3.utils import get_nmap_path # from utils import get_nmap_path
import simplejson as json
import argparse
from nmap3.nmapparser import NmapCommandParser #from nmapparser import NmapCommandParser
from xml.etree import ElementTree as ET

__author__ = 'Wangolo Joel (info@nmapper.com)'
__version__ = '0.1.1'
__last_modification__ = '2020/04/24'

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
        self.parser  = NmapCommandParser(None)

    def default_command(self):
        """
        Returns the default nmap command
        that will be chained with all others
        eg nmap -oX -
        """
        return self.default_args.format(nmap=self.nmaptool, outarg="-oX")

    def scan_top_ports(self, host, default=10, args=None):
        """
        Perform nmap's top ports scan

        :param: host can be IP or domain
        :param: default is the default top port

        This top port requires root previledges
        """
        parser  = NmapCommandParser(None)

        if(default > self.maxport):
            raise ValueError("Port can not be greater than default 65389")
        self.host = host

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        top_port_args = " {host} --top-ports {default}".format(host=host, default=default)
        scan_command = self.default_command() + top_port_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        # Run the command and get the output
        output = self.run_command(scan_shlex)
        if not output:
            # Probaby and error was raise
            raise ValueError("Unable to perform requested command")

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        self.top_ports = parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_dns_brute_script(self, host, dns_brute="--script dns-brute.nse"):
        """
        Perform nmap scan using the dns-brute script

        :param: host can be IP or domain
        :param: default is the default top port

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        self.host = host
        parser  = NmapCommandParser(None)

        dns_brute_args = "{host}  {default}".format(host=host, default=dns_brute)

        dns_brute_command = self.default_command() + dns_brute_args
        dns_brute_shlex = shlex.split(dns_brute_command) # prepare it for popen

        # Run the command and get the output
        output = self.run_command(dns_brute_shlex)

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        subdomains = parser.filter_subdomains(xml_root)
        return subdomains

    def nmap_version_detection(self, host, arg="-sV", args=None):
        """
        Perform nmap scan using the dns-brute script

        :param: host can be IP or domain

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        self.host = host

        command_args = "{host}  {default}".format(host=host, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)

        services = self.parser.version_parser(xml_root)
        return services

    def nmap_stealth_scan(self, host, arg="-sA", args=None):
        """
        nmap -oX - nmmapper.com -sA
        """
        # TODO
        self.host = host

        command_args = "{host}  {default}".format(host=host, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        # Run the command and get the output
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)

    def nmap_detect_firewall(self, host, arg="-sA", args=None): # requires root
        """
        nmap -oX - nmmapper.com -sA
        @ TODO
        """
        self.host = host

        command_args = "{host}  {default}".format(host=host, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)
        # TODO

    def nmap_os_detection(self, host, arg="-O", args=None): # requires root
        """
        nmap -oX - nmmapper.com -O
        NOTE: Requires root
        """
        self.host = host

        command_args = "{host}  {default}".format(host=host, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)

        os_identified = self.parser.os_identifier_parser(xml_root)
        return os_identified

    def nmap_subnet_scan(self, subnet, arg="-p-", args=None): # requires root
        """
        nmap -oX - nmmapper.com -p-
        NOTE: Requires root
        """
        self.host = subnet

        command_args = "{host}  {default}".format(host=subnet, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)

        scan_shlex = shlex.split(scan_command)
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)

        host_discovered = self.parser.parse_nmap_subnetscan(xml_root)
        return host_discovered

    def nmap_list_scan(self, subnet, arg="-sL", args=None): # requires root
        """
        The list scan is a degenerate form of host discovery that simply lists each host of the network(s)
        specified, without sending any packets to the target hosts.

        NOTE: /usr/bin/nmap  -oX  -  192.168.178.1/24  -sL
        """
        self.host = subnet

        command_args = "{host}  {default}".format(host=subnet, default=arg)
        scan_command = self.default_command() + command_args
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)

        host_discovered = self.parser.parse_nmap_listscan(xml_root)
        return host_discovered

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

class NmapScanTechniques(Nmap):
    """
    Extends Nmap to include nmap commands
    with different scan techniques

    This scan techniques include

    1) TCP SYN Scan (-sS)
    2) TCP connect() scan (-sT)
    3) FIN Scan (-sF)
    4) Ping Scan (-sP)
    5) Idle Scan (-sI)
    """

    def __init__(self, path=None):
        super(NmapScanTechniques, self).__init__(path=path)

        self.sync_scan = "-sS"
        self.tcp_connt = "-sT"
        self.fin_scan = "-sF"
        self.ping_scan = "-sP"
        self.idle_scan = "-sL"
        self.udp_scan = "-sU"

    def nmap_fin_scan(self, host, args=None):
        """
        Perform scan using nmap's fin scan

        @cmd nmap -sF 192.168.178.1

        """
        fin_scan = " {host} {default}".format(host=host, default=self.fin_scan)
        fin_scan_command = self.default_command() + fin_scan
        if(args):
            fin_scan_command += " {0}".format(args)
        fin_scan_shlex = shlex.split(fin_scan_command)
        parser  = NmapCommandParser(None)

        # Use the ping scan parser
        output = self.run_command(fin_scan_shlex)
        xml_root = self.get_xml_et(output)
        fin_results = parser.parse_nmap_idlescan(xml_root)
        return fin_results

    def nmap_syn_scan(self, host, args=None):
        """
        Perform syn scan on this given
        host

        @cmd nmap -sS 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        sync_scan = " {host} {default}".format(host=host, default=self.sync_scan)
        sync_scan_command = self.default_command() + sync_scan
        if(args):
            sync_scan_command += " {0}".format(args)
        sync_scan_shlex = shlex.split(sync_scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(sync_scan_shlex)
        xml_root = self.get_xml_et(output)
        self.top_ports = parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_tcp_scan(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -sT 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        tcp_scan = " {host} {default}".format(host=host, default=self.tcp_connt)
        tcp_scan_command = self.default_command() + tcp_scan
        if(args):
            tcp_scan_command += " {0}".format(args)
        tcp_scan_shlex = shlex.split(tcp_scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(tcp_scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.filter_top_ports(xml_root)
        return tcp_results
        
    def nmap_udp_scan(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -sU 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        tcp_scan = " {host} {default}".format(host=host, default=self.udp_scan)
        tcp_scan_command = self.default_command() + tcp_scan
        if(args):
            tcp_scan_command += " {0}".format(args)
        tcp_scan_shlex = shlex.split(tcp_scan_command) # prepare it
        
        # Use the top_port_parser
        output = self.run_command(tcp_scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.filter_top_ports(xml_root)
        return tcp_results

    def nmap_ping_scan(self, host, args=None):
        """
        Scan host using nmaps' ping scan

        @cmd nmap -sP 192.168.178.1
        """
        ping_scan = " {host} {default}".format(host=host, default=self.ping_scan)
        ping_scan_command = self.default_command() + ping_scan
        if(args):
            ping_scan_command += " {0}".format(args)
        ping_scan_shlex = shlex.split(ping_scan_command) # prepare it
        parser  = NmapCommandParser(None)

        output = self.run_command(ping_scan_shlex)
        xml_root = self.get_xml_et(output)
        ping_results = parser.parse_nmap_pingscan(xml_root)
        return ping_results

    def nmap_idle_scan(self, host, args=None):
        """
        Using nmap idle_scan

        @cmd nmap -sL 192.168.178.1
        """
        idle_scan = " {host} {default}".format(host=host, default=self.idle_scan)
        idle_scan_command = self.default_command() + idle_scan
        if(args):
            idle_scan_command += " {0}".format(args)
        idle_scan_shlex = shlex.split(idle_scan_command) # prepare it
        parser  = NmapCommandParser(None)

        # Use the ping scan parser
        output = self.run_command(idle_scan_shlex)
        xml_root = self.get_xml_et(output)
        idle_results = parser.parse_nmap_pingscan(xml_root)
        return idle_results

class NmapHostDiscovery(Nmap):
    """
    This object will perform host discovery

    1) Only port scan    (-Pn)
    2) Only host discover    (-sn)
    3) Arp discovery on a local network  (-PR)
    4) Disable DNS resolution    (-n)
    """
    def __init__(self, path=None):
        super(NmapHostDiscovery, self).__init__(path=path)

        self.port_scan_only = "-Pn"
        self.no_port_scan = "-sn"
        self.arp_discovery = "-PR"
        self.disable_dns = "-n"

    def nmap_portscan_only(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -Pn 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        scancommand = " {host} {default}".format(host=host, default=self.port_scan_only)
        scan_command = self.default_command() + scancommand
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.filter_top_ports(xml_root)
        return tcp_results

    def nmap_no_portscan(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -sn 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        scancommand = " {host} {default}".format(host=host, default=self.no_port_scan)
        scan_command = self.default_command() + scancommand
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.parse_noportscan(xml_root)
        return tcp_results

    def nmap_arp_discovery(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -n 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        scancommand = " {host} {default}".format(host=host, default=self.disable_dns)
        scan_command = self.default_command() + scancommand
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.filter_top_ports(xml_root)
        return tcp_results

    def nmap_disable_dns(self, host, args=None):
        """
        Scan host using the nmap tcp connect

        @cmd nmap -PR 192.168.178.1
        """
        parser  = NmapCommandParser(None)

        if(args):
            assert(isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        scancommand = " {host} {default}".format(host=host, default=self.arp_discovery)
        scan_command = self.default_command() + scancommand
        if(args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command) # prepare it

        # Use the top_port_parser
        output = self.run_command(scan_shlex)
        xml_root = self.get_xml_et(output)
        tcp_results = parser.filter_top_ports(xml_root)
        return tcp_results

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="Python3 nmap")
    parser.add_argument('-d', '--d', help='Help', required=True)
    args = parser.parse_args()

    nmap = NmapScanTechniques()
    result = nmap.nmap_udp_scan(args.d)
    print(json.dumps(result, indent=4, sort_keys=True))
