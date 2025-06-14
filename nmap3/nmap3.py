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

import shlex
import subprocess
import sys
import argparse
import asyncio
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError
from nmap3.nmapparser import NmapCommandParser
from nmap3.utils import get_nmap_path, user_is_root
from nmap3.exceptions import NmapXMLParserError, NmapExecutionError
import re

__author__ = 'Wangolo Joel (inquiry@nmapper.com)'
__version__ = '1.9.3'
__last_modification__ = 'Jun/06/2025'

OS_TYPE = sys.platform

class Nmap(object):
    """
    This nmap class allows us to use the nmap port scanner tool from within python
    by calling nmap3.Nmap()
    """

    def __init__(self, path:str=''):
        """
        Module initialization

        :param path: Path where nmap is installed on a user system. On linux system it's typically on /usr/bin/nmap.
        """

        self.nmaptool = get_nmap_path(path) # check path, search or raise error
        self.default_args = "{nmap}  {outarg}  -  "
        self.maxport = 65535
        self.target = ""
        self.top_ports = dict()
        self.parser = NmapCommandParser(None)
        self.raw_output = None
        self.as_root = False

    def require_root(self, required=True):
        """
        Call this method to add "sudo" in front of nmap call
        """
        self.as_root = required

    def default_command(self):
        """
        Returns the default nmap command
        that will be chained with all others
        eg nmap -oX -
        """
        if self.as_root:
            return self.default_command_privileged()
        #return self.default_args.format(nmap=self.nmaptool, outarg="-oX")
        return self.default_args.format(nmap=self.nmaptool, outarg="-v -oX") # adding extra verbosity to feed "task_results" output

    def default_command_privileged(self):
        """
        Commands that require root privileges
        """
        if OS_TYPE == 'win32':
            # Elevate privileges and return nmap command
            # For windows now is not fully supported so just return the default
            return self.default_command()
        else:
            return self.default_args.format(nmap=self.nmaptool, outarg="-oX")

    def nmap_version(self):
        """
        Returns nmap version and build details
        """
        # nmap version output is not available in XML format (eg. -oX -)
        output = self.run_command([self.nmaptool, '--version'])
        version_data = {}
        for line in output.splitlines():
            if line.startswith('Nmap version '):
                version_string = line.split(' ')[2]
                version_data['nmap'] = tuple([int(_) for _ in version_string.split('.')])
            elif line.startswith('Compiled with:'):
                compiled_with = line.split(':')[1].strip()
                version_data['compiled_with'] = tuple(compiled_with.split(' '))
            elif line.startswith('Compiled without:'):
                compiled_without = line.split(':')[1].strip()
                version_data['compiled_without'] = tuple(compiled_without.split(' '))
            elif line.startswith('Available nsock engines:'):
                nsock_engines = line.split(':')[1].strip()
                version_data['nsock_engines'] = tuple(nsock_engines.split(' '))
        return version_data

    # Unique method for repetitive tasks - Use of 'target' variable instead of 'host' or 'subnet' - no need to make difference between 2 strings that are used for the same purpose
    def scan_command(self, target, arg, args=None, timeout=None):
        self.target = target

        command_args = "{target}  {default}".format(target=target, default=arg)
        scancommand = self.default_command() + command_args
        if (args):
            scancommand += " {0}".format(args)

        scan_shlex = shlex.split(scancommand)
        output = self.run_command(scan_shlex, timeout=timeout)
        file_name=re.search(r'(\-oX|-oN-|oG)\s+[a-zA-Z-_0-9]{1,100}\.[a-zA-Z]+',scancommand)
        if file_name:
            file_name=scancommand[file_name.start():file_name.end()].split(" ")[0]
            return self.get_success_xml_et(file_name)
        xml_root = self.get_xml_et(output)
        return xml_root

    def scan_top_ports(self, target, default=10, args=None, timeout=None):
        """
        Perform nmap's top ports scan

        :param: target can be IP or domain
        :param: default is the default top port

        This top port requires root previledges
        """
        if (default > self.maxport):
            raise ValueError("Port can not be greater than default 65535")
        self.target = target

        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))

        top_port_args = " {target} --top-ports {default}".format(target=target, default=default)
        scan_command = self.default_command() + top_port_args
        if (args):
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        # Run the command and get the output
        output = self.run_command(scan_shlex, timeout=timeout)
        if not output:
            # Probaby and error was raise
            raise ValueError("Unable to perform requested command")

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_dns_brute_script(self, target, dns_brute="--script dns-brute.nse", args=None, timeout=None):
        """
        Perform nmap scan using the dns-brute script

        :param: target can be IP or domain
        :param: default is the default top port

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        self.target = target
        dns_brute_args = "{target}  {default}".format(target=target, default=dns_brute)
        
        if args:
            dns_brute_args += " {0}".format(args)
            
        dns_brute_command = self.default_command() + dns_brute_args
        dns_brute_shlex = shlex.split(dns_brute_command)  # prepare it for popen

        # Run the command and get the output
        output = self.run_command(dns_brute_shlex, timeout=timeout)

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        subdomains = self.parser.filter_subdomains(xml_root)
        return subdomains

    def nmap_version_detection(self, target, arg="-sV", args=None, timeout=None):
        """
        Perform nmap scan using the dns-brute script

        :param: target can be IP or domain

        nmap -oX - nmmapper.com --script dns-brute.nse
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args, timeout=timeout)
        services = self.parser.filter_top_ports(xml_root)
        return services

    # Using of basic options for stealth scan
    @user_is_root
    def nmap_stealth_scan(self, target, arg="-Pn -sZ", args=None):
        """
        nmap -oX - nmmapper.com -Pn -sZ
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_detect_firewall(self, target, arg="-sA", args=None):  # requires root
        """
        nmap -oX - nmmapper.com -sA
        @ TODO
        """
        return self.scan_command(target=target, arg=arg, args=args)
        # TODO

    @user_is_root
    def nmap_os_detection(self, target, arg="-O", args=None):  # requires root
        """
        nmap -oX - nmmapper.com -O
        NOTE: Requires root
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.os_identifier_parser(xml_root)
        return results

    def nmap_subnet_scan(self, target, arg="-p-", args=None):  # requires root
        """
        nmap -oX - nmmapper.com -p-
        NOTE: Requires root
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_list_scan(self, target, arg="-sL", args=None):  # requires root
        """
        The list scan is a degenerate form of target discovery that simply lists each target of the network(s)
        specified, without sending any packets to the target targets.

        NOTE: /usr/bin/nmap  -oX  -  192.168.178.1/24  -sL
        """
        self.target = target
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def run_command(self, cmd, timeout=None):
        """
        Runs the nmap command using popen

        @param: cmd--> the command we want run eg /usr/bin/nmap -oX -  nmmapper.com --top-ports 10
        @param: timeout--> command subprocess timeout in seconds.
        """
        sub_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                )
        try:
            output, errs = sub_proc.communicate(timeout=timeout)
        except Exception as e:
            sub_proc.kill()
            raise (e)
        else:
            if 0 != sub_proc.returncode:
                raise NmapExecutionError(
                        'Error during command: "' + ' '.join(cmd) + '"\n\n' \
                        + errs.decode('utf8')
                        )
            # Response is bytes so decode the output and return
            return output.decode('utf8').strip()
            

    def get_xml_et(self, command_output):
        """
        @ return xml ET
        """
        try:
            self.raw_output = command_output
            return ET.fromstring(command_output)
        except ParseError:
            raise NmapXMLParserError()


    def get_success_xml_et(self,file_name):
        root = ET.Element("root")
        success = ET.SubElement(root, "success")
        success.text = "Nmap scan completed successfully."
        file_path = ET.SubElement(root, "file_path")
        file_path.text = "{}".format(file_name)
        ET.ElementTree(root)
        return root

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
    6) UDP Scan (-sU)
    7) IP Scan (-sO)
    """

    def __init__(self, path:str=''):
        super(NmapScanTechniques, self).__init__(path=path)

        self.sync_scan = "-sS"
        self.tcp_connt = "-sT"
        self.fin_scan = "-sF"
        self.ping_scan = "-sP"
        self.idle_scan = "-sL"
        self.udp_scan = "-sU"
        self.ip_scan = "-sO"
        self.parser = NmapCommandParser(None)

    # Unique method for repetitive tasks - Use of 'target' variable instead of 'host' or 'subnet' - no need to make difference between 2 strings that are used for the same purpose. Creating a scan template as a switcher
    def scan_command(self, scan_type, target, args, timeout=None):
        def tpl(i):
            scan_template = {
                1: self.fin_scan,
                2: self.sync_scan,
                3: self.tcp_connt,
                4: self.ping_scan,
                5: self.idle_scan,
                6: self.udp_scan,
                7: self.ip_scan
            }

            return scan_template.get(i)

        for i in range(1, 8):
            if scan_type == tpl(i):
                scan = " {target} {default}".format(target=target, default=scan_type)
                scan_type_command = self.default_command() + scan

                if (args):
                    scan_type_command += " {0}".format(args)

                scan_shlex = shlex.split(scan_type_command)

                # Use the ping scan parser
                output = self.run_command(scan_shlex, timeout=timeout)
                xml_root = self.get_xml_et(output)

                return xml_root
        raise Exception("Something went wrong")
            

    @user_is_root
    def nmap_fin_scan(self, target, args=None):
        """
        Perform scan using nmap's fin scan

        @cmd nmap -sF 192.168.178.1

        """
        xml_root = self.scan_command(self.fin_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results
    
    @user_is_root
    def nmap_syn_scan(self, target, args=None):
        """
        Perform syn scan on this given
        target

        @cmd nmap -sS 192.168.178.1
        """
        xml_root = self.scan_command(self.sync_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_tcp_scan(self, target, args=None):
        """
        Scan target using the nmap tcp connect

        @cmd nmap -sT 192.168.178.1
        """
        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = self.scan_command(self.tcp_connt, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results
    
    @user_is_root
    def nmap_udp_scan(self, target, args=None):
        """
        Scan target using the nmap tcp connect

        @cmd nmap -sU 192.168.178.1
        """

        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = self.scan_command(self.udp_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_ping_scan(self, target, args=None):
        """
        Scan target using nmaps' ping scan

        @cmd nmap -sP 192.168.178.1
        """
        xml_root = self.scan_command(self.ping_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_idle_scan(self, target, args=None):
        """
        Using nmap idle_scan

        @cmd nmap -sL 192.168.178.1
        """
        xml_root = self.scan_command(self.idle_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_ip_scan(self, target, args=None):
        """
        Using nmap ip_scan

        @cmd nmap -sO 192.168.178.1
        """
        xml_root = self.scan_command(self.ip_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

class NmapHostDiscovery(Nmap):
    """
    This object will perform host discovery

    1) Only port scan    (-Pn)
    2) Only host discover    (-sn)
    3) Arp discovery on a local network  (-PR)
    4) Disable DNS resolution    (-n)
    """

    def __init__(self, path:str=''):
        super(NmapHostDiscovery, self).__init__(path=path)

        self.port_scan_only = "-Pn"
        self.no_port_scan = "-sn"
        self.arp_discovery = "-PR"
        self.disable_dns = "-n"
        self.parser = NmapCommandParser(None)

    def scan_command(self, scan_type, target, args, timeout=None):
        def tpl(i):
            scan_template = {
                1: self.port_scan_only,
                2: self.no_port_scan,
                3: self.arp_discovery,
                4: self.disable_dns
            }

            return scan_template.get(i)

        for i in range(1, 5):
            if scan_type == tpl(i):
                scan = " {target} {default}".format(target=target, default=scan_type)
                scan_type_command = self.default_command() + scan

                if (args):
                    scan_type_command += " {0}".format(args)

                scan_shlex = shlex.split(scan_type_command)

                # Use the ping scan parser
                output = self.run_command(scan_shlex, timeout=timeout)
                xml_root = self.get_xml_et(output)

                return xml_root
        raise Exception("Something went wrong")

    def nmap_portscan_only(self, target, args=None):
        """
        Scan target using the nmap tcp connect

        @cmd nmap -Pn 192.168.178.1
        """
        xml_root = self.scan_command(self.port_scan_only, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_no_portscan(self, target, args=None):
        """
        Scan target using the nmap tcp connect

        @cmd nmap -sn 192.168.178.1
        """
        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = self.scan_command(self.no_port_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_arp_discovery(self, target, args=None):
        """
        Scan target using the nmap tcp connect
        @cmd nmap -PR 192.168.178.1
        """
        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = self.scan_command(self.arp_discovery, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_disable_dns(self, target, args=None):
        """
        Scan target using the nmap tcp connect
        @cmd nmap -n 192.168.178.1
        """
        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = self.scan_command(self.disable_dns, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

class NmapAsync(Nmap):
    def __init__(self, path:str=''):
        super(NmapAsync, self).__init__(path=path)
        self.stdout = asyncio.subprocess.PIPE
        self.stderr = asyncio.subprocess.PIPE
        
    async def run_command(self, cmd, timeout=None):        
        process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=self.stdout,
                stderr=self.stderr
                )
            
        try:
            data, stderr = await process.communicate()
        except Exception as e:
            raise (e)
        else:
            if 0 != process.returncode:
                raise NmapExecutionError(
                    'Error during command: "' + ' '.join(cmd) + '"\n\n' + \
                    stderr.decode('utf8')
                    )

            # Response is bytes so decode the output and return
            return data.decode('utf8').strip()
    
    async def scan_command(self, target, arg, args=None, timeout=None):
        self.target = target

        command_args = "{target}  {default}".format(target=target, default=arg)
        scancommand = self.default_command() + command_args
        if (args):
            scancommand += " {0}".format(args)

        output = await self.run_command(scancommand, timeout=timeout)
        xml_root = self.get_xml_et(output)

        return xml_root
        
    async def scan_top_ports(self, target, default=10, args=None, timeout=None):
        top_port_args = " {target} --top-ports {default}".format(target=target, default=default)
        command = self.default_command() + top_port_args
        if (args):
            command += " {0}".format(args)

        output = await self.run_command(command, timeout=timeout)
        if not output:
            raise ValueError("Unable to perform requested command")

        self.top_ports = self.parser.filter_top_ports(self.get_xml_et(output))
        return self.top_ports
    
    async def nmap_dns_brute_script(self, target, dns_brute="--script dns-brute.nse", args=None, timeout=None):
        self.target = target

        dns_brute_args = "{target}  {default}".format(target=target, default=dns_brute)
        dns_brute_command = self.default_command() + dns_brute_args
        
        if args:
            dns_brute_command += " {0}".format(args)
            
        # Run the command and get the output
        output = await self.run_command(dns_brute_command, timeout=timeout)
        subdomains = self.parser.filter_subdomains(self.get_xml_et(output))
        return subdomains

    async def nmap_version_detection(self, target, arg="-sV", args=None, timeout=None):
        xml_root = await self.scan_command(target=target, arg=arg, timeout=timeout)
        services = self.parser.filter_top_ports(xml_root)
        return services

    async def nmap_stealth_scan(self, target, arg="-Pn -sZ", args=None):
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    async def nmap_os_detection(self, target, arg="-O", args=None):  # requires root
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.os_identifier_parser(xml_root)
        return results

    async def nmap_subnet_scan(self, target, arg="-p-", args=None):  # requires root
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_list_scan(self, target, arg="-sL", args=None):  # requires root
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

class NmapScanTechniquesAsync(NmapAsync,NmapScanTechniques):
    def __init__(self, path:str=''):
        super(NmapScanTechniquesAsync, self).__init__(path=path)
        self.udp_scan = "-sU"
        
    async def scan_command(self, scan_type, target, args, timeout=None):
        def tpl(i):
            scan_template = {
                1: self.fin_scan,
                2: self.sync_scan,
                3: self.tcp_connt,
                4: self.ping_scan,
                5: self.idle_scan,
                6: self.udp_scan,
                7: self.ip_scan
            }

            return scan_template.get(i)

        for i in range(1, 8):
            if scan_type == tpl(i):
                scan = " {target} {default}".format(target=target, default=scan_type)
                scan_type_command = self.default_command() + scan

                if (args):
                    scan_type_command += " {0}".format(args)

                output = await self.run_command(scan_type_command, timeout=timeout)
                xml_root = self.get_xml_et(output)

                return xml_root
        raise Exception("Something went wrong")
    
    async def nmap_udp_scan(self, target, args=None):
        if (args):
            assert (isinstance(args, str)), "Expected string got {0} instead".format(type(args))
        xml_root = await self.scan_command(self.udp_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Python3 nmap")
    parser.add_argument('-d', '--d', help='Help', required=True)
    args = parser.parse_args()
    
    nmap = NmapScanTechniquesAsync()
    asyncio.run(nmap.nmap_udp_scan(target='127.0.0.1'))
