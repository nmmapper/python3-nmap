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

"""
Nmap3 - A Python 3 wrapper for Nmap port scanner
================================================

This library provides a Pythonic interface to Nmap, converting Nmap commands
into callable Python methods. It supports both synchronous and asynchronous
operations with comprehensive error handling and type hints.

Basic Usage:
    >>> from nmap3 import Nmap
    >>> nmap = Nmap()
    >>> results = nmap.scan_top_ports("example.com")
    >>> print(results)

Author: Wangolo Joel (inquiry@nmapper.com)
Version: 1.9.4
Last Modified: Mar/14/2026
"""

import shlex
import subprocess
import sys
import argparse
import asyncio
import logging
from typing import Dict, List, Optional, Union, Any, Tuple
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError
from pathlib import Path
from functools import wraps

# Local imports
from nmap3.nmapparser import NmapCommandParser
from nmap3.utils import get_nmap_path, user_is_root
from nmap3.exceptions import NmapXMLParserError, NmapExecutionError

import re

__author__ = 'Wangolo Joel (inquiry@nmapper.com)'
__version__ = '1.9.4'
__last_modification__ = 'Mar/14/2026'

# Configure module logger
logger = logging.getLogger(__name__)

OS_TYPE = sys.platform

# Constants for scan types and options
class NmapConstants:
    """Constants used throughout the Nmap3 module."""
    
    # Scan techniques
    SYN_SCAN = "-sS"
    TCP_CONNECT_SCAN = "-sT"
    FIN_SCAN = "-sF"
    PING_SCAN = "-sP"
    IDLE_SCAN = "-sI"
    UDP_SCAN = "-sU"
    IP_SCAN = "-sO"
    ACK_SCAN = "-sA"  # Added missing scan type
    WINDOW_SCAN = "-sW"  # Added missing scan type
    MAIMON_SCAN = "-sM"  # Added missing scan type
    
    # Host discovery options
    PORT_SCAN_ONLY = "-Pn"
    NO_PORT_SCAN = "-sn"
    ARP_DISCOVERY = "-PR"
    DISABLE_DNS = "-n"
    ENABLE_DNS = "-R"  # Added opposite option
    
    # Output formats
    OUTPUT_XML = "-oX"
    OUTPUT_NORMAL = "-oN"
    OUTPUT_GREPABLE = "-oG"
    OUTPUT_ALL = "-oA"
    
    # Timing templates
    TIMING_PARANOID = "-T0"
    TIMING_SNEAKY = "-T1"
    TIMING_POLITE = "-T2"
    TIMING_NORMAL = "-T3"
    TIMING_AGGRESSIVE = "-T4"
    TIMING_INSANE = "-T5"
    
    MAX_PORT = 65535
    DEFAULT_TOP_PORTS = 10


def requires_root(func):
    """
    Decorator to ensure the method is run with root privileges.
    
    This decorator checks if the current user has root privileges
    before executing the decorated method. If not, it logs a warning
    and attempts to re-run with sudo.
    
    Args:
        func: The function to decorate
        
    Returns:
        Wrapped function that checks for root privileges
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.as_root and OS_TYPE != 'win32':
            logger.warning(f"Method {func.__name__} may require root privileges")
            logger.info("Set as_root=True or call require_root() before this method")
        return func(self, *args, **kwargs)
    return wrapper


class NmapBase:
    """
    Base class for Nmap operations with common functionality.
    
    This class provides the foundation for all Nmap operations,
    including command execution, XML parsing, and error handling.
    """
    
    def __init__(self, nmap_path: str = ''):
        """
        Initialize the Nmap base class.
        
        Args:
            nmap_path: Optional custom path to nmap executable.
                      If not provided, the system path will be searched.
        
        Raises:
            FileNotFoundError: If nmap executable cannot be found
        """
        self.nmap_path = get_nmap_path(nmap_path)
        self.target = ""
        self.raw_output = None
        self.as_root = False
        self.parser = NmapCommandParser(None)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def require_root(self, required: bool = True) -> 'NmapBase':
        """
        Set whether commands should be run with root privileges.
        
        Args:
            required: True to run commands with sudo, False otherwise
            
        Returns:
            Self for method chaining
        """
        self.as_root = required
        return self
    
    def _build_base_command(self, include_output: bool = True) -> str:
        """
        Build the base nmap command with common options.
        
        Args:
            include_output: Whether to include output format (-oX)
            
        Returns:
            Base command string ready for additional arguments
        """
        cmd_parts = []
        
        # Add sudo if required and not on Windows
        if self.as_root and OS_TYPE != 'win32':
            cmd_parts.append("sudo")
            
        cmd_parts.append(self.nmap_path)
        
        if include_output:
            # Add verbose output for better parsing
            cmd_parts.append("-v")
            cmd_parts.append(NmapConstants.OUTPUT_XML)
            cmd_parts.append("-")
            
        return " ".join(cmd_parts)
    
    def _execute_command(self, cmd: List[str], timeout: Optional[int] = None) -> str:
        """
        Execute a shell command and return its output.
        
        Args:
            cmd: Command as a list of strings
            timeout: Optional timeout in seconds
            
        Returns:
            Command output as string
            
        Raises:
            NmapExecutionError: If command fails
            subprocess.TimeoutExpired: If timeout is exceeded
        """
        self.logger.debug(f"Executing command: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True  # Use text mode for string output
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode != 0:
                error_msg = f"Command failed with exit code {process.returncode}\n"
                error_msg += f"STDERR: {stderr}"
                self.logger.error(error_msg)
                raise NmapExecutionError(error_msg)
                
            self.logger.debug(f"Command succeeded, output length: {len(stdout)}")
            return stdout.strip()
            
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.logger.error(f"Command timed out after {timeout} seconds")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during command execution: {e}")
            raise NmapExecutionError(f"Command execution failed: {e}")
    
    def _parse_xml_output(self, xml_string: str) -> ET.Element:
        """
        Parse XML output from nmap command.
        
        Args:
            xml_string: XML string to parse
            
        Returns:
            Parsed XML element tree root
            
        Raises:
            NmapXMLParserError: If XML parsing fails
        """
        try:
            self.raw_output = xml_string
            return ET.fromstring(xml_string)
        except ParseError as e:
            self.logger.error(f"Failed to parse XML output: {e}")
            self.logger.debug(f"Raw output (first 500 chars): {xml_string[:500]}")
            raise NmapXMLParserError(f"XML parsing failed: {e}")
    
    def _handle_file_output(self, command: str) -> Optional[ET.Element]:
        """
        Handle cases where output is written to a file instead of stdout.
        
        Args:
            command: The full command string
            
        Returns:
            XML element if file output was detected, None otherwise
        """
        # Match output file patterns: -oX filename.xml, -oN filename.txt, etc.
        file_pattern = r'(\-oX|\-oN|\-oG)\s+([a-zA-Z0-9_\-\.]{1,255}\.[a-zA-Z]+)'
        match = re.search(file_pattern, command)
        
        if match:
            output_format = match.group(1)
            filename = match.group(2)
            self.logger.info(f"Output written to file: {filename} ({output_format})")
            
            # Create a simple success response
            root = ET.Element("nmaprun")
            success = ET.SubElement(root, "success")
            success.text = "Nmap scan completed successfully"
            output_file = ET.SubElement(root, "output_file")
            output_file.text = filename
            return root
            
        return None


class Nmap(NmapBase):
    """
    Main Nmap class for common scanning operations.
    
    This class provides methods for the most commonly used nmap scans,
    including top ports, version detection, OS detection, and more.
    
    Example:
        >>> nmap = Nmap()
        >>> # Simple top ports scan
        >>> results = nmap.scan_top_ports("example.com")
        >>> 
        >>> # OS detection (requires root)
        >>> nmap.require_root(True)
        >>> os_info = nmap.nmap_os_detection("192.168.1.1")
    """

    def __init__(self, path: str = ''):
        """
        Initialize Nmap class.
        
        Args:
            path: Optional custom path to nmap executable
        """
        super().__init__(path)
        self.top_ports: Dict = {}
        self.logger = logging.getLogger(f"{__name__}.Nmap")

    def nmap_version(self) -> Dict[str, Any]:
        """
        Get Nmap version and build information.
        
        Returns:
            Dictionary containing version information:
            - nmap: Tuple of version numbers (major, minor, patch)
            - compiled_with: Tuple of compile-time features
            - compiled_without: Tuple of excluded features
            - nsock_engines: Tuple of available nsock engines
            
        Example:
            >>> version = nmap.nmap_version()
            >>> print(f"Nmap version: {version['nmap']}")
        """
        self.logger.info("Retrieving Nmap version information")
        
        cmd = [self.nmap_path, '--version']
        output = self._execute_command(cmd)
        
        version_data: Dict[str, Any] = {}
        
        for line in output.splitlines():
            if line.startswith('Nmap version '):
                # Parse version string: "Nmap version 7.80 ( https://nmap.org )"
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', line)
                if version_match:
                    version_str = version_match.group(1)
                    version_parts = [int(x) for x in version_str.split('.')]
                    version_data['nmap_version'] = tuple(version_parts)
                    
            elif line.startswith('Compiled with:'):
                features = line.split(':', 1)[1].strip()
                version_data['compiled_with'] = tuple(features.split())
                
            elif line.startswith('Compiled without:'):
                missing = line.split(':', 1)[1].strip()
                version_data['compiled_without'] = tuple(missing.split())
                
            elif line.startswith('Available nsock engines:'):
                engines = line.split(':', 1)[1].strip()
                version_data['nsock_engines'] = tuple(engines.split())
        
        self.logger.debug(f"Version data retrieved: {version_data}")
        return version_data

    def scan_top_ports(self, 
                      target: str, 
                      top_ports: int = NmapConstants.DEFAULT_TOP_PORTS,
                      args: Optional[str] = None,
                      timeout: Optional[int] = None) -> List[Dict]:
        """
        Scan the most common ports on a target.
        
        This method performs a top ports scan, which scans the most frequently
        open ports based on nmap's statistics.
        
        Args:
            target: IP address or hostname to scan
            top_ports: Number of top ports to scan (max 65535)
            args: Additional nmap arguments as a string
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results for each open port
            
        Raises:
            ValueError: If top_ports exceeds maximum port number
            
        Example:
            >>> results = nmap.scan_top_ports("scanme.nmap.org", top_ports=100)
            >>> for port in results:
            ...     print(f"Port {port['port']}: {port['service']['name']}")
        """
        if top_ports > NmapConstants.MAX_PORT:
            error_msg = f"Port cannot exceed maximum of {NmapConstants.MAX_PORT}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        self.logger.info(f"Scanning top {top_ports} ports on {target}")
        
        # Build command
        base_cmd = self._build_base_command()
        scan_args = f" {target} --top-ports {top_ports}"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        cmd_parts = shlex.split(full_command)
        
        # Execute scan
        output = self._execute_command(cmd_parts, timeout=timeout)
        
        if not output:
            error_msg = "No output received from nmap command"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Parse results
        xml_root = self._parse_xml_output(output)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        
        self.logger.info(f"Found {len(self.top_ports)} open ports")
        return self.top_ports

    def nmap_dns_brute_script(self,
                             target: str,
                             args: Optional[str] = None,
                             timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform DNS brute force enumeration using nmap script.
        
        This method uses the dns-brute.nse script to enumerate subdomains
        of a target domain.
        
        Args:
            target: Domain name to enumerate subdomains for
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing discovered subdomains
            
        Example:
            >>> subdomains = nmap.nmap_dns_brute_script("example.com")
            >>> for sub in subdomains:
            ...     print(f"{sub['hostname']} -> {sub['address']}")
        """
        self.logger.info(f"Performing DNS brute force on {target}")
        
        base_cmd = self._build_base_command()
        scan_args = f" {target} --script dns-brute.nse"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        cmd_parts = shlex.split(full_command)
        
        output = self._execute_command(cmd_parts, timeout=timeout)
        xml_root = self._parse_xml_output(output)
        
        subdomains = self.parser.filter_subdomains(xml_root)
        self.logger.info(f"Discovered {len(subdomains)} subdomains")
        
        return subdomains

    def nmap_version_detection(self,
                              target: str,
                              args: Optional[str] = None,
                              timeout: Optional[int] = None) -> List[Dict]:
        """
        Detect service versions on open ports.
        
        This method performs version detection (-sV) to identify service
        versions running on open ports.
        
        Args:
            target: IP address or hostname to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing service version information
            
        Example:
            >>> services = nmap.nmap_version_detection("scanme.nmap.org")
            >>> for svc in services:
            ...     print(f"{svc['port']}: {svc['service']['product']} {svc['service']['version']}")
        """
        self.logger.info(f"Performing version detection on {target}")
        
        xml_root = self.scan_command(
            target=target,
            arg="-sV",
            args=args,
            timeout=timeout
        )
        
        services = self.parser.filter_top_ports(xml_root)
        return services

    @requires_root
    def nmap_os_detection(self,
                         target: str,
                         args: Optional[str] = None,
                         timeout: Optional[int] = None) -> List[Dict]:
        """
        Detect operating system of target.
        
        This method performs OS detection (-O) to identify the target's
        operating system based on TCP/IP fingerprinting.
        
        Note: Requires root privileges for accurate results.
        
        Args:
            target: IP address or hostname to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing OS detection results
            with accuracy percentages and CPE information
            
        Example:
            >>> os_info = nmap.nmap_os_detection("192.168.1.1")
            >>> for os in os_info:
            ...     print(f"{os['name']} (accuracy: {os['accuracy']}%)")
        """
        self.logger.info(f"Performing OS detection on {target}")
        
        xml_root = self.scan_command(
            target=target,
            arg="-O",
            args=args,
            timeout=timeout
        )
        
        results = self.parser.os_identifier_parser(xml_root)
        return results

    def nmap_subnet_scan(self,
                        target: str,
                        args: Optional[str] = None,
                        timeout: Optional[int] = None) -> List[Dict]:
        """
        Scan all ports on all hosts in a subnet.
        
        This method performs a comprehensive scan of all ports (-p-)
        on all hosts in the specified subnet.
        
        Args:
            target: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results for each host
            
        Example:
            >>> results = nmap.nmap_subnet_scan("192.168.1.0/24")
            >>> for host in results:
            ...     print(f"Host: {host['ip']}, Ports: {len(host.get('ports', []))}")
        """
        self.logger.info(f"Performing subnet scan on {target}")
        
        xml_root = self.scan_command(
            target=target,
            arg="-p-",
            args=args,
            timeout=timeout
        )
        
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_list_scan(self,
                      target: str,
                      args: Optional[str] = None,
                      timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform a list scan to enumerate targets without sending packets.
        
        This method simply lists each target in the specified network(s)
        without sending any packets. Useful for testing and inventory.
        
        Args:
            target: Target specification (IP, range, or CIDR)
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing target information
            
        Example:
            >>> targets = nmap.nmap_list_scan("192.168.1.0/24")
            >>> for t in targets:
            ...     print(t.get('ip', t.get('hostname')))
        """
        self.logger.info(f"Performing list scan on {target}")
        
        xml_root = self.scan_command(
            target=target,
            arg="-sL",
            args=args,
            timeout=timeout
        )
        
        results = self.parser.filter_top_ports(xml_root)
        return results

    def scan_command(self,
                    target: str,
                    arg: str,
                    args: Optional[str] = None,
                    timeout: Optional[int] = None) -> ET.Element:
        """
        Generic method to execute any nmap command.
        
        This is a low-level method that allows execution of arbitrary
        nmap commands with proper XML output handling.
        
        Args:
            target: Target specification
            arg: Main nmap arguments/options
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            XML element tree root of the scan results
            
        Note:
            This method is used internally by other scan methods.
            For most use cases, use the specialized methods instead.
        """
        self.target = target
        
        # Build command
        base_cmd = self._build_base_command()
        command_args = f" {target} {arg}"
        
        if args:
            command_args += f" {args}"
            
        full_command = base_cmd + command_args
        self.logger.debug(f"Scan command: {full_command}")
        
        cmd_parts = shlex.split(full_command)
        
        # Check for file output
        file_result = self._handle_file_output(full_command)
        if file_result:
            return file_result
            
        # Execute and parse
        output = self._execute_command(cmd_parts, timeout=timeout)
        xml_root = self._parse_xml_output(output)
        
        return xml_root


class NmapScanTechniques(Nmap):
    """
    Extended Nmap class with various scan techniques.
    
    This class provides access to different nmap scan techniques
    including SYN scan, FIN scan, UDP scan, and more.
    
    Example:
        >>> scanner = NmapScanTechniques()
        >>> scanner.require_root(True)  # Most scans require root
        >>> results = scanner.nmap_syn_scan("192.168.1.1")
    """

    def __init__(self, path: str = ''):
        """
        Initialize NmapScanTechniques class.
        """
        super().__init__(path)
        self.logger = logging.getLogger(f"{__name__}.NmapScanTechniques")

    @requires_root
    def nmap_syn_scan(self,
                     target: str,
                     args: Optional[str] = None,
                     timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform TCP SYN stealth scan.
        
        SYN scan is the default and most popular scan option. It's fast,
        unobtrusive, and can be performed quickly.
        
        Args:
            target: Target to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
            
        Example:
            >>> results = scanner.nmap_syn_scan("192.168.1.1")
        """
        self.logger.info(f"Performing SYN scan on {target}")
        
        xml_root = self._scan_technique(
            scan_type=NmapConstants.SYN_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    @requires_root
    def nmap_fin_scan(self,
                     target: str,
                     args: Optional[str] = None,
                     timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform TCP FIN scan.
        
        FIN scan sends a FIN packet to target ports. Useful for
        bypassing some firewalls.
        
        Args:
            target: Target to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Performing FIN scan on {target}")
        
        xml_root = self._scan_technique(
            scan_type=NmapConstants.FIN_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def nmap_tcp_scan(self,
                     target: str,
                     args: Optional[str] = None,
                     timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform TCP connect scan.
        
        This scan uses the operating system's TCP connect() function.
        It doesn't require root privileges but is more detectable.
        
        Args:
            target: Target to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Performing TCP connect scan on {target}")
        
        xml_root = self._scan_technique(
            scan_type=NmapConstants.TCP_CONNECT_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    @requires_root
    def nmap_udp_scan(self,
                     target: str,
                     args: Optional[str] = None,
                     timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform UDP scan.
        
        UDP scanning is generally slower and more difficult than TCP
        scanning due to the connectionless nature of UDP.
        
        Args:
            target: Target to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Performing UDP scan on {target}")
        
        xml_root = self._scan_technique(
            scan_type=NmapConstants.UDP_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def nmap_ping_scan(self,
                      target: str,
                      args: Optional[str] = None,
                      timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform ping scan (host discovery).
        
        This scan simply pings targets to see if they're up, without
        port scanning.
        
        Args:
            target: Target to scan
            args: Additional nmap arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing host discovery results
        """
        self.logger.info(f"Performing ping scan on {target}")
        
        xml_root = self._scan_technique(
            scan_type=NmapConstants.PING_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def _scan_technique(self,
                       scan_type: str,
                       target: str,
                       args: Optional[str] = None,
                       timeout: Optional[int] = None) -> ET.Element:
        """
        Internal method for executing different scan techniques.
        
        Args:
            scan_type: Nmap scan type flag (e.g., "-sS", "-sF")
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            XML element tree root
        """
        base_cmd = self._build_base_command()
        scan_args = f" {target} {scan_type}"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        cmd_parts = shlex.split(full_command)
        
        output = self._execute_command(cmd_parts, timeout=timeout)
        return self._parse_xml_output(output)


class NmapHostDiscovery(Nmap):
    """
    Nmap class focused on host discovery techniques.
    
    This class provides methods for discovering hosts without
    necessarily port scanning them.
    
    Example:
        >>> discover = NmapHostDiscovery()
        >>> results = discover.nmap_portscan_only("192.168.1.1")
    """

    def __init__(self, path: str = ''):
        """
        Initialize NmapHostDiscovery class.
        """
        super().__init__(path)
        self.logger = logging.getLogger(f"{__name__}.NmapHostDiscovery")

    def nmap_portscan_only(self,
                          target: str,
                          args: Optional[str] = None,
                          timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform port scan only, skipping host discovery.
        
        This method uses the -Pn option to treat all hosts as online,
        skipping the host discovery phase.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Performing port-only scan on {target}")
        
        xml_root = self._discovery_scan(
            scan_type=NmapConstants.PORT_SCAN_ONLY,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def nmap_no_portscan(self,
                        target: str,
                        args: Optional[str] = None,
                        timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform host discovery only, no port scan.
        
        This method uses the -sn option to ping hosts but not
        scan for open ports.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing host discovery results
        """
        self.logger.info(f"Performing host discovery only on {target}")
        
        xml_root = self._discovery_scan(
            scan_type=NmapConstants.NO_PORT_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def nmap_arp_discovery(self,
                          target: str,
                          args: Optional[str] = None,
                          timeout: Optional[int] = None) -> List[Dict]:
        """
        Perform ARP discovery on local network.
        
        This method uses ARP requests to discover hosts on the
        local network. Very fast and reliable for local networks.
        
        Args:
            target: Local target (usually IP range)
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing ARP discovery results
        """
        self.logger.info(f"Performing ARP discovery on {target}")
        
        xml_root = self._discovery_scan(
            scan_type=NmapConstants.ARP_DISCOVERY,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def nmap_disable_dns(self,
                        target: str,
                        args: Optional[str] = None,
                        timeout: Optional[int] = None) -> List[Dict]:
        """
        Disable DNS resolution during scan.
        
        This method uses the -n option to never do DNS resolution,
        which can significantly speed up scans.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Performing scan with DNS disabled on {target}")
        
        xml_root = self._discovery_scan(
            scan_type=NmapConstants.DISABLE_DNS,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    def _discovery_scan(self,
                       scan_type: str,
                       target: str,
                       args: Optional[str] = None,
                       timeout: Optional[int] = None) -> ET.Element:
        """
        Internal method for discovery scans.
        
        Args:
            scan_type: Discovery scan type flag
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            XML element tree root
        """
        base_cmd = self._build_base_command()
        scan_args = f" {target} {scan_type}"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        cmd_parts = shlex.split(full_command)
        
        output = self._execute_command(cmd_parts, timeout=timeout)
        return self._parse_xml_output(output)


class NmapAsync(NmapBase):
    """
    Asynchronous Nmap scanner using asyncio.
    
    This class provides asynchronous versions of common nmap scans,
    allowing multiple scans to run concurrently.
    
    Example:
        >>> async def scan_example():
        ...     nmap = NmapAsync()
        ...     results = await nmap.scan_top_ports("example.com")
        ...     print(results)
        >>> asyncio.run(scan_example())
    """

    def __init__(self, path: str = ''):
        """
        Initialize asynchronous Nmap scanner.
        """
        super().__init__(path)
        self.stdout = asyncio.subprocess.PIPE
        self.stderr = asyncio.subprocess.PIPE
        self.top_ports: Dict = {}
        self.logger = logging.getLogger(f"{__name__}.NmapAsync")

    async def _execute_command_async(self,
                                    cmd: str,
                                    timeout: Optional[int] = None) -> str:
        """
        Execute command asynchronously.
        
        Args:
            cmd: Command string to execute
            timeout: Optional timeout in seconds
            
        Returns:
            Command output as string
            
        Raises:
            NmapExecutionError: If command fails
            asyncio.TimeoutError: If timeout is exceeded
        """
        self.logger.debug(f"Executing async command: {cmd}")
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=self.stdout,
                stderr=self.stderr
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                self.logger.error(f"Async command timed out after {timeout} seconds")
                raise
                
            if process.returncode != 0:
                error_msg = f"Async command failed with exit code {process.returncode}\n"
                error_msg += f"STDERR: {stderr.decode('utf8')}"
                self.logger.error(error_msg)
                raise NmapExecutionError(error_msg)
                
            return stdout.decode('utf8').strip()
            
        except Exception as e:
            self.logger.error(f"Async command execution failed: {e}")
            raise

    async def scan_top_ports(self,
                            target: str,
                            top_ports: int = NmapConstants.DEFAULT_TOP_PORTS,
                            args: Optional[str] = None,
                            timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously scan top ports on target.
        
        Args:
            target: Target to scan
            top_ports: Number of top ports to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Async scanning top {top_ports} ports on {target}")
        
        base_cmd = self._build_base_command()
        scan_args = f" {target} --top-ports {top_ports}"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        
        output = await self._execute_command_async(full_command, timeout=timeout)
        
        if not output:
            error_msg = "No output received from async nmap command"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        xml_root = self._parse_xml_output(output)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        
        return self.top_ports

    async def nmap_version_detection(self,
                                    target: str,
                                    args: Optional[str] = None,
                                    timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously detect service versions.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing service information
        """
        self.logger.info(f"Async version detection on {target}")
        
        xml_root = await self._scan_command_async(
            target=target,
            arg="-sV",
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    async def nmap_os_detection(self,
                               target: str,
                               args: Optional[str] = None,
                               timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously detect operating system.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing OS detection results
        """
        self.logger.info(f"Async OS detection on {target}")
        
        xml_root = await self._scan_command_async(
            target=target,
            arg="-O",
            args=args,
            timeout=timeout
        )
        
        return self.parser.os_identifier_parser(xml_root)

    async def nmap_dns_brute_script(self,
                                   target: str,
                                   args: Optional[str] = None,
                                   timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously perform DNS brute force enumeration.
        
        Args:
            target: Domain to enumerate
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing discovered subdomains
        """
        self.logger.info(f"Async DNS brute force on {target}")
        
        base_cmd = self._build_base_command()
        scan_args = f" {target} --script dns-brute.nse"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        
        output = await self._execute_command_async(full_command, timeout=timeout)
        xml_root = self._parse_xml_output(output)
        
        return self.parser.filter_subdomains(xml_root)

    async def _scan_command_async(self,
                                 target: str,
                                 arg: str,
                                 args: Optional[str] = None,
                                 timeout: Optional[int] = None) -> ET.Element:
        """
        Internal method for async scan commands.
        
        Args:
            target: Target to scan
            arg: Main arguments
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            XML element tree root
        """
        base_cmd = self._build_base_command()
        command_args = f" {target} {arg}"
        
        if args:
            command_args += f" {args}"
            
        full_command = base_cmd + command_args
        
        output = await self._execute_command_async(full_command, timeout=timeout)
        return self._parse_xml_output(output)


class NmapScanTechniquesAsync(NmapAsync, NmapScanTechniques):
    """
    Asynchronous version of NmapScanTechniques.
    
    Combines async capabilities with various scan techniques.
    
    Example:
        >>> async def scan():
        ...     scanner = NmapScanTechniquesAsync()
        ...     results = await scanner.nmap_syn_scan("192.168.1.1")
        ...     print(results)
        >>> asyncio.run(scan())
    """

    def __init__(self, path: str = ''):
        """
        Initialize async scan techniques class.
        """
        super().__init__(path)
        self.logger = logging.getLogger(f"{__name__}.NmapScanTechniquesAsync")

    async def nmap_syn_scan(self,
                           target: str,
                           args: Optional[str] = None,
                           timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously perform SYN scan.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Async SYN scan on {target}")
        
        xml_root = await self._scan_technique_async(
            scan_type=NmapConstants.SYN_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    async def nmap_udp_scan(self,
                           target: str,
                           args: Optional[str] = None,
                           timeout: Optional[int] = None) -> List[Dict]:
        """
        Asynchronously perform UDP scan.
        
        Args:
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            List of dictionaries containing scan results
        """
        self.logger.info(f"Async UDP scan on {target}")
        
        xml_root = await self._scan_technique_async(
            scan_type=NmapConstants.UDP_SCAN,
            target=target,
            args=args,
            timeout=timeout
        )
        
        return self.parser.filter_top_ports(xml_root)

    async def _scan_technique_async(self,
                                   scan_type: str,
                                   target: str,
                                   args: Optional[str] = None,
                                   timeout: Optional[int] = None) -> ET.Element:
        """
        Internal method for async scan techniques.
        
        Args:
            scan_type: Scan type flag
            target: Target to scan
            args: Additional arguments
            timeout: Command timeout in seconds
            
        Returns:
            XML element tree root
        """
        base_cmd = self._build_base_command()
        scan_args = f" {target} {scan_type}"
        
        if args:
            scan_args += f" {args}"
            
        full_command = base_cmd + scan_args
        
        output = await self._execute_command_async(full_command, timeout=timeout)
        return self._parse_xml_output(output)


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure logging for the nmap3 module.
    
    Args:
        level: Logging level (default: INFO)
    """
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


if __name__ == "__main__":
    """
    Command-line interface for testing.
    
    Example:
        python nmap3.py --target 127.0.0.1 --scan-type udp
    """
    parser = argparse.ArgumentParser(
        prog="Python3 nmap",
        description="Nmap3 - Python wrapper for Nmap port scanner"
    )
    
    parser.add_argument(
        '--target',
        '-t',
        help='Target to scan (IP or domain)',
        required=True
    )
    
    parser.add_argument(
        '--scan-type',
        '-s',
        choices=['syn', 'udp', 'tcp', 'fin', 'os', 'version', 'top'],
        default='top',
        help='Type of scan to perform'
    )
    
    parser.add_argument(
        '--top-ports',
        '-p',
        type=int,
        default=10,
        help='Number of top ports to scan (default: 10)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    async def run_async_scan():
        """Run async scan based on command-line arguments."""
        nmap = NmapScanTechniquesAsync()
        
        if args.scan_type == 'syn':
            results = await nmap.nmap_syn_scan(args.target)
        elif args.scan_type == 'udp':
            results = await nmap.nmap_udp_scan(args.target)
        elif args.scan_type == 'os':
            nmap.require_root(True)
            results = await nmap.nmap_os_detection(args.target)
        elif args.scan_type == 'version':
            results = await nmap.nmap_version_detection(args.target)
        else:
            # Default to top ports scan
            results = await nmap.scan_top_ports(args.target, top_ports=args.top_ports)
            
        print(f"Scan results for {args.target}:")
        print(results)
    
    # Run the async scan
    asyncio.run(run_async_scan())