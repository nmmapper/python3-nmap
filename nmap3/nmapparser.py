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
from .utils import (get_nmap_path
)

class NmapCommandParser(object):
    """
    Object for parsing the xml results
    
    Each function below will correspond to the parse
    for each nmap command or option.
    """
    def __init__(self, xml_et):
        self.xml_et = xml_et
        self.xml_root = None
        
    def parse_nmap_listscan(self, xml_root):
        """
        Performs parsin for nmap listscan xml rests
        @ return DICT
        """
        host_list = []
        try:
            
            if not xml_root:
                return host_list
            self.xml_root == xml_root
            
            hosts = xml_root.findall("host")
            for host in hosts:
                attrib = dict()
                
                if(host.find("status") != None):
                    attrib = host.find("status").attrib
          
                if(host.find("address") != None):
                    for attr in host.find("address").attrib:
                        attrib[attr]=host.find("address").attrib.get(attr)
                        
                host_list.append(attrib)
            return host_list
            
        except Exception:
            return host_list
            
    def parse_nmap_subnetscan(self, xml_root):
        """
        Performs parsin for nmap listscan xml rests
        @ return DICT
        """
        host_list = []
        try:
            
            if not xml_root:
                return host_list
            self.xml_root == xml_root
            
            hosts = xml_root.findall("host")
            
            for host in hosts:
                attrib = host.find("address").attrib
                ports = []
                
                if(host.find("hostnames")):
                    for hn in host.find("hostnames").findall("hostname"):
                        attrib["hostname"]=hn.attrib.get("name")
                        attrib["ptr"]=hn.attrib.get("type")
                
                if host.find("ports"):
                    for port in host.find("ports").findall("port"):
                        port_attrib = port.attrib
                        ports.append(
                            {"port":port_attrib.get("portid"), "protocol":port_attrib.get("protocol"),
                            "state":port.find("state").attrib.get("state")
                            }
                        )
                        
                attrib["ports"]=ports
                
                host_list.append(attrib)
            return host_list
            
        except Exception as e:
            raise 
            return host_list
        
    def parse_nmap_pingscan(self, xml_root):
        """
        Performs parsing for nmap pingscan xml rests
        @ return DICT
        """
        ping_status = dict()
        try:
            
            if not xml_root:
                return host_list
            self.xml_root == xml_root
            host = xml_root.find("host")
            
            if(host):
                ping_status = host.find('status').attrib
                address = []
                hostname = []
                
                for addr in host.findall("address"):
                    address.append(addr.attrib)
                ping_status["addresses"]=address
                
                if(host.find("hostnames")):
                    for host_n in host.find("hostnames").findall("hostname"):
                        hostname.append(host_n.attrib)
                ping_status["hostname"]=hostname
                
            return ping_status
        except Exception as e:
            raise
            
    def parse_nmap_idlescan(self, xml_root):
        """
        Performs parsing for nmap idlescan xml rests
        @ return DICT
        """
        idle_scan = dict()
        try:
            
            if not xml_root:
                return host_list
            self.xml_root == xml_root
            host = xml_root.find("host")
            
            if(host):
                address = []
                hostname = []
                ports = []
                
                for addr in host.findall("address"):
                    address.append(addr.attrib)
                idle_scan["addresses"]=address
                
                if(host.find("hostnames")):
                    for host_n in host.find("hostnames").findall("hostname"):
                        hostname.append(host_n.attrib)
                idle_scan["hostname"]=hostname
                
                port = host.find("ports")
                port_dict = dict()
                
                if(port):
                    for open_ports in port.findall("port"):
                        port_dict = open_ports.attrib
                        
                        if(open_ports.find('state')):
                            port_dict['state']=open_ports.find('state').attrib
                            
                        if(open_ports.find('service')):
                            port_dict['service']=open_ports.find('service').attrib
                            
                idle_scan["ports"]=port_dict
                
            return idle_scan
        except Exception as e:
            raise
        
