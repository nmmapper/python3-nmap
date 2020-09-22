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

                if host.find("status") is not None:
                    attrib = host.find("status").attrib

                if host.find("address") is not None:
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
                
                if host.find("hostnames") is not None:
                    for hn in host.find("hostnames").findall("hostname"):
                        attrib["hostname"]=hn.attrib.get("name")
                        attrib["ptr"]=hn.attrib.get("type")
                
                if host.find("ports") is not None:
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
        ping_status_list = []
        try:
            
            if not xml_root:
                return host_list
            self.xml_root == xml_root
            
            for host in xml_root.findall("host"):
                host_ping_status = dict()
                if(host):
                    host_ping_status = host.find('status').attrib
                    address = []
                    hostname = []
                    
                    for addr in host.findall("address"):
                        address.append(addr.attrib)
                    host_ping_status["addresses"]=address
                    
                    if host.find("hostnames") is not None:
                        for host_n in host.find("hostnames").findall("hostname"):
                            hostname.append(host_n.attrib)
                    host_ping_status["hostname"]=hostname
                ping_status_list.append(host_ping_status)
            return ping_status_list
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
            
            if host is not None:
                address = []
                hostname = []
                ports = []
                
                for addr in host.findall("address"):
                    address.append(addr.attrib)
                idle_scan["addresses"]=address
                
                if host.find("hostnames") is not None:
                    for host_n in host.find("hostnames").findall("hostname"):
                        hostname.append(host_n.attrib)
                idle_scan["hostname"]=hostname
                
                port = host.find("ports")
                port_dict = dict()
                
                if port is not None:
                    for open_ports in port.findall("port"):
                        port_dict = open_ports.attrib
                        
                        if open_ports.find('state') is not None:
                            port_dict['state']=open_ports.find('state').attrib
                            
                        if open_ports.find('service') is not None:
                            port_dict['service']=open_ports.find('service').attrib
                            
                idle_scan["ports"]=port_dict
                
            return idle_scan
        except Exception as e:
            raise
        
    def filter_subdomains(self, xmlroot):
        """
        Given the xmlroot return the all the ports that are open from 
        that tree
        """
        try:
            subdomains_list = []
            
            scanned_host = xmlroot.find("host")
            if scanned_host is not None:
                hostscript = scanned_host.find("hostscript")
                
                script = None
                first_table = None
                final_result_table = None
                
                if hostscript is not None:
                    script = hostscript.find("script")
                    
                if hostscript is not None:
                    first_table = script.find("table")
                    
                if first_table is not None:
                    final_result_table = first_table.findall("table")
                
                if final_result_table is not None:
                    for table in final_result_table:
                        script_results = dict()
                        elem = table.findall("elem")
                        
                        if(len(elem) >= 2):
                            script_results[elem[0].attrib["key"]] = elem[0].text
                            script_results[elem[1].attrib["key"]] = elem[1].text
                            subdomains_list.append(script_results)

        except Exception as e:
            raise(e)
        else:
            return subdomains_list
            
    def parse_noportscan(self, xmlroot):
        """
        Given the xmlroot return the all the ports that are open from 
        that tree
        """
        
        result_dicts = {}
        hosts_list=[]
        
        # Find all hosts 
        all_hosts = xmlroot.findall("host")
        for host in all_hosts:
            
            host_record = {}
            if host.find("status") is not None:
                for key in host.find("status").attrib:
                    host_record[key]=host.find("status").attrib.get(key)
                
                for key in host.find("address").attrib:
                    host_record[key]=host.find("address").attrib.get(key)
                    
            hosts_list.append(host_record)
                
        runstats = xmlroot.find("runstats")
        if runstats is not None:
            
            if runstats.find("finished") is not None:
                result_dicts["runtime"]=runstats.find("finished").attrib
                result_dicts["status"]=runstats.find("hosts").attrib
        
        result_dicts["hosts"]=hosts_list
        return result_dicts 
    
    def filter_top_ports(self, xmlroot):
        """
        Given the xmlroot return the all the ports that are open from
        that tree
        """
        try:
            port_result_dict = {}
            
            scanned_host = xmlroot.findall("host")
            stats = xmlroot.attrib
            
            for hosts in scanned_host:
                address = hosts.find("address").get("addr")
                
                ports = hosts.find("ports").findall("port")
                port_results =[]
                
                for port in ports:
                    open_ports = {}
                    open_ports["host"]=address
                    for key in port.attrib:
                        open_ports[key]=port.attrib.get(key)
                        
                    if port.find('state') is not None:
                        for key in port.find('state').attrib:
                            open_ports[key]=port.find("state").attrib.get(key)

                    if  port.find("service") is not None:
                        open_ports["service"]=port.find("service").attrib

                    port_results.append(open_ports)
                port_result_dict[address]=port_results
                
                if hosts.find("os") is not None: # Checks if we have os may have been passed as args
                    port_result_dict["os"]=self.os_identifier_parser(xmlroot)
                    
            runstats = xmlroot.find("runstats")
            if runstats is not None:
                if runstats.find("finished") is not None:
                    port_result_dict["runtime"]=runstats.find("finished").attrib
            port_result_dict["stats"]=stats
            
        except Exception as e:
            raise(e)
        else:
            return port_result_dict
    
    def filter_stealth_scan(self, xmlroot):
        """
        Parses the results from a stealth scan
        """
        try:
            port_result_dict = {}
            
            scanned_host = xmlroot.findall("host")
            stats = xmlroot.attrib
            
            for hosts in scanned_host:
                address = hosts.find("address").get("addr")
                
                ports = hosts.find("ports").findall("extraports")
                port_results =[]
                
                for port in ports:
                    open_ports = {}
                    open_ports["host"]=address
                    for key in port.attrib:
                        open_ports[key]=port.attrib.get(key)
                    
                    if port.find("extrareasons") is not None:
                        for extra in port.findall("extrareasons"):
                            open_ports["extrareasons"]=extra.attrib 
                            
                    port_results.append(open_ports)
                port_result_dict[address]=port_results
                
                if hosts.find("os") is not None: # Checks if we have os may have been passed as args
                    port_result_dict["os"]=self.os_identifier_parser(xmlroot)
                    
            runstats = xmlroot.find("runstats")
            if runstats is not None:
                if runstats.find("finished") is not None:
                    port_result_dict["runtime"]=runstats.find("finished").attrib
            port_result_dict["stats"]=stats
            
        except Exception as e:
            raise(e)
        else:
            return port_result_dict
    
    def version_parser(self, xmlroot):
        """
        Parse version detected
        """
        try:
            service_version = []
            service_version_dict = dict()
            scanned_host = xmlroot.findall("host")
            stats = xmlroot.attrib
            
            for hosts in scanned_host:
                address = hosts.find("address").get("addr")
                ports = hosts.find("ports").findall("port")
                if hosts is not None:
                    ports = hosts.find("ports")
                    port_service = None
                    
                    if ports is not None:
                        port_service = ports.findall("port")

                    if port_service is not None:
                        services_result = []
                        for port in port_service:
                            service = {}
                            service["protocol"] = port.attrib.get("protocol")
                            service["port"] = port.attrib.get("portid")

                            if port.find("state") is not None:
                                for s in port.find("state").attrib:
                                    service[s] = port.find("state").attrib.get(s)

                            if port.find("service") is not None:
                                service["service"] = port.find("service").attrib

                                for cp in port.find("service").findall("cpe"):
                                    cpe_list = []
                                    cpe_list.append({"cpe": cp.text})
                                    service["cpe"] = cpe_list
                            services_result.append(service)

                    service_version_dict[address] = services_result
            return service_version_dict
        except Exception as e:
            raise(e)
        else:
            return port_result_dict
    
    def os_identifier_parser(self, xmlroot):
        """
        Parser for identified os
        """
        try:
            os_identified = []

            host = xmlroot.find("host")
            if host is not None:
                os = host.find("os")

                if os is not None:
                    for match in os.findall("osmatch"):
                        attrib = match.attrib

                        for osclass in match.findall("osclass"):
                            attrib["osclass"]=osclass.attrib

                            for cpe in osclass.findall("cpe"):
                                attrib["cpe"]=cpe.text
                        os_identified.append(attrib)
        except Exception as e:
            raise(e)
        else:
            return os_identified
    
