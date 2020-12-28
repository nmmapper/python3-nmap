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
                port_result_dict[address]={} # A little trick to avoid errors
                
                port_result_dict[address]["osmatch"]=self.parse_os(hosts)
                port_result_dict[address]["ports"] = self.parse_ports(hosts)
                port_result_dict[address]["hostname"] = self.parse_hostnames(hosts)
                port_result_dict[address]["macaddress"] = self.parse_mac_address(hosts)
                port_result_dict[address]["state"] = self.get_hostname_state(hosts)
                
            port_result_dict["stats"]=stats
            port_result_dict["runtime"]=self.parse_runtime(xmlroot)
            
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
            os_dict = {}
            hosts = xmlroot.findall("host")
            stats = xmlroot.attrib
            
            for host in hosts:
                address = host.find("address").get("addr")
                os_dict[address]={}
                
                os_dict[address]["osmatch"]=self.parse_os(host)
                os_dict[address]["ports"] = self.parse_ports(host)
                os_dict[address]["hostname"] = self.parse_hostnames(host)
                os_dict[address]["macaddress"] = self.parse_mac_address(host)
            
            os_dict["runtime"]=self.parse_runtime(xmlroot)
            os_dict["stats"]=stats
            return os_dict
            
        except Exception as e:
            raise(e)
        else:
            return os_identified
    
    def parse_os(self, os_results):
        """
        parses os results
        """
        os = os_results.find("os")
        os_list = []
        
        if os is not None:
            for match in os.findall("osmatch"):
                attrib = match.attrib

                for osclass in match.findall("osclass"):
                    attrib["osclass"]=osclass.attrib

                    for cpe in osclass.findall("cpe"):
                        attrib["cpe"]=cpe.text
                os_list.append(attrib)
            return os_list
        else:
            return {}
            
    def parse_ports(self, xml_hosts):
        """
        Parse parts from xml
        """
        open_ports_list = []
        
        for port in xml_hosts.findall("ports/port"):
            open_ports = {}            
            for key in port.attrib:
                open_ports[key]=port.attrib.get(key)
                
            if(port.find('state') is not None):
                for key in port.find('state').attrib:
                    open_ports[key]=port.find("state").attrib.get(key)
           
            if(port.find('service') is not None):
                open_ports["service"]=port.find("service").attrib
                
                for cp in port.find("service").findall("cpe"):
                    cpe_list = []
                    cpe_list.append({"cpe": cp.text})
                    open_ports["cpe"] = cpe_list
            
            # Script
            open_ports["scripts"]=self.parse_scripts(port.findall('script')) if port.findall('script') is not None else []
            open_ports_list.append(open_ports)
            
        return open_ports_list
                    
    def parse_runtime(self, xml):
        """
        Parse parts from xml
        """
        runstats = xml.find("runstats")
        runtime = {}
        
        if runstats is not None:
            if runstats.find("finished") is not None:
                return runstats.find("finished").attrib
    
    def parse_mac_address(self, xml):
        """
        Parse parts from xml
        """
        addresses = xml.findall("address")
        
        for addr in addresses:
            if(addr.attrib.get("addrtype") == "mac"):
                return addr.attrib
    
    def parse_hostnames(self, host):
        """
        Parse parts from xml
        """
        hostnames = host.findall("hostnames/hostname")
        hostnames_list = []
        
        for host in hostnames:
            hostnames_list.append(host.attrib)
        return hostnames_list
    
    def get_hostname_state(self, xml):
        """
        Parse parts from xml
        """
        state = xml.find("status")
        if(state is not None):
            return state.attrib
    
    def parse_scripts(self, scripts_xml):
        scripts = []

        for script_xml in scripts_xml:
            script_name = script_xml.attrib.get('id')
            raw_output = script_xml.attrib.get('output')

            data = self.convert_xml_elements(script_xml)
            if script_xml.findall('table') is not None:
                tables = script_xml.findall('table')
                child_data = self.convert_xml_tables(tables)
                for k in child_data:
                    if {} != k:
                        data[k] = child_data[k]

            scripts.append({
                'name': script_name,
                'raw': raw_output,
                'data': data
            })

        return scripts

    def convert_xml_tables(self, xml_tables):
        data = {}
        for xml_table in xml_tables:
            key = xml_table.attrib.get('key')
            child_data = self.convert_xml_elements(xml_table)
            if key is None:
                if {} != child_data:
                    a = data.get('children', [])
                    data['children'] = a + [child_data]
            else:
                if xml_table.findall('table') is not None:
                    data[key] = self.convert_xml_tables(xml_table.findall('table'))
                if {} != child_data:
                    a = data.get(key, {})
                    b = a.get('children', [])
                    a['children'] = b + [child_data]

        return data

    def convert_xml_elements(self, xml_obj):
        elements = {}
        elem_counter = 0
        for elem in xml_obj.findall('elem'):
            if None == elem.attrib.get('key'):
                elements[elem_counter] = elem.text
            else:
                elements[elem.attrib.get('key')] = elem.text
            elem_counter += 1
        return elements
