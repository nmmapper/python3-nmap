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
from collections import defaultdict
import typing
from xml.etree import ElementTree as ET


class NmapCommandParser(object):
    """
    Object for parsing the xml results

    Each function below will correspond to the parse
    for each nmap command or option.
    """

    def __init__(self, xml_et: typing.Optional[ET.ElementTree]) -> None:
        self.xml_et = xml_et
        self.xml_root = None

    def filter_subdomains(
        self, xmlroot: ET.Element
    ) -> typing.List[typing.Dict[str, typing.Optional[str]]]:
        """
        Given the xmlroot return the all the ports that are open from
        that tree

        :param xmlroot: xml root element from nmap xml output
        :return: List of subdomains found
        """
        subdomains_list: typing.List[typing.Dict[str, typing.Optional[str]]] = []
        scanned_host = xmlroot.find("host")
        if scanned_host is None:
            return subdomains_list

        script = None
        first_table = None
        final_result_table = None
        hostscript = scanned_host.find("hostscript")

        if hostscript is None:
            return subdomains_list

        script = hostscript.find("script")
        if script is None:
            return subdomains_list

        first_table = script.find("table")
        if first_table is None:
            return subdomains_list

        final_result_table = first_table.findall("table")
        if final_result_table is None:
            return subdomains_list

        for table in final_result_table:
            script_results = {}
            elem = table.findall("elem")

            if len(elem) >= 2:
                script_results[elem[0].attrib["key"]] = elem[0].text
                script_results[elem[1].attrib["key"]] = elem[1].text
                subdomains_list.append(script_results)

        return subdomains_list

    def filter_top_ports(self, xmlroot: ET.Element) -> typing.Dict[str, typing.Any]:
        """
        Given the xmlroot return the all the ports that are open from
        that tree

        :param xmlroot: xml root element from nmap xml output
        :return: List of open ports found
        """
        port_result_dict: typing.Dict[str, typing.Any] = defaultdict(dict)
        scanned_host = xmlroot.findall("host")
        # This ensures we have a copy of the stats and we are not holding reference
        # to the xmlroot.attrib, just in case we modify it later
        stats = dict(xmlroot.attrib)

        for hosts in scanned_host:
            address = hosts.find("address")
            if address is None:
                continue
            addr = address.get("addr")
            if addr is None:
                continue

            port_result_dict[addr]["osmatch"] = self.parse_os(hosts)
            port_result_dict[addr]["ports"] = self.parse_ports(hosts)
            port_result_dict[addr]["hostname"] = self.parse_hostnames(hosts)
            port_result_dict[addr]["macaddress"] = self.parse_mac_address(hosts)
            port_result_dict[addr]["state"] = self.get_hostname_state(hosts)

        port_result_dict["runtime"] = self.parse_runtime(xmlroot)
        port_result_dict["stats"] = stats
        port_result_dict["task_results"] = self.parse_task_results(xmlroot)
        return port_result_dict

    def os_identifier_parser(self, xmlroot: ET.Element) -> typing.Dict[str, typing.Any]:
        """
        Parser for identified os

        :param xmlroot: xml root element from nmap xml output
        :return: Dictionary of os identified
        """
        os_dict: typing.Dict[str, typing.Any] = defaultdict(dict)
        hosts = xmlroot.findall("host")
        stats = dict(xmlroot.attrib)

        for host in hosts:
            address = host.find("address")
            if address is None:
                continue
            addr = address.get("addr")
            if addr is None:
                continue

            os_dict[addr]["osmatch"] = self.parse_os(host)
            os_dict[addr]["ports"] = self.parse_ports(host)
            os_dict[addr]["hostname"] = self.parse_hostnames(host)
            os_dict[addr]["macaddress"] = self.parse_mac_address(host)

        os_dict["runtime"] = self.parse_runtime(xmlroot)
        os_dict["stats"] = stats
        os_dict["task_results"] = self.parse_task_results(xmlroot)
        return os_dict

    def parse_os(
        self, os_results: ET.Element
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Parses os results

        :param os_results: xml root element from nmap xml output
        :return: List of os identified
        """
        os = os_results.find("os")
        os_list: typing.List[typing.Dict[str, typing.Any]] = []

        if os is None:
            return os_list

        for match in os.findall("osmatch"):
            attrib: typing.Dict[str, typing.Any] = dict(match.attrib)

            for osclass in match.findall("osclass"):
                attrib["osclass"] = dict(osclass.attrib)

                for cpe in osclass.findall("cpe"):
                    attrib["cpe"] = cpe.text
            os_list.append(attrib)
        return os_list

    def parse_ports(
        self, xml_hosts: ET.Element
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Parse ports from xml

        :param xml_hosts: xml root element from nmap xml output
        :return: List of open ports found
        """
        open_ports_list = []

        for port in xml_hosts.findall("ports/port"):
            open_ports: typing.Dict[str, typing.Any] = {}
            open_ports.update(port.attrib)

            state = port.find("state")
            if state is not None:
                open_ports.update(state.attrib)

            service = port.find("service")
            if service is not None:
                open_ports["service"] = dict(service.attrib)
                cpe_list = []
                for cp in service.findall("cpe"):
                    cpe_list.append({"cpe": cp.text})
                open_ports["cpe"] = cpe_list

            # Script
            open_ports["scripts"] = (
                self.parse_scripts(port.findall("script"))
                if port.findall("script") is not None
                else []
            )
            open_ports_list.append(open_ports)

        return open_ports_list

    def parse_runtime(self, xml: ET.Element) -> typing.Optional[typing.Dict[str, str]]:
        """
        Parse runtime from xml

        :param xml: xml root element from nmap xml output
        :return: Dictionary with runtime attributes
        """
        runstats = xml.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                return dict(finished.attrib)
        return None

    def parse_task_results(self, xml: ET.Element) -> typing.List[typing.Dict[str, str]]:
        """
        Parse task results from xml

        :param xml: xml root element from nmap xml output
        :return: List of task results found
        """
        task_results = xml.findall("taskend")
        task_results_list = []

        for task_result in task_results:
            task_results_list.append(dict(task_result.attrib))
        return task_results_list

    def parse_mac_address(
        self, xml: ET.Element
    ) -> typing.Optional[typing.Dict[str, str]]:
        """
        Parse mac address from xml

        :param xml: xml root element from nmap xml output
        :return: Dictionary with mac address attributes or None if not found
        """
        addresses = xml.findall("address")

        for addr in addresses:
            if addr.attrib.get("addrtype") == "mac":
                return dict(addr.attrib)
        return None

    def parse_hostnames(self, host: ET.Element) -> typing.List[typing.Dict[str, str]]:
        """
        Parse hostnames from xml

        :param host: xml root element from nmap xml output
        :return: List of hostnames found
        """
        hostnames = host.findall("hostnames/hostname")
        hostnames_list = []

        for hostname in hostnames:
            hostnames_list.append(dict(hostname.attrib))
        return hostnames_list

    def get_hostname_state(
        self, xml: ET.Element
    ) -> typing.Optional[typing.Dict[str, str]]:
        """
        Parse hostname state from xml

        :param xml: xml root element from nmap xml output
        :return: Dictionary with hostname state attributes or None if not found
        """
        state = xml.find("status")
        if state is not None:
            return dict(state.attrib)
        return None

    def parse_scripts(
        self, scripts_xml: typing.List[ET.Element]
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Parse scripts from xml

        :param scripts_xml: List of xml elements containing script data
        :return: List of dictionaries containing script name, raw output, and data
        """
        if not scripts_xml:
            return []
        scripts = []

        for script_xml in scripts_xml:
            script_name = script_xml.attrib.get("id")
            raw_output = script_xml.attrib.get("output")

            data = self.convert_xml_elements(script_xml)
            tables = script_xml.findall("table")
            if tables is not None:
                child_data = self.convert_xml_tables(tables)
                for key, value in child_data.items():
                    if key:
                        data[key] = value

            scripts.append({"name": script_name, "raw": raw_output, "data": data})
        return scripts

    def convert_xml_tables(
        self, xml_tables: typing.List[ET.Element]
    ) -> typing.Dict[str, typing.Any]:
        """
        Convert XML tables to a dictionary format.

        :param xml_tables: List of XML table elements to convert
        :return: Dictionary representation of the XML tables
        """
        data: typing.Dict[str, typing.Any] = {}
        for xml_table in xml_tables:
            key = xml_table.attrib.get("key")
            child_data = self.convert_xml_elements(xml_table)
            if key is None:
                if child_data:
                    a = data.get("children", [])
                    data["children"] = a + [child_data]
            else:
                tables = xml_table.findall("table")
                if tables is not None:
                    data[key] = self.convert_xml_tables(tables)
                if child_data:
                    a = data.get(key, {})
                    b = a.get("children", [])
                    a["children"] = b + [child_data]
        return data

    def convert_xml_elements(
        self, xml_obj: ET.Element
    ) -> typing.Dict[str, typing.Optional[str]]:
        """
        Convert XML elements to a dictionary format.

        :param xml_obj: XML element to convert
        :return: Dictionary representation of the XML elements
        """
        elements = {}
        for counter, element in enumerate(xml_obj.findall("element")):
            key = element.attrib.get("key")
            if key is None:
                elements[str(counter)] = element.text
            else:
                elements[key] = element.text
        return elements
