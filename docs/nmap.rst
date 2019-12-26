
Nmap
====

Nmap or Network Mapper is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping).
Nmap's power can be summarized as follows;

 * Flexible
 * Powerful
 * Portable
 * Easy
 * Free
 * Well Documented
 * Supported
 * Acclaimed
 * Popular

Sample nmap command

.. code-block:: bash
   :linenos:
   
   $ nmap -A -T4 scanme.nmap.org

Nmap option summary
-------------------
If you want to get a summary of nmap's command just run nmap without any command like this;

.. code-block:: bash
   :linenos:
   
   $ nmap 

What come after that command is run is the option summary

Nmap Host discovery
-------------------
One of the very first steps in any network reconnaissance mission is to reduce a (sometimes huge) set of IP ranges into a list of active or interesting hosts. Scanning every port of every single IP address is slow and usually unnecessary. Of course what makes a host interesting depends greatly on the scan purposes. Network administrators may only be interested in hosts running a certain service, while security auditors may care about every single device with an IP address. An administrator may be comfortable using just an ICMP ping to locate hosts on his internal network, while an external penetration tester may use a diverse set of dozens of probes in an attempt to evade firewall restrictions

.. code-block:: bash
   :linenos:
   
   $ nmap  -sL # (List Scan) 

   $ nmap  -sn # (No port scan) 

   $ nmap  -Pn # (No ping) 
  
   $ nmap  -PS <port list> # (TCP SYN Ping) 
   
   $ nmap -PA <port list> # (TCP ACK Ping) 

   $ nmap  -PU <port list> # (UDP Ping) 

   $ nmap  -PY <port list> # (SCTP INIT Ping) 

   $ nmap  -PE; -PP; -PM # (ICMP Ping Types) 

   $ nmap  -PO <protocol list> # (IP Protocol Ping) 

   $ nmap  --disable-arp-ping # (No ARP or ND Ping) 

   $ nmap  --traceroute # (Trace path to host) 

   $ nmap  -n # (No DNS resolution) 

   $ nmap  -R # (DNS resolution for all targets) 

   $ nmap  --resolve-all # (Scan each resolved address) 

   $ nmap  --system-dns # (Use system DNS resolver) 

   $ nmap  --dns-servers <server1>[,<server2>[,...]] # (Servers to use for reverse DNS queries) 


Nmap Port Scanning Basics
-------------------------
While Nmap has grown in functionality over the years, it began as an efficient port scanner, and that remains its core function. The simple command nmap <target> scans 1,000 TCP ports on the host <target>. While many port scanners have traditionally lumped all ports into the open or closed states, Nmap is much more granular. It divides ports into six states: open, closed, filtered, unfiltered, open|filtered, or closed|filtered.

These states are not intrinsic properties of the port itself, but describe how Nmap sees them. For example, an Nmap scan from the same network as the target may show port 135/tcp as open, while a scan at the same time with the same options from across the Internet might show that port as filtered

**Six port states recognized by Nmap**

* **open** 

  An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port. Finding these is often the primary goal of port scanning. Security-minded people know that each open port is an avenue for attack. Attackers and pen-testers want to exploit the open ports, while administrators try to close or protect them with firewalls without thwarting legitimate users. Open ports are also interesting for non-security scans because they show services available for use on the network.

* **closed**

    A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. They can be helpful in showing that a host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next. 

* **filtered**

    Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software. These ports frustrate attackers because they provide so little information. Sometimes they respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes without responding are far more common. This forces Nmap to retry several times just in case the probe was dropped due to network congestion rather than filtering. This slows down the scan dramatically.

* **unfiltered**

    The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open

* **open|filtered**

    Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.

* **closed|filtered**

    This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.

.. code-block:: bash
   :linenos:

   Not shown: 995 filtered ports
   PORT     STATE  SERVICE
   80/tcp   open   http
   113/tcp  closed ident
   443/tcp  open   https
   8080/tcp open   http-proxy
   8443/tcp open   https-alt

   Nmap done: 1 IP address (1 host up) scanned in 18.57 seconds
   # Notice the STATE
