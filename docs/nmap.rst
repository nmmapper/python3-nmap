
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

   $ nmap 
