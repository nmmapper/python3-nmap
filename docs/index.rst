.. python3-nmap documentation master file, created by
   sphinx-quickstart on Thu Dec  5 12:49:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python3-nmap's documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Home page
=========
* `https://www.nmmapper.com <https://www.nmmapper.com>`_


Rationale
=========
There is python-nmap projects out there hosted on bitbucket, which is the basic of our `online port scanner <https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/>`_ at Nmmapper  But we wanted to extend our online port scanner   with nmap features like running nmap scripts online. The existing projects does it very well, in fact we used the existing python-nmap project to run nmap's dns-brute script on our `subdomain finder tool <https://www.nmmapper.com/sys/tools/subdomainfinder/>`_
. 

But we wanted something that defines each nmap command and  each nmap script as a python3 function that we can call like calling python3 function. for example

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.Nmap()
    
    result = nmap.nmap_version_detection("nmmapper.com")

    # This is equivalent to nmap's
    # nmap  nmmapper.com  -sV
    # Except we add 'oX' to be /usr/bin/nmap  -oX  -  nmmapper.com  -sV
    # 
    # result Output 
    [
    {
        "cpe": [
            {
                "cpe": "cpe:/o:linux:linux_kernel"
            }
        ],
        "port": "80",
        "protocol": "tcp",
        "service": {
            "conf": "10",
            "extrainfo": "Ubuntu",
            "method": "probed",
            "name": "http",
            "ostype": "Linux",
            "product": "nginx",
            "version": "1.14.0"
        }
    },
    {
        "cpe": [
            {
                "cpe": "cpe:/o:linux:linux_kernel"
            }
        ],
        "port": "443",
        "protocol": "tcp",
        "service": {
            "conf": "10",
            "extrainfo": "Ubuntu",
            "method": "probed",
            "name": "http",
            "ostype": "Linux",
            "product": "nginx",
            "tunnel": "ssl",
            "version": "1.14.0"
        }
    },
    {
        "cpe": [
            {
                "cpe": "cpe:/o:linux:linux_kernel"
            }
        ],
        "port": "2000",
        "protocol": "tcp",
        "service": {
            "conf": "10",
            "extrainfo": "Ubuntu Linux; protocol 2.0",
            "method": "probed",
            "name": "ssh",
            "ostype": "Linux",
            "product": "OpenSSH",
            "version": "7.6p1 Ubuntu 4ubuntu0.3"
        }
    }
    ]

This python3 program defines each `Nmap command <https://www.nmmapper.com/commands/nmap-commands/latest-nmap-7-commands/run-online/>`_
 as a python3 method that can be called independently, this makes using nmap in python very easy. Right now the script is not yet complete, because we are still adding more nmap args and commands inside this script, but we are already using this script at `Nmmapper's <https://www.nmmapper.com/>`_
 `online port scanner <https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/>`_

The following are some of the added commands from nmap and how to use them. In this script.

 * Nmap top port scan
 * Nmap dns-brute-script( to find subdomains and more )
 * Nmap List scan
 * Nmap os detection
 * Nmap Subnet scan
 * Nmap version detection

Contents
========

.. toctree::
   :maxdepth: 2

   overview
   installation
   howto
   nmap
   advanced



Other reading
=============
* `Dnsdumpster <https://github.com/wangoloj/dnsdumpster>`_
* `Spy-Subdomain-Finder <https://github.com/wangoloj/spyse-subdomain-finder>`_
* `Censys-Subdomain Finder None Api <https://github.com/wangoloj/censys-subdomain-finder-non-api>`_
* `Ethicaltools <https://ethicaltools.gitbook.io/subdomainfinder/>`_
* `theHarvester online <https://www.nmmapper.com/kalitools/theharvester/email-harvester-tool/online/>`_
* `Wappalyzer online <https://www.nmmapper.com/st/cms-detection/wappalyzer-online/>`_
* `Whatweb online <https://www.nmmapper.com/tools/cms-detection/whatweb-online/WhatWeb/>`_


Nmap Scanning Techniques
========================
**TCP SYN Scan (-sS)**

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.NmapScanTechniques()
    
    results = nmap.nmap_syn_scan()
    
    [
    {
        "port": "53",
        "protocol": "tcp",
        "reason": "syn-ack",
        "reason_ttl": "64",
        "service": {
            "conf": "3",
            "method": "table",
            "name": "domain"
        },
        "state": "open"
    },
    {
        "port": "80",
        "protocol": "tcp",
        "reason": "syn-ack",
        "reason_ttl": "64",
        "service": {
            "conf": "3",
            "method": "table",
            "name": "http"
        },
        "state": "open"
    }
   ]


**TCP connect() scan (-sT)**

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan()

**FIN Scan (-sF)**

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_fin_scan()

**Ping Scan (-sP)**

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_ping_scan()

**Idle Scan (-sI))**

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_idle_scan()

Nmap is a large tool, as you can see python3-nmap provides only things what you could say commonly used nmap features.

**NmapHostDiscovery**

***def nmap_portscan_only(self, host, args=None)***

.. code-block:: python
    import nmap3
    nmap = nmapp.NmapHostDiscovery()
    results = nmap.nmap_portscan_only("your-host")
 
**def nmap_no_portscan(self, host, args=None):**

.. code-block:: python
    :linenos:

    import nmap3
    nmap = nmapp.NmapHostDiscovery()
    results = nmap.nmap_no_portscan("your-host")


**def nmap_arp_discovery(self, host, args=None):**

.. code-block:: python
    :linenos:

    import nmap3
    nmap = nmapp.NmapHostDiscovery()
    results = nmap.nmap_arp_discovery("your-host")


**def nmap_disable_dns(self, host, args=None):**

.. code-block:: python
    :linenos:

    import nmap3
    nmap = nmapp.NmapHostDiscovery()
    results = nmap.nmap_disable_dns("your-host")
 
**Using custom nmap command line arguments.**

As we said, the script defines each set of nmap command as python function/methods. You can also pass arguments to those methods/function thus extending your capabilities for example.Let's say we want to scan top ports but also perform version detection .

.. code-block:: python
   :linenos:

    import nmap3
    nmap = nmap3.Namp()
    results = nmap3.scan_top_ports("host", args="-sV")


**Cross Reading**
 `Wappalyzer online <https://www.nmmapper.com/st/cms-detection/wappalyzer-online/>`_

 `Whatweb online <https://www.nmmapper.com/tools/cms-detection/whatweb-online/WhatWeb/>`_ 

 `Cmseek online <https://www.nmmapper.com/tools/reconnaissance-tools/cmseek-scanning/CMS%20Detection%20and%20Exploitation%20suite/>`_

 `theHarvester online <https://www.nmmapper.com/kalitools/theharvester/email-harvester-tool/online/>`_

 `Become a patreon <https://www.patreon.com/nmmapper>`_

==================
Indices and tables
==================

* :ref:`genindex`
* :ref:`search`




