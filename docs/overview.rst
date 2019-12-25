
Overview
========
* `https://www.nmmapper.com <https://www.nmmapper.com>`_

Repository and source code
==========================
* `https://github.com/wangoloj/python3-nmap <https://github.com/wangoloj/python3-nmap>`_

Rationale
=========
There is python-nmap projects out there hosted on bitbucket, which is the basic of our `online port scanner <https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/>`_ at `Nmmapper <https://www.nmmapper.com>`_ But we wanted to extend our `online port scanner <https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/>`_  with nmap features like running nmap scripts online. The existing projects does it very well, in fact we used the existing python-nmap project to run nmap's dns-brute script on our `subdomain finder tool <https://www.nmmapper.com/sys/tools/subdomainfinder/>`_
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


==================
Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
