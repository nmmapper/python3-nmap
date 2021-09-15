

# python3-nmap

A python 3  library which helps in using nmap port scanner. The way this tools works is by defining each nmap command into a python function making it very easy to use sophisticated nmap commands in other python scripts. Nmap is a complicated piece of software used for reconnaissance on target networks, over the years new features have been added making it more sophisticated.

With this python3-nmap we make using nmap in python very easy and painless

For example in nmap if you want to scan for common ports you would to something like this
```sh
$ nmap your-host.com --top-ports 10
```
But in this python3-nmap  script you would do something like this
```py
import nmap3
nmap = nmap3.Nmap()
results = nmap.scan_top_ports("your-host.com")
# And you would get your results in json
```
You will notice each nmap command is defined as a python function/method. this make it easy to remember this in python and easily use them.

Again in nmap if you want to use the famous dns-brute script you would do something like this
```sh
$ nmap your-host.com  --script dns-brute.nse
```
But in this python3 script again it's very easy you just do something like this
```py
import nmap3
nmap = nmap3.Nmap()
results = nmap.nmap_dns_brute_script("your-host.com")

# And you would get your results in json
[
    {
        "address": "mail.your-host.com",
        "hostname": "68.65.122.10"
    },
    {
        "address": "www.your-host.com",
        "hostname": "5.189.129.43"
    }
]
```

#### How to use python3-nmap
Using this scripts is very easy, though it assumes you have nmap already installed, as it is the primary dependence required. Also this tools supports both windows and linux, it's cross platform so to say.

**Installation**
```sh
$ git clone https://github.com/wangoloj/python3-nmap.git

$ pip3 install -r requirements.txt

# Install nmap online

$ apt-get install nmap

# That's all is needed to get started
```
In nmap some commands require root privileges for example the command to identify OS requires root privileges;
```sh
$ nmap -O your-host.com

TCP/IP fingerprinting (for OS scan) requires root privileges.
QUITTING!
# Until you sudo

$ sudo nmap -O your-host.com

```
The same applies to the script to be able to run the os identifier  you have to be a super user.

### How to use the script to identify OS
```py
import nmap3
nmap = nmap3.Nmap()
os_results = nmap.nmap_os_detection("192.168.178.2") # MOST BE ROOT
```
```json
[
    {
        "accuracy": "100",
        "cpe": "cpe:/o:linux:linux_kernel:2.6",
        "line": "45249",
        "name": "Linux 2.6.14 - 2.6.34",
        "osclass": {
            "accuracy": "100",
            "osfamily": "Linux",
            "osgen": "2.6.X",
            "type": "general purpose",
            "vendor": "Linux"
        }
    },
    {
        "accuracy": "100",
        "cpe": "cpe:/o:linux:linux_kernel:2.6.17",
        "line": "45775",
        "name": "Linux 2.6.17",
        "osclass": {
            "accuracy": "100",
            "osfamily": "Linux",
            "osgen": "2.6.X",
            "type": "general purpose",
            "vendor": "Linux"
        }
    },
    {
        "accuracy": "100",
        "cpe": "cpe:/o:linux:linux_kernel:2.6.17",
        "line": "45811",
        "name": "Linux 2.6.17 (Mandriva)",
        "osclass": {
            "accuracy": "100",
            "osfamily": "Linux",
            "osgen": "2.6.X",
            "type": "general purpose",
            "vendor": "Linux"
        }
    },
    {
        "accuracy": "100",
        "cpe": "cpe:/o:linux:linux_kernel:3.13",
        "line": "60884",
        "name": "Linux 3.13",
        "osclass": {
            "accuracy": "100",
            "osfamily": "Linux",
            "osgen": "3.X",
            "type": "general purpose",
            "vendor": "Linux"
        }
    }
]
```

### Class components of python3-nmap
The script is made of up the following classes, each holding different nmap abilities and scan types.

 - Nmap
 - NmapHostDiscovery
 - NmapScanTechniques

### Identifying service version
In nmap if you want to identify versions you would run this kind of command
```sh
$ nmap 192.168.178.1  -sV
```
In this python script you would do something like this
```py
import nmap3
nmap = nmap3.Nmap()
version_result = nmap.nmap_version_detection("your-host.com")
```
```json
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
```
### Nmap commands available
The following nmaps commands have been added to the following scripts

 - get Nmap version details
   ```python
   import nmap3
   nmap = nmap3.Nmap()
   results = nmap.nmap_version()
   ```
 - Nmap top port scan
   ```python
   import nmap3
   nmap = nmap3.Nmap()
   results = nmap.scan_top_ports("your-host")
   ```
 - Nmap Dns-brute-script( to get subdomains )
 ```python
    import nmap3
    nmap = nmap3.Nmap()
    results = nmap.nmap_dns_brute_script("domain")
  ```
 - Nmap list scan
 ```python
    import nmap3
    nmap = nmap3.Nmap()
    results = nmap.nmap_list_scan("your-host")
 ```
 - Nmap Os detection
 ```python
   import nmap3
   nmap = nmap3.Nmap()
   results = nmap.nmap_os_detection("your-host");
 ```
 - Nmap subnet scan
 ```python
    import nmap3
    nmap = nmap3.Nmap()
    results = nmap.nmap_subnet_scan("your-host") #Must be root
 ```
 - Nmap version detection
```python
   import nmap3
   nmap = nmap3.Nmap()
   results = nmap.nmap_version_detection("your-host") # Must be root
```

###  Nmap Scanning Techniques
The script offers nmap scan techniques also as python function/methods
 - nmap_fin_scan
   ```python
   import nmap3
   nmap = nmap3.NmapScanTechniques()
   result = nmap.nmap_fin_scan("192.168.178.1")
   ```
   
 - nmap_idle_scan
 ```python
    import nmap3
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_idle_scan("192.168.178.1")
 ```
 - nmap_ping_scan
 ```python
    import nmap3
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan("192.168.178.1")
 ```
 - nmap_syn_scan
 ```python
    import nmap3
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_syn_scan("192.168.178.1")
 ```
 - nmap_tcp_scan
 ```python
    import nmap3
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_tcp_scan("192.168.178.1")
 ```
 
- nmap_udp_scan
 ```python
    import nmap3
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_udp_scan("192.168.178.1")
 ```
### Supporting the nmap host discovery
The script also offers support for map Added Nmap Host discovery techniques still as python function/methods

 - Only port scan    (-Pn)
 - Only host discover    (-sn)
 - Arp discovery on a local network  (-PR)
 - Disable DNS resolution    (-n)

NmapHostDiscovery

 -  `def nmap_portscan_only(self, host, args=None)`
 ```python
    import nmap3
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_portscan_only("your-host")
 ```
 -  `def nmap_no_portscan(self, host, args=None):`
 ```python
    import nmap3
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan("your-host")
 ```
 -  `def nmap_arp_discovery(self, host, args=None):`
  ```python
    import nmap3
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_arp_discovery("your-host")
 ```
 -  `def nmap_disable_dns(self, host, args=None):`
  ```python
    import nmap3
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_disable_dns("your-host")
 ```

Nmap is a large tool, as you can see python3-nmap provides only things what you could say commonly used nmap features.

### Using custom nmap command line arguments.
As we said, the script defines each set of nmap command as python function/methods. You can also pass arguments to those methods/function thus extending your capabilities for example.
Let's say we want to scan top ports but also perform version detection .

```python
   import nmap3
   nmap = nmap3.Nmap()
   results = nmap.scan_top_ports("host", args="-sV")
```

### Using the nmap vulners script to identify vulnerabilities (CVE's)
You scan the the target IP using version detection ('-sV') to get the service and, the script performs a lookup in the CVE database. The nmap vulners script is part of the default Nmap installation, so you shouldn't need to install any other packages.  

```python
   import nmap3
   nmap = nmap3.Nmap()
   ressults = nmap_version_detection("host", args="--script vulners --script-args mincvss+5.0")
```

## Cross-Selling
* [Ethical-tools](https://ethicaltools.gitbook.io/subdomainfinder/)
* [Wappalyzer online](https://www.nmmapper.com/st/cms-detection/wappalyzer-online/)
* [Whatweb online](https://www.nmmapper.com/tools/cms-detection/whatweb-online/WhatWeb/)
* [Raccoon By Offensive security](https://www.nmmapper.com/tools/reconnaissance-tools/raccoon-vulnerability-scanning/Raccoon%20tool/)
* [Detect WAF](https://www.nmmapper.com/tools/reconnaissance-tools/waf/web-application-firewall-detector/)
* [Dnsdumpster](https://dnsdumpster.readthedocs.io/)
* [Become a patreon](https://www.patreon.com/nmmapper)
* [Online port scanner](https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/)
