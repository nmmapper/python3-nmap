
# python3-nmap
A python 3  library which helps in using nmap port scanner. The way this tools works is by defining each nmap command into a python function making it very easy to use sophisticated nmap commands in other python scripts.
For example in nmap if you want to scan for common ports you would to something like this
```sh
$ nmap nmmapper.com --top-ports 10
```
But in this python3 script you would do something like this
```py
import nmap3
nmap = nmap3.Nmap()
results = nmap.scan_top_ports("nmmapper.com")
# And you would get your results in json
```

Again in nmap if you want to use the famous dns-brute script you would do something like this
```sh
$ nmap nmmapper.com  --script dns-brute.nse
```
But in this python3 script again it's very easy you just do something like this
```py
import nmap3
nmap = nmap3.Nmap()
results = nmap.nmap_dns_brute_script("nmmapper.com")

# And you would get your results in json
[
    {
        "address": "mail.nmmapper.com",
        "hostname": "68.65.122.10"
    },
    {
        "address": "www.nmmapper.com",
        "hostname": "5.189.129.43"
    }
]
```

#### Why this script?
Why the design of this tool? At [Nmmapper.com](https://www.nmmapper.com) we ran an [online port scanner](https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/) and we wanted a simple script that could help us extend our [online port scanner](https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/) with more options. So we decided to develop a custom python3 script which holds all the common nmap command we want to host online.

#### How to
The scripts assumes you have nmap already installed
```sh
$ pip3 install -r requirements.txt

# Install nmap online

$ apt-get install nmap

# That's all is needed to get started
```
In nmap some commands require root privileges for example the command to identify OS requires root privileges;
```sh
$ nmap -O nmmapper.com

TCP/IP fingerprinting (for OS scan) requires root privileges.
QUITTING!
# Until you sudo

$ sudo nmap -O nmmapper.com

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

### Identifying service version
In nmap if you want to identify versions you would run this kind of command
```sh
$ nmap 192.168.178.1  -sV
```
In this python script you would do something like this
```py
import nmap3
nmap = nmap3.Nmap()
version_result = nmap.nmap_version_detection("nmmapper.com")
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

 - Nmap top port scan
 - Nmap Dns-brute-script( to get subdomains )
 - Nmap list scan
 - Nmap Os detection
 - Nmap subnet scan
 - Nmap version detection

### ## Nmap Scanning Techniques

 - nmap_fin_scan
   ```python
   import nmap3
   nmap = nmap3.NmapScanTechniques()
   result = nmap.nmap_fin_scan("192.168.178.1")
   ```
   
 - nmap_idle_scan
 - nmap_ping_scan
 - nmap_syn_scan
 - nmap_tcp_scan

## # Documentation

 - [Readthedocs](https://nmap.readthedocs.io/)

