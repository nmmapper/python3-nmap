# python3-nmap
A python 3  library which helps in using nmap port scanner. The way this tools works is by defining each nmap command into a python function making it very easy to use sophiscated nmap commands in other python scripts.
For examle in nmap if you want to scan for common ports you would to something like this
```sh
$ nmap nmmapper.com --top-ports 10
```
But in this python3 script you would do something like this
```py
import nmap3
results = nmap3.scan_top_ports("nmmapper.com")
# And you would get your results in json
```

Again in nmap if you want to use the famous dns-brute script you would do something like this
```sh
$ nmap nmmapper.com  --script dns-brute.nse
```
But in this python3 script again it's very easy you just do something like this
```py
import nmap3
results = nmap3.nmap_dns_brute_script("nmmapper.com")
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
```
$ pip3 install -r requirements.txt
```
