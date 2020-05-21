import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python3-nmap", 
    version="1.4.7",
    author="Wangolo Joel",
    author_email="info@nmmapper.com",
    description="Python3-nmap converts Nmap commands into python3 methods making it very easy to use nmap in any of your python pentesting projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wangoloj/python3-nmap",
    project_urls={
        'Documentation': 'https://nmap.readthedocs.io/en/latest/',
        'How it is used': 'https://www.nmmapper.com/st/networkmapper/nmap/online-port-scanning/',
        'Homepage': 'https://www.nmmapper.com/',
        'Source': 'https://github.com/wangoloj/python3-nmap',
        'Subdomain finder': 'https://www.nmmapper.com/sys/tools/subdomainfinder/',
        'theHarvester online': 'https://www.nmmapper.com/kalitools/theharvester/email-harvester-tool/online/',
        'Helpdesk': 'https://www.aquariumdesk.com/',
        'Crosselling': 'https://www.byogyo.com/',
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    setup_requires=['wheel'],
    install_requires=['requests', 'sphinx', 'sphinx_rtd_theme', 'simplejson'],
)
