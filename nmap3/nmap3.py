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
from utils import (get_nmap_path
)

__author__ = 'Wangolo Joel (info@nmapper.com)'
__version__ = '0.1.1'
__last_modification__ = '2019/11/22'


class Nmap(object):
    """
    This nmap class allows us to use the nmap port scanner tool from within python
    by calling nmap3.Nmap()
    """
    def __init__(self, path=None):
        """
        Module initialization
        
        :param path: Path where nmap is installed on a user system. On linux system it's typically on /usr/bin/nmap.
        """
        
        self.nmaptool = path if path else get_nmap_path()
        

if __name__=="__main__":
    nmap = Nmap()
    print(nmap.nmaptool)
