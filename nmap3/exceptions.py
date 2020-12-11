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
import shlex
import subprocess
import sys
import re

__author__ = 'Wangolo Joel (inquiry@nmapper.com)'
__version__ = '1.4.9'
__last_modification__ = '2029/12/11'

class NmapNotInstalledError(Exception):
    """Exception raised when nmap is not installed"""
    
    def __init__(self, message="Nmap is either not installed or we couldn't locate nmap path Please ensure nmap is installed"):
        self.message = message 
        super().__init__(message)
        
class NmapXMLParserError(Exception):
    """Exception raised when we can't parse the output"""
    
    def __init__(self, message="Unable to parse xml output"):
        self.message = message 
        super().__init__(message)

class NmapExecutionError(Exception):
    """Exception raised when en error occurred during nmap call"""

