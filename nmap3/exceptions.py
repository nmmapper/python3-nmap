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

__author__ = "Wangolo Joel (inquiry@nmapper.com)"
__version__ = "1.9.3"
__last_modification__ = "Jun/06/2025"

import typing


class NmapError(Exception):
    """Base exception for all nmap3 exceptions"""

    def __init__(self, message: str = "An error occurred in nmap3"):
        self.message = message
        super().__init__(message)


class NmapNotInstalledError(NmapError):
    """Exception raised when nmap is not installed"""

    def __init__(self, path: typing.Optional[str] = None):
        self.message = f"Nmap is either not installed or we couldn't locate \
nmap path. Please ensure nmap is installed and provide right path string. \n\
Provided: *{path if path else 'Not provided'}*"
        super().__init__(self.message)


class NmapXMLParserError(NmapError):
    """Exception raised when we can't parse the output"""

    def __init__(self, message: str = "Unable to parse xml output"):
        super().__init__(message)


class NmapExecutionError(NmapError):
    """Exception raised when en error occurred during nmap call"""


class NmapTimeoutError(NmapError):
    """Exception raised when nmap execution times out"""

    def __init__(self, message: str = "Nmap execution timed out"):
        super().__init__(message)


class NmapPrivilegeError(NmapError):
    """Exception raised when nmap requires root privileges to run"""

    def __init__(self, message: str = "Nmap requires root privileges to run"):
        super().__init__(message)
