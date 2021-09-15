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
import os
import ctypes

__author__ = 'Wangolo Joel (inquiry@nmapper.com)'
__version__ = '1.4.9'
__last_modification__ = '2019/12/11'


def get_nmap_path():
    """
    Returns the location path where nmap is installed
    by calling which nmap
    """
    os_type = sys.platform
    if os_type == 'win32':
        cmd = "where nmap"
    else:
        cmd = "which nmap"
    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, errs = sub_proc.communicate(timeout=15)
    except Exception as e:
        print(e)
        sub_proc.kill()
    else:
        if os_type == 'win32':
            return output.decode('utf8').strip().replace("\\", "/")
        else:
            return output.decode('utf8').strip()


def get_nmap_version():
    nmap = get_nmap_path()
    cmd = nmap + " --version"

    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, errs = sub_proc.communicate(timeout=15)
    except Exception as e:
        print(e)
        sub_proc.kill()
    else:
        return output.decode('utf8').strip()


def user_is_root(func):
    def wrapper(*args, **kwargs):
        try:
            is_root_or_admin = (os.getuid() == 0)
        except AttributeError as e:
            is_root_or_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if is_root_or_admin:
            return func(*args, **kwargs)
        else:
            return {"error": True, "msg": "You must be root/administrator to continue!"}

    return wrapper
