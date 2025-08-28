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
import os
import ctypes
import functools
import re
import threading
import queue
from typing import Optional, Callable
import time

from nmap3.exceptions import NmapNotInstalledError

__author__ = 'Wangolo Joel (inquiry@nmapper.com)'
__version__ = '1.9.3'
__last_modification__ = 'Jun/06/2025'

def get_nmap_path(path:str='') -> str: 
    """
    Accepts path, validate it. If not valide, search nmap path
    Returns the location path where nmap is installed
    by calling which nmap
    If not found raises NmapNotInstalledError
    """
    if path and (os.path.exists(path)):
        return path

    os_type = sys.platform
    if os_type == 'win32':
        cmd = "where nmap"
    else:
        cmd = "which nmap"
    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    output, e = sub_proc.communicate(timeout=15)
    if e:
        print(e)

    if not output:
        raise NmapNotInstalledError(path=path)
    if os_type == 'win32':
        return output.decode('utf8').strip().replace("\\", "/")
    return output.decode('utf8').strip()

def get_nmap_version():
    nmap = get_nmap_path()
    cmd = nmap + " --version"

    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, _ = sub_proc.communicate(timeout=15)
    except Exception as e:
        print(e)
        sub_proc.kill()
    else:
        return output.decode('utf8').strip()

def user_is_root(func):
    def wrapper(*args, **kwargs):
        try:
            is_root_or_admin = (os.getuid() == 0)
        except AttributeError:
            is_root_or_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            
        if(is_root_or_admin):
            return func(*args, **kwargs)
        else:
            return {"error":True, "msg":"You must be root/administrator to continue!"}
    return wrapper 

def nmap_is_installed_async():
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(*args, **kwargs):
            nmap_path = get_nmap_path()
                
            if(os.path.exists(nmap_path)):
                return await func(*args, **kwargs)
            else:
                print({"error":True, "msg":"Nmap has not been install on this system yet!"})
                return {"error":True, "msg":"Nmap has not been install on this system yet!"}
        return wrapped
    return  wrapper 

def communicate_with_progress(
    sub_proc: subprocess.Popen,
    xml_path: str,
    timeout: int = None,
    progress_callback: Optional[Callable[[str], None]] = None
) -> tuple[str, str]:
    """
    Reads stdout and stderr from a subprocess, optionally reporting progress.

    Parameters
    ----------
    sub_proc : subprocess.Popen
        The subprocess object to communicate with.
    xml_path : str
        Path to xml_file for io
    timeout : int | None, optional
        Timeout in seconds for the subprocess. If None, waits until finished.
    progress_callback : Callable[[float], None] | None, optional
        A callback function that is called with the current scan progress
        and details as a string.

    Returns
    -------
    Tuple[str, str]
        A tuple containing xml and stderr output.
    """

    stdout_queue = queue.Queue()
    stderr_queue = queue.Queue()

    def reader(pipe, q):
        for line in pipe:
            q.put(line)
        pipe.close()

    #start threads to read stdout and stderr
    t_out = threading.Thread(target=reader, args=(sub_proc.stdout, stdout_queue))
    t_err = threading.Thread(target=reader, args=(sub_proc.stderr, stderr_queue))
    t_out.start()
    t_err.start()

    output = ""
    errs = ""
    start_time = time.time()

    while True:
    
        #Check timeout
        if timeout is not None and (time.time() - start_time) > timeout:
            sub_proc.kill()
            errs += f"\nProcess killed after exceeding timeout of {timeout} seconds.\n"
            break

        if sub_proc.poll() is not None and stdout_queue.empty() and stderr_queue.empty():
            sub_proc.kill()
            break # finished

        #Process stdout
        while not stdout_queue.empty():
            line = stdout_queue.get_nowait()
            if progress_callback:
                #grab the progress line from stdout and pass to progress_callback
                match = re.search(r'(\d+(?:\.\d+)?)% done', line)
                if match:
                    progress_callback(line.strip())

        #Process stderr
        while not stderr_queue.empty():
            line = stderr_queue.get_nowait()
            errs += line

        time.sleep(0.05) # prevent busy-loop

    with open(xml_path) as f:
        output = f.read()

    return output, errs