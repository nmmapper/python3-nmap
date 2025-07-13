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
import logging
import typing

from nmap3.exceptions import NmapNotInstalledError

__author__ = "Wangolo Joel (inquiry@nmapper.com)"
__version__ = "1.9.3"
__last_modification__ = "Jul/12/2025"

logger = logging.getLogger(__name__)

R = typing.TypeVar("R")


def get_nmap_path(path: typing.Optional[str] = None) -> str:
    """
    Accepts path, validate it. If not valid, search nmap path
    Returns the location path where nmap is installed
    by calling which nmap

    :param path: Optional path to nmap binary
    :return: Path to nmap binary
    :raises NmapNotInstalledError: If nmap is not installed or path is not valid
    """
    if path and (os.path.exists(path)):
        return path

    os_type = sys.platform
    if os_type == "win32":
        cmd = "where nmap"
    else:
        cmd = "which nmap"
    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    output, error = sub_proc.communicate(timeout=15)
    if error:
        logger.error(f"Error while trying to get nmap path: {error.decode('utf8')}")

    if not output:
        raise NmapNotInstalledError(path=path)
    if os_type == "win32":
        return output.decode("utf8").strip().replace("\\", "/")
    return output.decode("utf8").strip()


def get_nmap_version() -> typing.Optional[str]:
    """
    Returns the version of nmap installed on the system

    :return: Version of nmap installed or None if an error occurs
    :raises NmapNotInstalledError: If nmap is not installed
    """
    nmap = get_nmap_path()
    cmd = nmap + " --version"

    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, _ = sub_proc.communicate(timeout=15)
    except Exception as e:
        logger.error(f"Error while trying to get nmap version: {e}", exc_info=True)
        sub_proc.kill()
        return None
    return output.decode("utf8").strip()


def user_is_root(func: typing.Callable[..., R]) -> typing.Callable[..., R]:
    """Decorator to check if the user is root or administrator."""

    def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Union[dict, R]:
        try:
            is_root_or_admin = os.getuid() == 0
        except AttributeError:
            is_root_or_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore

        if is_root_or_admin:
            return func(*args, **kwargs)
        else:
            return {"error": True, "msg": "You must be root/administrator to continue!"}

    return typing.cast(typing.Callable[..., R], wrapper)


def nmap_is_installed_async() -> typing.Callable[
    [typing.Callable[..., typing.Awaitable[R]]],
    typing.Callable[..., typing.Awaitable[R]],
]:
    """Decorator to check if nmap is installed before executing the function."""

    def wrapper(
        func: typing.Callable[..., typing.Awaitable[R]],
    ) -> typing.Callable[..., typing.Awaitable[R]]:
        @functools.wraps(func)
        async def wrapped(
            *args: typing.Any, **kwargs: typing.Any
        ) -> typing.Union[dict, R]:
            nmap_path = get_nmap_path()

            if os.path.exists(nmap_path):
                return await func(*args, **kwargs)
            else:
                logger.error(
                    {
                        "error": True,
                        "msg": "Nmap has not been install on this system yet!",
                    }
                )
                return {
                    "error": True,
                    "msg": "Nmap has not been install on this system yet!",
                }

        return typing.cast(typing.Callable[..., typing.Awaitable[R]], wrapped)

    return wrapper
