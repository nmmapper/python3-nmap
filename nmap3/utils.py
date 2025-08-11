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
import os
import sys
import functools
import logging
import typing
import asyncio
import shutil
import ctypes

from nmap3.exceptions import (
    NmapExecutionError,
    NmapNotInstalledError,
    NmapPrivilegeError,
)

__author__ = "Wangolo Joel (inquiry@nmapper.com)"
__version__ = "1.9.3"
__last_modification__ = "Jul/14/2025"

logger = logging.getLogger(__name__)

T = typing.TypeVar("T")
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

    output = shutil.which("nmap")
    if not output:
        raise NmapNotInstalledError(path=path)
    return output.strip().replace("\\", "/")


def get_nmap_version() -> typing.Optional[str]:
    """
    Returns the version of nmap installed on the system

    :return: Version of nmap installed or None if an error occurs
    :raises NmapNotInstalledError: If nmap is not installed
    """
    nmap = get_nmap_path()
    cmd = nmap + " --version"

    args = shlex.split(cmd)
    process = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, _ = process.communicate(timeout=15)
    except Exception as e:
        logger.error(f"Error while trying to get nmap version: {e}", exc_info=True)
        _terminate_process(process, timeout=0.2)
        return None
    return output.decode("utf8").strip()


PRIVILEGE_DENIED_KEYWORDS = {
    "root privileges",
    "administrator",
    "permission denied",
    "operation not permitted",
}


if sys.version_info >= (3, 10) or (sys.version_info >= (3, 7) and typing.TYPE_CHECKING):
    # For Python 3.10+ or when type checking, use proper ParamSpec typing
    try:
        from typing import ParamSpec

        P = ParamSpec("P")  # type: ignore[no-redef]

        @typing.overload  # type: ignore[no-overload-impl]
        def requires_root_privilege(
            func: typing.Callable[P, typing.Awaitable[T]],
        ) -> typing.Callable[P, typing.Awaitable[T]]: ...

        @typing.overload
        def requires_root_privilege(
            func: typing.Callable[P, T],
        ) -> typing.Callable[P, T]: ...

    except ImportError:
        # Fallback if ParamSpec is not available
        try:
            from typing_extensions import ParamSpec  # type: ignore[assignment]

            P = ParamSpec("P")  # type: ignore[no-redef]

            @typing.overload  # type: ignore[no-overload-impl,no-redef]
            def requires_root_privilege(  # type: ignore[no-redef]
                func: typing.Callable[P, typing.Awaitable[T]],
            ) -> typing.Callable[P, typing.Awaitable[T]]: ...

            @typing.overload
            def requires_root_privilege(  # type: ignore[no-redef]
                func: typing.Callable[P, T],
            ) -> typing.Callable[P, T]: ...

        except ImportError:
            # No overloads for very old Python versions
            pass


if os.name == "nt":
    def _is_windows_admin() -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0 # type: ignore[attr-defined]


def requires_root_privilege(  # type: ignore[no-redef]
    func: typing.Callable[..., typing.Any],
) -> typing.Callable[..., typing.Any]:
    """
    Decorator that marks a function as requiring root privileges.

    If the function is called without root privileges, it catches `NmapExecutionError`
    and raises `NmapPrivilegeError` with a message indicating insufficient privilege.

    Works with both sync and async functions.
    """
    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            if os.name == "nt" and not _is_windows_admin():
                raise NmapPrivilegeError(
                    "You must be root/administrator to continue!"
                )
            # Proceed for other platforms as the user may already
            # be running the program with 'sudo' or 'doas' privileges
            try:
                return await func(*args, **kwargs)
            except NmapExecutionError as e:
                msg = str(e).lower()
                if any(keyword in msg for keyword in PRIVILEGE_DENIED_KEYWORDS):
                    raise NmapPrivilegeError(
                        "You must be root/administrator to continue!"
                    ) from e
                raise e

        return async_wrapper

    else:

        @functools.wraps(func)
        def sync_wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            if os.name == "nt" and not _is_windows_admin():
                raise NmapPrivilegeError(
                    "You must be root/administrator to continue!"
                )
            
            # Proceed for other platforms
            try:
                return func(*args, **kwargs)
            except NmapExecutionError as e:
                msg = str(e).lower()
                if any(keyword in msg for keyword in PRIVILEGE_DENIED_KEYWORDS):
                    raise NmapPrivilegeError(
                        "You must be root/administrator to continue!"
                    ) from e
                raise e

        return sync_wrapper


user_is_root = requires_root_privilege  # Alias for backward compatibility


def _terminate_process(process: subprocess.Popen, timeout: float = 0.5) -> None:
    """Terminate a (sub) process gracefully"""
    try:
        process.terminate()
        process.wait(
            timeout=timeout
        )  # Wait to reap the process and avoid 'zombie' state
    except subprocess.TimeoutExpired:
        logger.warning(f"Process {process.pid!r} did not terminate gracefully")
        process.kill()


async def _terminate_asyncio_process(
    process: asyncio.subprocess.Process, timeout: float = 0.5
) -> None:
    """Terminate a asyncio (sub) process gracefully"""
    try:
        process.terminate()
        await asyncio.wait_for(
            process.wait(), timeout=1.0
        )  # Wait to reap the process and avoid 'zombie' state
    except asyncio.TimeoutError:
        logger.warning(f"Process {process.pid!r} did not terminate gracefully")
        process.kill()
