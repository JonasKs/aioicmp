import socket
from ipaddress import AddressValueError, IPv4Address, IPv6Address

from icmplib import NameLookupError


def valid_ipv4(address: str) -> bool:
    """
    Checks if an address is a IPv4 address
    :param address: Address to check
    :return: bool
    """
    try:
        IPv4Address(address=address)
        return True
    except AddressValueError:
        return False


def valid_ipv6(address: str) -> bool:
    """
    Checks if an address is a IPv4 address

    :param address: Address to check
    :return: bool
    """
    try:
        IPv6Address(address=address)
        return True
    except AddressValueError:
        return False


async def resolve(loop, name):
    """
    Async

    :param loop:
    :param name:
    :return:
    """
    if valid_ipv4(address=name) or valid_ipv6(address=name):
        return name
    try:
        return loop.getaddrinfo(host=name, port=None, family=socket.AF_INET, type=socket.SOCK_DGRAM)[0][4][0]
    except OSError:
        pass
    try:
        return loop.getaddrinfo(host=name, port=None, family=socket.AF_INET6, type=socket.SOCK_DGRAM)[0][4][0]
    except OSError:
        raise NameLookupError(name)
