import asyncio
from socket import AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, socket
from time import time

import async_timeout
from icmplib.exceptions import ICMPSocketError, SocketUnavailableError, TimeoutExceeded
from icmplib.sockets import ICMPv4Socket, ICMPv6Socket
from icmplib.utils import PLATFORM_LINUX


class AioICMPv4Socket(ICMPv4Socket):
    def _create_socket(self, type: int) -> socket:
        """
        Creates a socket
        :param type: Type, either SOCK_DGRAM or SOCK_RAW, depending on system and permissions. Decided by the subclass.
        :return: socket
        """
        sock = socket(
            family=AF_INET,
            type=type,
            proto=IPPROTO_ICMP,
        )
        sock.setblocking(False)
        return sock

    async def receive(self, address: str, request=None, timeout=2, loop=None):
        """
        Async implementation of the receive method.
        Receive an ICMP reply message from the socket.

        This method can be called multiple times if you expect several
        responses as with a broadcast address.

        :type request: ICMPRequest, optional
        :param request: The ICMP request to use to match the response.
            By default, all ICMP packets arriving on the socket are
            returned.

        :type timeout: int or float, optional
        :param timeout: The maximum waiting time for receiving the
            response in seconds. Default to 2.

        :raises TimeoutExceeded: If no response is received before the
            timeout specified in parameters.
        :raises SocketUnavailableError: If the socket is closed.
        :raises ICMPSocketError: If another error occurs while
            receiving.

        :rtype: ICMPReply
        :returns: An `ICMPReply` object representing the response of
            the desired destination or an upstream gateway.

        See the `ICMPReply` class for details.

        """
        if not loop:
            loop = asyncio.get_event_loop()
        if not self._socket:
            raise SocketUnavailableError
        try:
            with async_timeout.timeout(timeout=timeout):
                packet = await loop.sock_recv(self._socket, 1024)
                current_time = time()

                if not self._privileged and PLATFORM_LINUX:
                    padding = b'\x00' * self._ICMP_HEADER_OFFSET
                    packet = padding + packet

                reply = self._parse_reply(packet=packet, source=address, time=current_time)

                if reply and not request or reply and request.id == reply.id and request.sequence == reply.sequence:
                    return reply

        except asyncio.TimeoutError:
            raise TimeoutExceeded(timeout)
        except OSError as err:
            raise ICMPSocketError(str(err))


class AioICMPv6Socket(ICMPv6Socket):
    def _create_socket(self, type) -> socket:
        """
        Creates a socket
        :param type: Type, either SOCK_DGRAM or SOCK_RAW, depending on system and permissions.
            Decided by the subclass.
        :return: socket
        """
        sock = socket(
            family=AF_INET6,
            type=type,
            proto=IPPROTO_ICMPV6,
        )
        sock.setblocking(False)
        return sock
