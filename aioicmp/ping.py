import asyncio
from functools import partial

from icmplib.exceptions import *
from icmplib.models import Host, ICMPRequest
from icmplib.utils import *

from aioicmp.sockets import AioICMPv4Socket, AioICMPv6Socket
from aioicmp.utils import resolve, valid_ipv6


async def aioping(address, count=4, interval=1, timeout=2, packet_id=0, source=None, privileged=True, **kwargs):
    """
    Send ICMP Echo Request packets to a network host.
    Same API as `ping`.
    Usage::
        >>> import asyncio
        >>> from aioicmp import aioping
        >>> asyncio.run(aioping('1.1.1.1'))
        Or
        >>> async def my_func():
        >>>     host = await aioping('1.1.1.1')
        >>>     host.avg_rtt
        >>>     host.is_alive
        >>> asyncio.run(my_func())
        13.2
        True
    See the `Host` class for details.
    """
    loop = asyncio.get_event_loop()

    address = await resolve(loop=loop, name=address)
    if valid_ipv6(address):
        sock = AioICMPv6Socket(address=source, privileged=privileged)
    else:
        sock = AioICMPv4Socket(address=source, privileged=privileged)

    packets_sent = 0
    packets_received = 0

    min_rtt = float('inf')
    avg_rtt = 0.0
    max_rtt = 0.0
    for sequence in range(count):
        request = ICMPRequest(destination=address, id=packet_id, sequence=sequence, **kwargs)
        try:
            await loop.run_in_executor(None, partial(sock.send, request))
            packets_sent += 1
            reply = await sock.receive(address=address, request=request, timeout=timeout, loop=loop)
            reply.raise_for_status()
            packets_received += 1

            round_trip_time = (reply.time - request.time) * 1000
            avg_rtt += round_trip_time
            min_rtt = min(round_trip_time, min_rtt)
            max_rtt = max(round_trip_time, max_rtt)

            if sequence < count - 1:
                await asyncio.sleep(interval)

        except ICMPLibError:
            pass

    if packets_received:
        avg_rtt /= packets_received

    else:
        min_rtt = 0.0

    host = Host(
        address=address,
        min_rtt=min_rtt,
        avg_rtt=avg_rtt,
        max_rtt=max_rtt,
        packets_sent=packets_sent,
        packets_received=packets_received,
    )

    loop.remove_writer(sock._socket)
    loop.remove_reader(sock._socket)
    sock.close()

    return host
