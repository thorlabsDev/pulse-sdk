"""Sig-first handoff queue tests -- no network required.

A slow consumer must lose the OLDEST signatures and be able to count them; the
end-of-stream sentinel must survive a full queue, or the consumer hangs forever.
"""

import asyncio

from thornode_pulse.client import SIG_QUEUE_LEN, _put_dropping_oldest


def drain(q: asyncio.Queue) -> list:
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def test_puts_without_dropping_when_there_is_room():
    async def run():
        q: asyncio.Queue = asyncio.Queue(maxsize=4)

        dropped = sum(_put_dropping_oldest(q, n) for n in range(3))

        assert dropped == 0
        assert drain(q) == [0, 1, 2]

    asyncio.run(run())


def test_evicts_oldest_when_full():
    async def run():
        q: asyncio.Queue = asyncio.Queue(maxsize=3)

        dropped = sum(_put_dropping_oldest(q, n) for n in range(6))

        # Six in, three slots: the three oldest are gone, the freshest survive.
        assert dropped == 3
        assert drain(q) == [3, 4, 5]

    asyncio.run(run())


def test_sentinel_survives_a_full_queue():
    async def run():
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        for n in range(2):
            _put_dropping_oldest(q, n)

        _put_dropping_oldest(q, None)

        # The None sentinel is what stops the consumer's async-for. Losing it to a
        # full queue would leave the caller blocked on a dead connection.
        assert None in drain(q)

    asyncio.run(run())


def test_queue_is_bounded():
    assert SIG_QUEUE_LEN > 0
