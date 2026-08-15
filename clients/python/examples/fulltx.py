"""Subscribe to full-tx with an explicit account or program filter.

PULSE_TARGET='<HOST:PORT_FROM_DASHBOARD>' \
PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' \
PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' python examples/fulltx.py
"""

import asyncio
import os

import base58

from thornode_pulse import Filter, connect_pulse


async def main() -> None:
    target = os.environ["PULSE_TARGET"]
    token = os.environ["PULSE_TOKEN"]
    account_or_program = os.environ["PULSE_ACCOUNT"]
    flt = Filter.accounts(account_or_program)

    async with connect_pulse(target, token=token) as client:
        sub = await client.subscribe_full(flt, fields=("alt",))
        async for frame in sub:
            tx = frame.tx
            signature = (
                base58.b58encode(tx.signatures[0]).decode("ascii")
                if tx.signatures
                else ""
            )
            print(
                f"slot={tx.slot} signatures={len(tx.signatures)} "
                f"keys={len(tx.account_keys)} instructions={len(tx.instructions)} "
                f"alt_incomplete={frame.alt_incomplete} signature={signature}"
            )
            print(f"metrics={sub.metrics}")


if __name__ == "__main__":
    asyncio.run(main())
