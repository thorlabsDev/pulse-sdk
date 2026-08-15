"""Subscribe to sig-first with an explicit account or program filter.

PULSE_TARGET='<HOST:PORT_FROM_DASHBOARD>' \
PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' \
PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' python examples/sigfirst.py
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
        sub = await client.subscribe_sig_first(flt)
        async for item in sub:
            signature = base58.b58encode(item.signature).decode("ascii")
            print(f"slot={item.slot} seq={item.seq} signature={signature}")
            print(f"metrics={sub.metrics} gaps={sub.gaps}")


if __name__ == "__main__":
    asyncio.run(main())
