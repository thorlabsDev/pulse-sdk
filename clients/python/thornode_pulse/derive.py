"""Fields a client can compute from a decoded transaction.

Mirrors ``pulse-core/src/derive.rs`` (the normative reference) and
``clients/go/derive.go`` exactly.

These are deliberately NOT on the wire. `fee_payer` is `account_keys[0]`,
`program_ids` resolve each instruction's `program_id_index`, the static
writable set falls out of the three header counts, and the ComputeBudget
instruction data is already carried verbatim. Shipping them as TLVs would
spend wire bytes and single-threaded hot-path encode time to save a caller a
few lines.
"""

from __future__ import annotations

import struct
from typing import List, Optional

from .frame import FullTx

#: ComputeBudget111111111111111111111111111111, derived with a base58
#: decoder validated against `transaction.VOTE_PROGRAM_ID`.
COMPUTE_BUDGET_PROGRAM_ID = bytes(
    [
        3,
        6,
        70,
        111,
        229,
        33,
        23,
        50,
        255,
        236,
        173,
        186,
        114,
        195,
        155,
        231,
        188,
        140,
        229,
        187,
        197,
        247,
        18,
        107,
        44,
        67,
        155,
        58,
        64,
        0,
        0,
        0,
    ]
)


def fee_payer(tx: FullTx) -> Optional[bytes]:
    """The fee payer is always the first account key. `None` for a
    transaction with no account keys."""
    return tx.account_keys[0] if tx.account_keys else None


def program_ids(tx: FullTx) -> List[bytes]:
    """Every program the transaction invokes, in first-use order,
    deduplicated. Solana forbids an ALT-sourced program id, so this is
    complete without any lookup-table resolution."""
    out: List[bytes] = []
    seen: set = set()
    for ix in tx.instructions:
        idx = ix.program_id_index
        if 0 <= idx < len(tx.account_keys):
            k = tx.account_keys[idx]
            if k not in seen:
                seen.add(k)
                out.append(k)
    return out


def static_writable_accounts(tx: FullTx) -> List[bytes]:
    """Writable accounts drawn from the STATIC key array only. ALT-loaded
    writables arrive separately in the frame's `loaded_writable` TLV."""
    n = len(tx.account_keys)
    nrs = tx.num_required_signatures
    nrsa = tx.num_readonly_signed_accounts
    nrua = tx.num_readonly_unsigned_accounts

    out: List[bytes] = []
    signed_writable_end = min(max(nrs - nrsa, 0), n)
    out.extend(tx.account_keys[:signed_writable_end])
    unsigned_start = min(nrs, n)
    unsigned_end = max(n - nrua, 0)
    out.extend(tx.account_keys[unsigned_start:unsigned_end])
    return out


def _compute_budget_ix(tx: FullTx, discriminator: int) -> Optional[bytes]:
    for ix in tx.instructions:
        idx = ix.program_id_index
        if not (0 <= idx < len(tx.account_keys)):
            continue
        if tx.account_keys[idx] != COMPUTE_BUDGET_PROGRAM_ID:
            continue
        if ix.data and ix.data[0] == discriminator:
            return ix.data[1:]
    return None


def compute_unit_price(tx: FullTx) -> Optional[int]:
    """Micro-lamports per compute unit from `SetComputeUnitPrice`
    (discriminator 3). `None` means the transaction set no price -- NOT
    zero."""
    d = _compute_budget_ix(tx, 3)
    if d is None or len(d) < 8:
        return None
    return struct.unpack_from("<Q", d, 0)[0]


def compute_unit_limit(tx: FullTx) -> Optional[int]:
    """Explicit `SetComputeUnitLimit` (discriminator 2) only. `None` means
    the transaction set no limit; no implicit per-instruction default is
    applied."""
    d = _compute_budget_ix(tx, 2)
    if d is None or len(d) < 4:
        return None
    return struct.unpack_from("<I", d, 0)[0]
