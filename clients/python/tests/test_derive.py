"""Derived-field tests — pure, no aioquic / no network required.

Direct port of pulse-core/src/derive.rs's test suite (the normative
reference) so behavior can never silently drift.
"""

from thornode_pulse.derive import (
    COMPUTE_BUDGET_PROGRAM_ID,
    compute_unit_limit,
    compute_unit_price,
    fee_payer,
    program_ids,
    static_writable_accounts,
)
from thornode_pulse.frame import FullTx, Instruction


def tx_with(keys, ixs, nrs, nrsa, nrua) -> FullTx:
    return FullTx(
        slot=1,
        versioned=False,
        num_required_signatures=nrs,
        num_readonly_signed_accounts=nrsa,
        num_readonly_unsigned_accounts=nrua,
        recent_blockhash=b"\x00" * 32,
        signatures=[b"\x00" * 64],
        account_keys=keys,
        instructions=ixs,
        address_table_lookups=[],
    )


def test_fee_payer_is_the_first_account_key():
    t = tx_with([b"\xa1" * 32, b"\xb2" * 32], [], 1, 0, 0)
    assert fee_payer(t) == b"\xa1" * 32
    empty = tx_with([], [], 0, 0, 0)
    assert fee_payer(empty) is None


def test_program_ids_resolve_and_dedup_in_order():
    t = tx_with(
        [b"\xa1" * 32, b"\xb2" * 32, b"\xc3" * 32],
        [
            Instruction(2, b"", b""),
            Instruction(1, b"", b""),
            Instruction(2, b"", b""),
        ],
        1,
        0,
        0,
    )
    assert program_ids(t) == [b"\xc3" * 32, b"\xb2" * 32]


def test_program_id_index_out_of_range_is_skipped_not_erroring():
    t = tx_with([b"\xa1" * 32], [Instruction(9, b"", b"")], 1, 0, 0)
    assert program_ids(t) == []


def test_static_writable_follows_the_header_counts():
    # 4 keys, 2 signers of which 1 readonly, 1 readonly unsigned.
    # writable signers  = [0, nrs - nrsa)   = [0,1)  -> key 0
    # writable unsigned = [nrs, len - nrua) = [2,3)  -> key 2
    t = tx_with(
        [b"\x00" * 32, b"\x01" * 32, b"\x02" * 32, b"\x03" * 32],
        [],
        2,
        1,
        1,
    )
    assert static_writable_accounts(t) == [b"\x00" * 32, b"\x02" * 32]


def test_static_writable_survives_hostile_header_counts():
    # nrsa > nrs and nrua > n must not go negative / wrap a slice bound.
    t = tx_with([b"\x00" * 32, b"\x01" * 32], [], nrs=1, nrsa=5, nrua=9)
    assert static_writable_accounts(t) == []


def test_compute_budget_price_and_limit_are_parsed():
    # discriminator 3 = SetComputeUnitPrice(u64), 2 = SetComputeUnitLimit(u32)
    price_data = bytes([3]) + (7_500).to_bytes(8, "little")
    limit_data = bytes([2]) + (200_000).to_bytes(4, "little")
    t = tx_with(
        [b"\xa1" * 32, COMPUTE_BUDGET_PROGRAM_ID],
        [
            Instruction(1, b"", price_data),
            Instruction(1, b"", limit_data),
        ],
        1,
        0,
        0,
    )
    assert compute_unit_price(t) == 7_500
    assert compute_unit_limit(t) == 200_000


def test_compute_budget_absent_returns_none_not_a_default():
    # No implicit 200k default -- absent must be distinguishable from zero,
    # which is the documented footgun in Jetstream's own reference.
    t = tx_with([b"\xa1" * 32], [], 1, 0, 0)
    assert compute_unit_price(t) is None
    assert compute_unit_limit(t) is None


def test_truncated_compute_budget_data_is_ignored():
    t = tx_with(
        [b"\xa1" * 32, COMPUTE_BUDGET_PROGRAM_ID],
        [Instruction(1, b"", bytes([3, 1, 2]))],
        1,
        0,
        0,
    )
    assert compute_unit_price(t) is None


def test_compute_budget_program_id_shape():
    assert len(COMPUTE_BUDGET_PROGRAM_ID) == 32
    assert COMPUTE_BUDGET_PROGRAM_ID[0] == 0x03
