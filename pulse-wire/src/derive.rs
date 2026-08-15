//! Fields a client can compute from a decoded transaction.
//!
//! These are deliberately NOT on the wire. `fee_payer` is `account_keys[0]`,
//! `program_ids` resolve each instruction's `program_id_index`, the static
//! writable set falls out of the three header counts, and the ComputeBudget
//! instruction data is already carried verbatim. Shipping them as TLVs would
//! spend wire bytes and single-threaded hot-path encode time to save a caller
//! a few lines.

use crate::frame::FullTx;

/// `ComputeBudget111111111111111111111111111111`, derived with a base58 decoder
/// validated against `transaction::VOTE_PROGRAM_ID`.
pub const COMPUTE_BUDGET_PROGRAM_ID: [u8; 32] = [
    3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187,
    197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
];

/// The fee payer is always the first account key.
pub fn fee_payer(tx: &FullTx) -> Option<[u8; 32]> {
    tx.account_keys.first().copied()
}

/// Every program the transaction invokes, in first-use order, deduplicated.
/// Solana forbids an ALT-sourced program id, so this is complete without any
/// lookup-table resolution.
pub fn program_ids(tx: &FullTx) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for ix in &tx.instructions {
        if let Some(k) = tx.account_keys.get(ix.program_id_index as usize) {
            if !out.contains(k) {
                out.push(*k);
            }
        }
    }
    out
}

/// Writable accounts drawn from the STATIC key array only. ALT-loaded writables
/// arrive separately in the frame's `loaded_writable` TLV.
pub fn static_writable_accounts(tx: &FullTx) -> Vec<[u8; 32]> {
    let n = tx.account_keys.len();
    let nrs = tx.num_required_signatures as usize;
    let nrsa = tx.num_readonly_signed_accounts as usize;
    let nrua = tx.num_readonly_unsigned_accounts as usize;
    let mut out = Vec::new();
    for i in 0..nrs.saturating_sub(nrsa).min(n) {
        out.push(tx.account_keys[i]);
    }
    let unsigned_end = n.saturating_sub(nrua);
    for i in nrs.min(n)..unsigned_end {
        out.push(tx.account_keys[i]);
    }
    out
}

fn compute_budget_ix(tx: &FullTx, discriminator: u8) -> Option<&[u8]> {
    for ix in &tx.instructions {
        let is_cb = tx
            .account_keys
            .get(ix.program_id_index as usize)
            .is_some_and(|k| *k == COMPUTE_BUDGET_PROGRAM_ID);
        if is_cb && ix.data.first() == Some(&discriminator) {
            return Some(&ix.data[1..]);
        }
    }
    None
}

/// Micro-lamports per compute unit from `SetComputeUnitPrice` (discriminator 3).
/// `None` means the transaction set no price — NOT zero.
pub fn compute_unit_price(tx: &FullTx) -> Option<u64> {
    let d = compute_budget_ix(tx, 3)?;
    Some(u64::from_le_bytes(d.get(0..8)?.try_into().ok()?))
}

/// Explicit `SetComputeUnitLimit` (discriminator 2) only. `None` means the
/// transaction set no limit; no implicit per-instruction default is applied.
pub fn compute_unit_limit(tx: &FullTx) -> Option<u32> {
    let d = compute_budget_ix(tx, 2)?;
    Some(u32::from_le_bytes(d.get(0..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FullAtl, FullInstruction, FullTx};

    fn tx_with(
        keys: Vec<[u8; 32]>,
        ixs: Vec<FullInstruction>,
        nrs: u32,
        nrsa: u32,
        nrua: u32,
    ) -> FullTx {
        FullTx {
            slot: 1,
            versioned: false,
            num_required_signatures: nrs,
            num_readonly_signed_accounts: nrsa,
            num_readonly_unsigned_accounts: nrua,
            recent_blockhash: [0; 32],
            signatures: vec![[0u8; 64]],
            account_keys: keys,
            instructions: ixs,
            address_table_lookups: Vec::<FullAtl>::new(),
        }
    }

    #[test]
    fn fee_payer_is_the_first_account_key() {
        let t = tx_with(vec![[0xA1; 32], [0xB2; 32]], vec![], 1, 0, 0);
        assert_eq!(fee_payer(&t), Some([0xA1; 32]));
        let empty = tx_with(vec![], vec![], 0, 0, 0);
        assert_eq!(fee_payer(&empty), None);
    }

    #[test]
    fn program_ids_resolve_and_dedup_in_order() {
        let t = tx_with(
            vec![[0xA1; 32], [0xB2; 32], [0xC3; 32]],
            vec![
                FullInstruction {
                    program_id_index: 2,
                    accounts: vec![],
                    data: vec![],
                },
                FullInstruction {
                    program_id_index: 1,
                    accounts: vec![],
                    data: vec![],
                },
                FullInstruction {
                    program_id_index: 2,
                    accounts: vec![],
                    data: vec![],
                },
            ],
            1,
            0,
            0,
        );
        assert_eq!(program_ids(&t), vec![[0xC3; 32], [0xB2; 32]]);
    }

    #[test]
    fn program_id_index_out_of_range_is_skipped_not_panicking() {
        let t = tx_with(
            vec![[0xA1; 32]],
            vec![FullInstruction {
                program_id_index: 9,
                accounts: vec![],
                data: vec![],
            }],
            1,
            0,
            0,
        );
        assert!(program_ids(&t).is_empty());
    }

    #[test]
    fn static_writable_follows_the_header_counts() {
        // 4 keys, 2 signers of which 1 readonly, 1 readonly unsigned.
        // writable signers   = [0, nrs - nrsa)          = [0,1)  -> key 0
        // writable unsigned  = [nrs, len - nrua)        = [2,3)  -> key 2
        let t = tx_with(
            vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]],
            vec![],
            2,
            1,
            1,
        );
        assert_eq!(static_writable_accounts(&t), vec![[0u8; 32], [2u8; 32]]);
    }

    #[test]
    fn compute_budget_price_and_limit_are_parsed() {
        // discriminator 3 = SetComputeUnitPrice(u64), 2 = SetComputeUnitLimit(u32)
        let mut price_data = vec![3u8];
        price_data.extend_from_slice(&7_500u64.to_le_bytes());
        let mut limit_data = vec![2u8];
        limit_data.extend_from_slice(&200_000u32.to_le_bytes());
        let t = tx_with(
            vec![[0xA1; 32], COMPUTE_BUDGET_PROGRAM_ID],
            vec![
                FullInstruction {
                    program_id_index: 1,
                    accounts: vec![],
                    data: price_data,
                },
                FullInstruction {
                    program_id_index: 1,
                    accounts: vec![],
                    data: limit_data,
                },
            ],
            1,
            0,
            0,
        );
        assert_eq!(compute_unit_price(&t), Some(7_500));
        assert_eq!(compute_unit_limit(&t), Some(200_000));
    }

    #[test]
    fn compute_budget_absent_returns_none_not_a_default() {
        // An absent value must remain distinguishable from an explicit zero.
        let t = tx_with(vec![[0xA1; 32]], vec![], 1, 0, 0);
        assert_eq!(compute_unit_price(&t), None);
        assert_eq!(compute_unit_limit(&t), None);
    }

    #[test]
    fn truncated_compute_budget_data_is_ignored() {
        let t = tx_with(
            vec![[0xA1; 32], COMPUTE_BUDGET_PROGRAM_ID],
            vec![FullInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![3, 1, 2],
            }],
            1,
            0,
            0,
        );
        assert_eq!(compute_unit_price(&t), None);
    }

    #[test]
    fn compute_budget_program_id_shape() {
        assert_eq!(COMPUTE_BUDGET_PROGRAM_ID.len(), 32);
        assert_eq!(COMPUTE_BUDGET_PROGRAM_ID[0], 0x03);
    }
}
