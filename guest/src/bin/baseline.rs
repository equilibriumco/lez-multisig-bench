//! The same program as `approvals` without the signature checks.
//!
//! It decodes the approvals too. That cost scales with M, so a baseline
//! without it would fold the decode into the cost of verification.

use lee_core::program::{GuestOutput, PlanOutput, ProgramCall, ShardEffect, read_program_call};
use lez_multisig_bench_guest::{Instruction, apply_own_effect};

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, (digest, approvals)) => {
            // Keeps the decode live so the optimiser cannot drop it.
            let mut checksum = digest.len() as u8;
            for (public_key, signature) in &approvals {
                checksum ^= (public_key.len() as u8) ^ (signature.len() as u8);
            }

            let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("baseline expects exactly one account")
            };
            let effect = ShardEffect::new(&account, &vec![checksum]);
            GuestOutput::Plan(PlanOutput::new(input).with_effects(vec![effect])).write();
        }
        ProgramCall::Apply(input) => apply_own_effect(input),
    }
}
