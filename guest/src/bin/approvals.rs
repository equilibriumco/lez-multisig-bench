//! A LEZ program that verifies M BIP-340 approvals over one proposal digest.
//!
//! The approvals arrive as instruction data and are checked in the plan. On
//! v0.3 they have to be: an apply sees one effect and one shard, not the
//! instruction.

use lee_core::program::{GuestOutput, PlanOutput, ProgramCall, ShardEffect, read_program_call};
use lez_multisig_bench_guest::{Instruction, apply_own_effect, verify_approvals};

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, (digest, approvals)) => {
            let checksum = verify_approvals(&digest, &approvals);

            let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("approvals expects exactly one account")
            };
            let effect = ShardEffect::new(&account, &vec![checksum]);
            GuestOutput::Plan(PlanOutput::new(input).with_effects(vec![effect])).write();
        }
        ProgramCall::Apply(input) => apply_own_effect(input),
    }
}
