//! The program a multisig execute calls once its approvals check out.
//!
//! Trivial on purpose: the figure is what LEZ charges to chain a call, and a
//! heavier callee would hide that inside its own work.

use lee_core::program::{GuestOutput, PlanOutput, ProgramCall, ShardEffect, read_program_call};
use lez_multisig_bench_guest::apply_own_effect;

fn main() {
    match read_program_call::<Vec<u8>>() {
        ProgramCall::Plan(input, instruction) => {
            let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("target expects exactly one account")
            };
            let effect = ShardEffect::new(&account, &instruction);
            GuestOutput::Plan(PlanOutput::new(input).with_effects(vec![effect])).write();
        }
        ProgramCall::Apply(input) => apply_own_effect(input),
    }
}
