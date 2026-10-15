//! M BIP-340 approvals checked, then `calls` chained calls to a target.
//!
//! The approvals are checked in the plan, the only phase a chained call may be
//! emitted from. Two shards arrive: this program's own, then the callee's.
//!
//! The call count rides in the instruction rather than in a second binary, so
//! a run at 0 and a run at 1 execute the same ELF. Two binaries would differ
//! in codegen as well as in the call.

use lee_core::account::ProgramShardSelector;
use lee_core::program::{ChainedCall, Plan, ProgramCall, read_program_call};
use lez_multisig_bench_guest::{ChainInstruction, apply_own_effect, verify_approvals};

fn main() {
    match read_program_call::<ChainInstruction>() {
        ProgramCall::Plan(input, (digest, approvals, calls)) => {
            let checksum = verify_approvals(&digest, &approvals);

            let Ok([own, target]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                panic!("chain expects its own shard and the target's")
            };

            // The multisig's own record of the execution
            let mut plan = Plan::new(&input);
            plan.effect(&own, &vec![checksum]);

            // The calls those approvals authorised
            for _ in 0..calls {
                plan.call(ChainedCall::new(
                    target.program_account_id,
                    vec![ProgramShardSelector::from(&target)],
                    &vec![checksum],
                ));
            }
            plan.write();
        }
        ProgramCall::Apply(input) => apply_own_effect(input),
    }
}
