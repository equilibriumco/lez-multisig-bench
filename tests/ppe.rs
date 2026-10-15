//! What M BIP-340 approvals cost inside the privacy-preserving circuit.
//!
//! `execute_and_prove` runs a program through the privacy circuit with
//! nothing else attached, so each cost is the difference between two programs
//! over the same accounts and the same instruction.
//!
//! Ignored by default: real proving takes minutes.
//!
//! ```sh
//! cargo test --release -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` is not optional. Each prover uses every core, so
//! concurrent tests contend, and one finishing early steps the contention the
//! others are still measuring under.

use std::collections::HashMap;
use std::time::Instant;

use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{Signature, SigningKey};
use key_protocol::key_management::secret_holders::ViewingSecretKey;
use lee::execute_and_prove;
use lee::privacy_preserving_transaction::circuit::{ProgramWithDependencies, ProvingInput};
use lee::program::Program;
use lee_core::account::{Account, AccountId, ProgramShardSelector};
use lee_core::encryption::shared_key_derivation::ViewingPublicKey;
use lee_core::program::PdaSeed;
use lee_core::{
    AuthorizationSecretKey, Identifier, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, WitnessKind,
};

/// The values of M the approval figure is measured at. 5 is the case that
/// matters; 1 and 10 bracket it.
const THRESHOLDS: &[usize] = &[1, 5, 10];

/// The account every program here is given.
const ACCOUNT: AccountId = AccountId::new([23; 32]);

/// The proposal digest every approver signs.
fn digest() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    bytes
}

/// `count` approvals over that digest, from deterministic member keys.
///
/// `sign_prehash` rather than `sign`: the `Signer` impl digests its argument
/// with SHA-256 first, so the guests would verify over a different message.
fn approvals(count: usize) -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>) {
    let message = digest();
    let signed = (1..=count)
        .map(|seed| {
            let seed = seed as u8;
            let mut scalar = [0u8; 32];
            scalar[31] = seed;
            scalar[11] = seed.wrapping_mul(37).wrapping_add(3);
            let key = SigningKey::from_bytes(&scalar).expect("a valid scalar");
            let signature: Signature = key.sign_prehash(&message).expect("signing succeeds");
            (
                key.verifying_key().to_bytes().to_vec(),
                signature.to_bytes().to_vec(),
            )
        })
        .collect();
    (message.to_vec(), signed)
}

/// Seconds and proof bytes for one run through the privacy circuit.
///
/// Refuses to run under `RISC0_DEV_MODE`, which returns a stub receipt in
/// milliseconds.
fn prove_for_real(input: ProvingInput, pwd: &ProgramWithDependencies) -> (f64, usize) {
    // `ProverOpts::is_dev_mode`, which the deprecation names, does not exist in
    // the pinned risc0, so this is the check available.
    #[allow(deprecated)]
    let dev_mode = risc0_zkvm::is_dev_mode();
    assert!(
        !dev_mode,
        "RISC0_DEV_MODE is on, so nothing is proved and every time here is meaningless"
    );

    let started = Instant::now();
    let (_output, proof) =
        execute_and_prove(input, pwd).expect("the program proves inside the privacy circuit");
    (started.elapsed().as_secs_f64(), proof.into_inner().len())
}

/// Proves one program over `count` approvals.
fn prove(elf: &'static [u8], image_id: [u32; 8], count: usize) -> (f64, usize) {
    let program = Program::new_unchecked(image_id, std::borrow::Cow::Borrowed(elf));
    let self_account_id = AccountId::from_builtin_program(program.id());
    let pwd = ProgramWithDependencies::new(program, self_account_id, HashMap::new());

    let instruction = borsh::to_vec(&approvals(count)).expect("the approvals serialise");

    prove_for_real(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(ACCOUNT, self_account_id)],
            signers: [ACCOUNT].into(),
            instruction_data: instruction.into(),
            ..Default::default()
        },
        &pwd,
    )
}

/// What verifying M approvals costs over decoding them.
///
/// One fixed-order pair per threshold, where the other two figures take the
/// mean of four counterbalanced pairs. The difference here is about the whole
/// baseline, an order of magnitude clear of the 5% run-to-run spread.
#[test]
#[ignore = "real proving, minutes"]
fn what_approvals_cost_inside_the_privacy_circuit() {
    println!();
    println!("| M | program | prove (s) | proof (B) |");
    println!("| ---: | --- | ---: | ---: |");

    let mut rows = Vec::new();
    for &count in THRESHOLDS {
        let (base_s, base_b) = prove(
            lez_multisig_bench::BASELINE_ELF,
            lez_multisig_bench::BASELINE_ID,
            count,
        );
        println!("| {count} | baseline | {base_s:.1} | {base_b} |");

        let (approvals_s, approvals_b) = prove(
            lez_multisig_bench::APPROVALS_ELF,
            lez_multisig_bench::APPROVALS_ID,
            count,
        );
        println!("| {count} | approvals | {approvals_s:.1} | {approvals_b} |");

        rows.push((count, base_s, approvals_s));
    }

    println!();
    println!("| M | verification (s) | per approval (s) |");
    println!("| ---: | ---: | ---: |");
    for (count, base_s, approvals_s) in rows {
        let delta = approvals_s - base_s;
        println!("| {count} | {delta:.1} | {:.2} |", delta / count as f64);
    }
    println!();
}

/// Proves `count` approvals followed by `calls` chained calls to the target.
///
/// Two shards go in: this program's own, and the target's. Both are selected
/// whatever `calls` is, so the two arms differ only by the call itself.
fn prove_chain(count: usize, calls: u8) -> (f64, usize) {
    let program = Program::new_unchecked(
        lez_multisig_bench::CHAIN_ID,
        std::borrow::Cow::Borrowed(lez_multisig_bench::CHAIN_ELF),
    );
    let self_account_id = AccountId::from_builtin_program(program.id());

    let target = Program::new_unchecked(
        lez_multisig_bench::TARGET_ID,
        std::borrow::Cow::Borrowed(lez_multisig_bench::TARGET_ELF),
    );
    let target_account_id = AccountId::from_builtin_program(target.id());

    let pwd = ProgramWithDependencies::new(
        program,
        self_account_id,
        [(target_account_id, target)].into(),
    );

    let (message, signed) = approvals(count);
    let instruction = borsh::to_vec(&(message, signed, calls)).expect("the approvals serialise");

    prove_for_real(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(ACCOUNT, self_account_id),
                ProgramShardSelector::new(ACCOUNT, target_account_id),
            ],
            signers: [ACCOUNT].into(),
            instruction_data: instruction.into(),
            ..Default::default()
        },
        &pwd,
    )
}

/// How many times each arm is proved.
///
/// The machine's run-to-run spread is about 5%, the scale of the differences
/// themselves. Each paired figure is the mean over the repeats.
const REPEATS: usize = 4;

/// The values of M the chained-call and private-account figures use.
const PAIR_THRESHOLDS: &[usize] = &[1, 5];

/// Proves both arms of a pair, the reference going first on odd runs.
///
/// The machine slows by about a third over a long run, so an arm that always
/// went second would carry that drift into every difference.
fn counterbalanced(
    run: usize,
    reference: impl Fn() -> f64,
    variant: impl Fn() -> f64,
) -> (f64, f64) {
    if run % 2 == 1 {
        let reference_s = reference();
        let variant_s = variant();
        (reference_s, variant_s)
    } else {
        let variant_s = variant();
        let reference_s = reference();
        (reference_s, variant_s)
    }
}

/// The mean difference over the repeats, with the spread it came from.
fn print_mean(count: usize, deltas: &[f64]) {
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    let low = deltas.iter().copied().fold(f64::INFINITY, f64::min);
    let high = deltas.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    println!("| {count} | **mean** | | | **{mean:.1}** ({low:.1} to {high:.1}) | |");
}

/// What the call a multisig execute authorises adds to the approval check.
///
/// Measured where the base is cheapest, so the difference is the largest
/// share of it. M = 5 runs too, to show the cost does not track M.
#[test]
#[ignore = "real proving, tens of minutes"]
fn what_a_chained_call_costs() {
    println!();
    println!("| M | run | no call (s) | one call (s) | the call (s) | power |");
    println!("| ---: | ---: | ---: | ---: | ---: | --- |");

    for &count in PAIR_THRESHOLDS {
        let mut deltas = Vec::new();
        for run in 1..=REPEATS {
            let before = power_state();
            let (none_s, one_s) =
                counterbalanced(run, || prove_chain(count, 0).0, || prove_chain(count, 1).0);
            let power = power_across(before, power_state());

            let delta = one_s - none_s;
            deltas.push(delta);
            println!("| {count} | {run} | {none_s:.1} | {one_s:.1} | {delta:.1} | {power} |");
        }

        print_mean(count, &deltas);
    }
    println!();
}

/// The PDA seed the configuration account is bound to.
const CONFIG_SEED: PdaSeed = PdaSeed::new([9; 32]);

/// How deep the commitment tree is assumed to be.
///
/// The circuit hashes once per sibling, so depth is a cost input. A chain
/// holding 2^24 notes gives a path of 24.
const TREE_DEPTH: usize = 24;

/// Where the machine is drawing power, and whether it is throttling.
fn power_state() -> &'static str {
    let Ok(output) = std::process::Command::new("pmset")
        .args(["-g", "batt"])
        .output()
    else {
        return "unknown";
    };
    let on_mains = String::from_utf8_lossy(&output.stdout).contains("'AC Power'");

    // `powermode` is 0 normal, 1 low, 2 high. Low throttles and high lifts the
    // limits, so the two move a measurement in opposite directions.
    let mode = std::process::Command::new("pmset")
        .arg("-g")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|line| line.contains("powermode"))
                .and_then(|line| line.split_whitespace().last().map(str::to_owned))
        })
        .unwrap_or_default();

    // A missing reading reports as unknown. Folding it into normal would print
    // agreeing rows that read as a machine holding still.
    match (on_mains, mode.as_str()) {
        (true, "0") => "AC",
        (true, "1") => "AC low",
        (true, "2") => "AC high",
        (true, _) => "AC mode?",
        (false, "0") => "battery",
        (false, "1") => "battery low",
        (false, "2") => "battery high",
        (false, _) => "battery mode?",
    }
}

/// One state if the two readings agree, `before -> after` if they do not.
fn power_across(before: &str, after: &str) -> String {
    if before == after {
        before.to_owned()
    } else {
        format!("{before} -> {after}")
    }
}

/// Keys for the configuration account, from fixed bytes so a run repeats.
///
/// The circuit re-derives the account id from `npk` and `vpk`, and the
/// nullifier from `nsk`, so these must be a real key set.
fn config_keys() -> (NullifierSecretKey, NullifierPublicKey, ViewingPublicKey) {
    let ask = AuthorizationSecretKey([11; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from(&ViewingSecretKey::new([13; 32], [17; 32]));
    (nsk, npk, vpk)
}

/// Proves `count` approvals with the configuration public or private.
///
/// Both arms run the same ELF over the same two accounts and the same
/// instruction. The second account is an ordinary shard in one and a private
/// PDA carried as a witness in the other.
fn prove_config(count: usize, private: bool) -> (f64, usize) {
    let program = Program::new_unchecked(
        lez_multisig_bench::CHAIN_ID,
        std::borrow::Cow::Borrowed(lez_multisig_bench::CHAIN_ELF),
    );
    let self_account_id = AccountId::from_builtin_program(program.id());
    let pwd = ProgramWithDependencies::new(program, self_account_id, HashMap::new());

    let (nsk, npk, vpk) = config_keys();
    let config_id = if private {
        AccountId::for_private_pda(&self_account_id, &CONFIG_SEED, &npk, &vpk, Identifier::ZERO)
    } else {
        AccountId::new([24; 32])
    };

    // A pre-state to update. The cost is in nullifying, re-committing and
    // encrypting it, not in its contents.
    let private_witnesses = if private {
        vec![PrivateWitness {
            vpk,
            random_seed: [5; 32],
            identifier: Identifier::ZERO,
            kind: WitnessKind::Pda {
                binding: (self_account_id, CONFIG_SEED),
            },
            nullifier: NullifierWitness::Update {
                account: Account::default(),
                view_tag: 0,
                nsk,
                membership_proof: (0, vec![[0; 32]; TREE_DEPTH]),
            },
        }]
    } else {
        Vec::new()
    };

    let (message, signed) = approvals(count);
    let instruction = borsh::to_vec(&(message, signed, 0u8)).expect("the approvals serialise");

    prove_for_real(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(ACCOUNT, self_account_id),
                ProgramShardSelector::new(config_id, self_account_id),
            ],
            signers: [ACCOUNT].into(),
            private_witnesses,
            instruction_data: instruction.into(),
            ..Default::default()
        },
        &pwd,
    )
}

/// What holding the multisig's configuration in a private account costs.
#[test]
#[ignore = "real proving, tens of minutes"]
fn what_a_private_configuration_costs() {
    println!();
    println!("| M | run | public config (s) | private config (s) | the account (s) | power |");
    println!("| ---: | ---: | ---: | ---: | ---: | --- |");

    for &count in PAIR_THRESHOLDS {
        let mut deltas = Vec::new();
        for run in 1..=REPEATS {
            let before = power_state();
            let (public_s, private_s) = counterbalanced(
                run,
                || prove_config(count, false).0,
                || prove_config(count, true).0,
            );
            let power = power_across(before, power_state());

            let delta = private_s - public_s;
            deltas.push(delta);
            println!("| {count} | {run} | {public_s:.1} | {private_s:.1} | {delta:.1} | {power} |");
        }

        print_mean(count, &deltas);
    }
    println!();
}
