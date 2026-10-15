//! Settles one M-of-N approval check on a LEZ network, privately.
//!
//! Proves the approvals guest and submits the proof as a transaction, so the
//! network verifies the approval check. Nothing on chain shows the approvers,
//! the threshold or the signatures.
//!
//! The wallet is read from `LEE_WALLET_HOME_DIR`. The program must already be
//! deployed, which `wallet program-loader deploy` does.
//!
//! ```sh
//! settle <approvals.bin> <program account> <private account> [M]
//! ```

use std::collections::HashMap;

use anyhow::{Context, Result};
use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{Signature, SigningKey};
use lee::AccountId;
use lee::privacy_preserving_transaction::circuit::ProgramWithDependencies;
use lee::program::Program;
use wallet::{AccountIdentity, WalletCore};

/// The threshold used when the command line gives none.
const DEFAULT_THRESHOLD: usize = 5;

/// The proposal digest every approver signs.
///
/// Fixed bytes: the guest verifies signatures over it and does not care what
/// it stands for.
fn digest() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    bytes
}

/// `count` real BIP-340 approvals over that digest, from deterministic keys.
///
/// `sign_prehash` rather than `sign`: the `Signer` impl digests its argument
/// with SHA-256 first, so the guest would verify over a different message.
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

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let elf_path = args
        .next()
        .context("usage: settle <approvals.bin> <program account> <private account> [M]")?;
    let program_account_id: AccountId = args
        .next()
        .context("missing program account")?
        .parse()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let account_id: AccountId = args
        .next()
        .context("missing private account")?
        .parse()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let threshold: usize = match args.next() {
        Some(m) => m.parse().context("M must be a number")?,
        None => DEFAULT_THRESHOLD,
    };

    let wallet_core = WalletCore::from_env()
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // The deployed bytecode, so the image id proved against is the one the
    // network has anchored for that account.
    let bytecode = std::fs::read(&elf_path).with_context(|| format!("reading {elf_path}"))?;
    let program = Program::new(bytecode.into()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    println!("image id {:?}", program.id());

    let program_with_dependencies =
        ProgramWithDependencies::new(program, program_account_id, HashMap::new());

    // The encoding the guest decodes: the digest, then one
    // (public key, signature) pair per approver.
    let instruction = borsh::to_vec(&approvals(threshold)).context("serialising approvals")?;
    let accounts =
        vec![AccountIdentity::PrivateOwned(account_id).select_program_shard(program_account_id)];

    println!("proving and submitting M = {threshold}...");
    let (hash, _secrets) = wallet_core
        .send_privacy_preserving_tx(accounts, instruction, &program_with_dependencies)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    println!("transaction {hash}");
    Ok(())
}
