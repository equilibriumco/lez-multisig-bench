//! What the measured programs share.
//!
//! Each figure subtracts one of these programs from another. Both must decode
//! the instruction the same way, so the shared types live here.

use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use lee_core::program::{ApplyInput, apply_write};

/// `(public_key, signature)` per approver, over one digest.
pub type Approval = (Vec<u8>, Vec<u8>);

/// What `baseline` and `approvals` decode: a digest and the approvals over it.
pub type Instruction = (Vec<u8>, Vec<Approval>);

/// What `chain` decodes: the same, plus how many calls to make.
pub type ChainInstruction = (Vec<u8>, Vec<Approval>, u8);

/// Verifies every approval over `digest`, returning a checksum of the keys.
///
/// Panics unless all of them verify: the refusal path costs less, so a failure
/// would quietly lower the figure.
pub fn verify_approvals(digest: &[u8], approvals: &[Approval]) -> u8 {
    let mut message = [0u8; 32];
    message.copy_from_slice(digest);

    let mut checksum = 0u8;
    for (public_key, signature) in approvals {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(public_key);

        let key = VerifyingKey::from_bytes(&key_bytes).expect("a valid approver key");
        let parsed = Signature::try_from(&signature[..]).expect("a valid signature");
        assert!(
            key.verify_prehash(&message, &parsed).is_ok(),
            "every approval must verify, or the measurement is of the refusal path"
        );
        checksum ^= key_bytes[0];
    }
    checksum
}

/// Writes back the one-byte effect the plan recorded on the program's own shard.
///
/// Does not return: `apply_write` ends the guest.
pub fn apply_own_effect(input: ApplyInput) -> ! {
    let written: Vec<u8> = borsh::from_slice(&input.effect_data).expect("the plan wrote an effect");
    apply_write(input, written.try_into().expect("one byte fits a shard"));
}
