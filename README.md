# What an M-of-N multisig costs on LEZ

This repo measures what it costs to check M approvals inside LEZ's privacy-preserving circuit. The figures come from real proving against LEZ v0.3.0 (`db66590ab821a4e142c211017a3866d007f6fa77`).

There are three figures. Each one compares two programs that differ in one way. Both run over the same accounts and the same instruction, so the extra time is the cost of that one difference.

| Figure | The two programs |
|---|---|
| One BIP-340 approval | `approvals` against `baseline`. Both decode the approvals. Only one verifies them. |
| The call an execute authorises | `chain` with one chained call, against `chain` with none. Same ELF both times. |
| One private account | The same program twice, with two accounts each time. In one arm the second account is an ordinary shard, in the other a private PDA. |

## Running it

```sh
cargo test --release -- --ignored --nocapture --test-threads=1
```

The tests are ignored by default because proving takes minutes. Each one prints a table.

The tests refuse to run under `RISC0_DEV_MODE`. That mode returns a stub receipt in milliseconds, so the table would look normal and measure nothing.

A full run took 51 minutes on an Apple M5 Max: about 6 minutes for the approval figure, 19 for the chained call and 27 for the private account. The last two prove eight pairs each, which is where most of the time goes.

`--test-threads=1` is required. Each prover uses every core, so tests running at the same time compete for the machine. When one of them finishes, the others get more of the machine, in the middle of whatever pair they were proving. Counterbalancing cannot cancel that, because it only cancels drift that moves both arms of a pair together. The power columns cannot catch it either, because the machine's state never changed.

## What to trust in the output

Every figure here is a difference between two times. On this machine a proof can take twice as long depending on the power source, Low Power Mode, and how long it has been proving. Subtracting cancels most of that, because the two arms of a pair run minutes apart under the same conditions. The chained-call and private-account tables carry a power column so you can check. It records the power source and `powermode` before each pair and again after it. If both readings agree, the cell shows one state. If they do not, it shows `before -> after`. Ignore that row. If different rows disagree about the power state, ignore the whole run.

Take the mean over the repeats. The chained-call and private-account tests prove each pair four times and swap which arm goes first. Earlier runs kept a fixed order, and some of their differences came out negative. That cannot happen, because adding a call cannot make proving faster.

The approval figure is simpler: one pair per threshold, fixed order, no power column. Verifying M approvals roughly doubles what the baseline costs on its own. The machine's run-to-run spread is about 5%, far too small to hide a difference that size, so repeats would not change the answer. The other two differences are small enough for that spread to hide them, which is why they get four pairs and a swapped order.

## Settling one on a real chain

The figures above are lab numbers. `settle/` goes further: it proves the same `approvals` guest and submits the proof as a transaction, so a network verifies the approval check instead of just the local prover.

```sh
cd settle
cargo build --release
LEE_WALLET_HOME_DIR=... ./target/release/settle <approvals.bin> <program account> <private account> 5
```

Deploy the program first, with `wallet program-loader deploy`. Give it `approvals.bin`, the combined `ProgramBinary`, not the bare `approvals` ELF next to it. `settle` prints the image id it computes from that file, so you see any mismatch before you submit anything.

`settle` returns as soon as the sequencer accepts the transaction. Acceptance is not inclusion. Check with `getTransaction` against the transaction hash.

One of these transactions is on the public LEZ testnet. It verifies five BIP-340 approvals:

```
8efcba7d6395bfe87c81c4b96ff8a6b45bf03108569b646f6c2fd521386e6cc0   block 48422
```

The transaction carries the `approvals` image id in its program claim. The sequencer checks that id against the deployed program.

## What it does not measure

- A full multisig. These are the pieces a multisig is built from. There is no multisig program here.
- A transaction on a chain. `execute_and_prove` runs a program through the privacy circuit and nothing else: no sequencer, no Bedrock, no wallet. That keeps the subtraction clean. It also means these are lab numbers. `settle/` does submit one, but no figure here comes from it.
- The cost with any other signature backend. The guests here patch in RISC Zero's forks of `k256`, `crypto-bigint` and `sha2`. Those speed up the curve arithmetic and the SHA-256 that BIP-340 uses for its challenge. LEZ patches only `keccak`, so its own guests do all of that in plain Rust, which costs more. Nothing here measures how much more, because no unpatched guest is proved. The patches are part of what these numbers assume.

## A faster backend

Everything above uses the accelerated `k256` path. A purpose-built BIP-340 backend over the same curve circuits is faster: 106,698 cycles per approval, against 267,647 on that path. The measurements are in [`logos-kanon`, branch `m0-addendum-a`](https://github.com/equilibriumco/logos-kanon/tree/m0-addendum-a). The backend is in `verifier-core/src/backend/bip340.rs`, the comparison in `bip340-bench`, and the same check inside a LEZ program in `m0/v0.3_rerun/lez-probe`.

It is not used here. The curve library under it is a release candidate, and everything measured here is released code.

## Assumptions worth knowing

The private-account measurement builds a `NullifierWitness::Update` by hand. The circuit takes the commitment-set digest from the membership proof. It never checks that proof against chain state. So a synthetic proof costs the same as a real one.

The membership path is 24 levels deep. The circuit hashes once per level, so the depth is part of the cost. On a real chain the depth grows with the number of commitments it holds.
