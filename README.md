# Keystone Arweave Recovery

Recover an Arweave wallet created by a Keystone hardware wallet when the
device is broken or unavailable—and importing the same 24 words into Wander
produces a different address.

The tools reproduce Keystone's deterministic RSA-4096 derivation, verify the
result against the wallet's original public address, and can then create a
Wander-compatible JWK keyfile.

**Keep your recovery phrase and generated keyfile private.** Enter the phrase
only into the hidden terminal prompt.

## How it works

1. The public checker derives an address and returns `MATCH` or `NO MATCH`.
2. Only after `MATCH`, a separate exporter can create the private keyfile.
3. The keyfile can be added to Wander with **Import Keyfile**.

The default implementation uses an empty BIP39 passphrase, matching Keystone's
default wallet. A device PIN/password is not a BIP39 passphrase.

## Quick start

### Requirements

The documented recovery workflow requires Docker Desktop on macOS or Windows,
or a Docker-compatible engine on Linux. Docker is used to provide the verified
build and network-disabled runtime.

The public-address checker can also run directly with Rust 1.88.0:

```sh
cargo run --release --locked --bin keystone-arweave-checker
```

The direct Rust command does not provide Docker's isolation. The keyfile export
workflow currently requires Docker.

Build and run the verified Docker image:

```sh
docker build --network=default --tag keystone-arweave-checker:verified .
./run-offline.sh
```

The program asks for:

1. The original public Arweave address—visible input.
2. The 24-word recovery phrase—hidden input.

The container runs with networking disabled, a read-only filesystem, dropped
capabilities, no new privileges, and no host-directory mount.

### Results

- `MATCH`: the phrase regenerates the expected address.
- `NO MATCH`: stop; do not create a keyfile.
- `ERROR`: the address, phrase, or environment is invalid.

## Restore the wallet in Wander

Proceed only after `MATCH`:

```sh
./export-keyfile-offline.sh
```

The exporter repeats the address check and writes only on an exact match:

```text
private-output/arweave-keyfile.json
```

In Wander, choose **Add account → Import Keyfile**, select the file, and verify
the original address. Wander now holds a hot-wallet private credential; anyone
with that JSON can control the wallet.

## Use with an AI coding agent

The repository includes an agent skill:

[`skills/recover-keystone-arweave/SKILL.md`](skills/recover-keystone-arweave/SKILL.md)

Give that file to a compatible coding agent or install the skill folder. The
skill guides the workflow while explicitly forbidding the agent from receiving
or reading the recovery phrase or generated keyfile.

## Verification

- Rust 1.88.0
- `rsa` 0.8.2
- `rand_chacha` 0.3.1
- `rpassword` 7.5.0
- Locked dependency graph in `Cargo.lock`
- Docker builder and runtime images pinned by digest
- Automated Keystone 3, first-generation Keystone, and dummy BIP39 vectors

See [ANALYSIS.md](ANALYSIS.md) for the exact Keystone/Wander source references
and [RECOVERY-SUMMARY.md](RECOVERY-SUMMARY.md) for the complete safety workflow.

## Security

- Build and test before entering secrets.
- Disconnect Wi-Fi/Ethernet and disable Bluetooth when practical.
- Close screen sharing, clipboard managers, cloud sync, and recording tools.
- Never put the phrase in commands, files, environment variables, chats, or
  agent prompts.
- Docker isolation does not protect a compromised host or keylogger.
- The pinned `rsa` version exists only to reproduce Keystone's deterministic
  key generation. Do not reuse it for network-observable RSA signing or
  decryption.
