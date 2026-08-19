---
name: recover-keystone-arweave
description: Safely guide verification and recovery of an Arweave wallet created by Keystone when the device is lost, broken, or unavailable, especially when importing the same 24-word phrase into Wander produces a different address. Use for building and running this repository's public-address checker, interpreting MATCH/NO MATCH, and—only after an explicit request and confirmed MATCH—creating a Wander-compatible keyfile under network isolation.
---

# Recover a Keystone Arweave wallet

Use the repository root two directories above this file. Read `README.md` for
commands and `ANALYSIS.md` only when derivation details or source evidence are
needed.

## Protect the user

- Never ask the user to send, paste, type, upload, or reveal their phrase,
  BIP39 passphrase, generated keyfile, or private fields to the agent.
- Never read a generated keyfile. Never print, inspect, summarize, validate,
  upload, commit, or transmit it.
- Never place a phrase in a command argument, environment variable, file,
  redirected input, clipboard automation, shell history, issue, or chat.
- Let the user enter the phrase personally into the program's hidden terminal
  prompt. The agent may provide or start the command but must not supply input.
- Treat the expected Arweave address as public. Do not retain or publish it in
  source, examples, documentation, or commits.
- Do not infer a BIP39 passphrase from a device PIN/password. Use the empty
  passphrase behavior only for Keystone's default wallet. Stop and investigate
  if the user deliberately used Keystone's passphrase-wallet feature.
- Do not create a keyfile merely because recovery is requested. First obtain a
  successful public-address `MATCH`, then require a separate explicit request.

## Verify before secrets are entered

1. Confirm Docker is installed and running.
2. Inspect local changes without opening any private output directory.
3. Build and test while network access is still available:

   ```sh
   docker build --network=default --tag keystone-arweave-checker:verified .
   ```

4. Require a successful build. The Dockerfile runs the pinned Rust test suite,
   including Keystone's published deterministic vectors.
5. Tell the user to disconnect Wi-Fi/Ethernet, disable Bluetooth when
   practical, and close screen sharing, clipboard managers, cloud sync,
   terminal recording, and other input-capture tools.

## Run the public checker

Run:

```sh
./run-offline.sh
```

The container has networking disabled, a read-only filesystem, dropped
capabilities, no new privileges, and no host mount. It asks first for the
expected public address, then for the 24 words through a hidden prompt.

Interpret the result:

- `MATCH`: the phrase with the empty BIP39 passphrase regenerates the expected
  address. Public verification succeeded.
- `NO MATCH`: stop. Do not run the exporter. Recheck the public address and
  word spelling/order; investigate intentional passphrase-wallet use.
- `ERROR`: correct invalid input or environment failures before retrying.

Do not claim that Docker protects against a compromised host, keylogger, or
administrator.

## Export only after confirmed MATCH

Proceed only when the user explicitly asks to create the keyfile and confirms
that the public checker returned `MATCH`.

Run under the same isolation:

```sh
./export-keyfile-offline.sh
```

For an existing encrypted destination directory:

```sh
./export-keyfile-offline.sh /Volumes/ENCRYPTED_VOLUME
```

The exporter asks again for the expected public address and hidden phrase. It
recomputes the address and writes `arweave-keyfile.json` only on an exact
match, with mode `0600`, without overwrite.

Afterward, tell the user to add an account in Wander, choose **Import Keyfile**,
select the file themselves, and verify the original public address. Explain
that Wander now holds a hot-wallet private credential. Recommend moving
meaningful funds to a newly generated secure wallet and protecting or securely
retiring the recovery keyfile according to the user's threat model.

## Preserve repository anonymity

Before publishing or committing, scan tracked source and documentation for:

- real wallet addresses or transaction IDs;
- machine usernames and absolute home paths;
- phrases, passphrases, keyfile contents, or private RSA/JWK fields;
- local logs, `private-output/`, `target/`, archives, and generated JSON.

Published Keystone test vectors and dummy BIP39 vectors are allowed when
clearly labeled as public fixtures. Never replace them with a user's data.
