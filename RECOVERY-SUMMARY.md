# Generic recovery summary

## Problem

A Keystone-created Arweave wallet can produce a different address when its
24-word phrase is imported through Wander's native seed-phrase flow. This does
not by itself mean the words are wrong. Keystone and Wander use different
deterministic RSA-generation procedures.

## Safe recovery sequence

1. Build the pinned Docker image and ensure all published Keystone vector tests
   pass.
2. Run the public checker with networking disabled.
3. Enter the user's expected public address at the visible prompt.
4. Have the user enter their 24 words directly into the hidden prompt. Never
   ask them to disclose the phrase to an agent or another person.
5. Continue only if the checker prints `MATCH`.
6. Run the separate exporter under the same isolation. It repeats the address
   check and writes `arweave-keyfile.json` only after another exact match.
7. In Wander, choose **Import Keyfile** when adding an account and verify the
   original address before accepting it.

## Security boundary

The repository contains only public source, public dependency metadata, and
published/dummy test vectors. It must never contain a user's address, phrase,
passphrase, generated keyfile, balance history, machine username, or absolute
home-directory path.

The expected address is public. The phrase and generated keyfile are private.
The phrase is read with terminal echo disabled and zeroized where practical.
The keyfile is written with mode `0600`, never printed, and never overwritten.

Docker network isolation does not make a compromised host safe. Users should
also disconnect physical and wireless networking, close capture/sync tools,
and use a trusted, encrypted machine when possible.

## Result meanings

- `MATCH`: the supplied phrase plus the empty BIP39 passphrase regenerates the
  supplied public address.
- `NO MATCH`: stop; do not create or import a keyfile.
- `ERROR`: correct the invalid input or environment failure before retrying.

Read [README.md](README.md) for commands and [ANALYSIS.md](ANALYSIS.md) for the
source-backed derivation analysis.
