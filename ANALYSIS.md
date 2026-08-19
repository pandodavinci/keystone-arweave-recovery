# Verified derivation analysis

This checker answers one narrow question without exporting a private key:
does a supplied 24-word BIP39 mnemonic, with the BIP39 passphrase set to the
empty string, regenerate the expected public Keystone Arweave address supplied
interactively by the user?

## Keystone algorithm and exact sources

The current Keystone 3 firmware was inspected at commit
[`6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f`](https://github.com/KeystoneHQ/keystone3-firmware/tree/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f).

- [`rust/keystore/src/algorithms/rsa/mod.rs` lines 32-60](https://github.com/KeystoneHQ/keystone3-firmware/blob/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f/rust/keystore/src/algorithms/rsa/mod.rs#L32-L60)
  hashes the input seed twice with SHA-256, seeds `ChaCha20Rng`, and uses it to
  generate a 4096-bit RSA key. Lines 130-133 return its unsigned big-endian
  modulus.
- [`rust/apps/arweave/src/lib.rs` lines 52-61](https://github.com/KeystoneHQ/keystone3-firmware/blob/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f/rust/apps/arweave/src/lib.rs#L52-L61)
  computes an Arweave address as unpadded URL-safe Base64 of SHA-256 over that
  modulus.
- [`src/ui/gui_model/gui_model.c` lines 1805-1827](https://github.com/KeystoneHQ/keystone3-firmware/blob/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f/src/ui/gui_model/gui_model.c#L1805-L1827)
  passes the account seed into the Arweave secret generator.
- [`src/managers/keystore.c` lines 217-247](https://github.com/KeystoneHQ/keystone3-firmware/blob/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f/src/managers/keystore.c#L217-L247)
  uses the ordinary stored seed when no passphrase exists, and recalculates it
  with the stored passphrase only when a passphrase wallet is active. Lines
  778-817 show the BIP39 mnemonic-to-seed call.
- [`src/managers/keystore.c` lines 417-466](https://github.com/KeystoneHQ/keystone3-firmware/blob/6ab436a2c34a5bcce2e72aae1e6ff8ee43bf057f/src/managers/keystore.c#L417-L466)
  shows the explicit `SetPassphrase` operation: non-empty input enables the
  passphrase state, while empty input clears it.

The current firmware lockfile pins the relevant algorithm dependencies to
`rsa 0.8.2`, `rand_chacha 0.3.1`, `rand_core 0.6.4`, and `sha2 0.10.9`.

The first-generation Keystone implementation was also checked at
[`rust-crypto-core` commit `207c83539c05cf35bb25b8e82888c4095854efdc`](https://github.com/KeystoneHQ/rust-crypto-core/tree/207c83539c05cf35bb25b8e82888c4095854efdc),
which is reached from `Keystone-cold-app` through its pinned `rcc_android`
submodule commit `50f679e8ad609af752fc626303283af3ada6bec3`.

- [`signer/src/algorithm/rsa.rs` lines 69-90](https://github.com/KeystoneHQ/rust-crypto-core/blob/207c83539c05cf35bb25b8e82888c4095854efdc/signer/src/algorithm/rsa.rs#L69-L90)
  contains the same double-SHA-256, ChaCha20, RSA-4096 construction.
- [`signer/src/keymaster/se/mod.rs` lines 192-210](https://github.com/KeystoneHQ/rust-crypto-core/blob/207c83539c05cf35bb25b8e82888c4095854efdc/signer/src/keymaster/se/mod.rs#L192-L210)
  requests `GetKeyType::MasterSeed` and passes that master seed to the RSA
  generator. The path-shaped constant is supplied to the secure-element API,
  but this call explicitly requests the master seed; it is not ordinary BIP32
  child-key derivation.

The older lockfile pins `rsa 0.7.2`, `rand_chacha 0.3.1`, `rand_core 0.6.4`,
and `sha2 0.9.9`. The included first-generation vector test proves the
checker, using `rsa 0.8.2`, reproduces the older published RSA output too.

## BIP39 passphrase versus device PIN/password

The [official BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed)
defines the seed as PBKDF2-HMAC-SHA512 with 2048 iterations, a salt of
`"mnemonic" + passphrase`, and a 64-byte output. When there is no passphrase,
the passphrase is the empty string. Every passphrase, including a typo,
produces a valid but different seed; there is no built-in wrong-passphrase
error.

Keystone's [official passphrase-wallet instructions](https://support.keyst.one/advanced-features/passphrase)
say the default wallet uses a blank passphrase and describe a deliberate flow
through Settings > Passphrase Wallet, authentication, passphrase entry, and
confirmation to open a hidden wallet. Leaving the field blank returns to the
default wallet. Keystone's [password documentation](https://support.keyst.one/basic-features/password)
describes the device password as authorization to unlock/sign and to enter a
passphrase wallet. It is not the BIP39 passphrase. A device PIN/password alone
therefore gives no reason to infer that a passphrase wallet existed; a user
would ordinarily have had to intentionally enable and use one.

## Why Wander's mnemonic import produces another address

Wander's official source was inspected at commit
[`4828cf173ef4b183a442b738ad349148c9edf60f`](https://github.com/wanderwallet/Wander/tree/4828cf173ef4b183a442b738ad349148c9edf60f),
package version `1.41.3`.

[`src/wallets/generator.ts` lines 20-39](https://github.com/wanderwallet/Wander/blob/4828cf173ef4b183a442b738ad349148c9edf60f/src/wallets/generator.ts#L20-L39)
does derive a BIP39 seed, but then calls `human-crypto-keys`
`getKeyPairFromSeed` for RSA-4096. Wander's lockfile resolves
`bip39-web-crypto 4.0.1`, `human-crypto-keys 0.1.4`, and `arweave 1.15.7`.
The [`human-crypto-keys` documentation](https://github.com/47ng/human-crypto-keys#deterministic-rsa-key-generation)
documents an HMAC-DRBG/Node-Forge deterministic RSA construction.

That is **not** Keystone's `double SHA-256 -> ChaCha20Rng -> Rust rsa`
construction. RSA prime generation is algorithm-specific: the same BIP39 seed
fed into these two deterministic generators yields different primes, modulus,
and therefore address. A different address from Wander's native mnemonic
import is consequently expected and does not invalidate the Keystone recovery
phrase.

To control the original Keystone address in Wander without the physical
Keystone, a Keystone-compatible Arweave JWK/keyfile must be generated under
network isolation and imported with Wander's keyfile option. A separate
fail-closed exporter performs that operation only after the public checker has
reported `MATCH`. The original checker remains public-address-only. The
exporter refuses to write unless the newly derived address equals the expected
address supplied by that user.

## Test vectors

The automated suite includes:

1. Keystone 3's published raw seed `2f1986623bdc5d4f908e5be9d6fa00ec`,
   whose published key material produces address
   `ICwtdLdGrJJ5bIe7rTWS1dd2_8tpOv1ZZIKnChvb19Y`.
2. The first-generation source's published 64-byte recovery-test seed
   (the standard dummy BIP39 vector's empty-passphrase seed), whose published
   modulus hashes to `eMCuSpXHZnPZ3AJsWqqs3Td7YrgD4E44fdDyBKxPT0I`.
3. A dummy valid 24-word mnemonic test. No user mnemonic is present in source,
   tests, build layers, shell history, or files.
