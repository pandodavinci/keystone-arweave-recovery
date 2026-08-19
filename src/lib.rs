use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bip39::{Language, Mnemonic};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rsa::{PublicKeyParts, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::{Zeroize, Zeroizing};

const RSA_BITS: usize = 4096;

/// A private Arweave JWK plus the public address derived from its modulus.
///
/// The JSON buffer is zeroized when dropped. Writing it to disk is the
/// caller's explicit responsibility.
pub struct ExportedKeyfile {
    pub address: String,
    pub json: Zeroizing<String>,
}

/// Validates a public Arweave address and returns its normalized text.
pub fn validate_arweave_address(input: &str) -> Result<String, Box<dyn Error>> {
    let address = input.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(address)
        .map_err(|_| "expected a 43-character unpadded Base64URL Arweave address")?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != address {
        return Err("expected a 43-character unpadded Base64URL Arweave address".into());
    }
    Ok(address.to_owned())
}

/// Reproduces Keystone's deterministic Arweave public-address derivation.
///
/// This function generates RSA private components transiently because the
/// public modulus cannot otherwise be reproduced. It never serializes or
/// returns them. Only SHA-256(modulus), encoded as unpadded base64url, leaves
/// this function.
pub fn address_from_mnemonic_empty_passphrase(
    phrase: &str,
) -> Result<String, Box<dyn Error>> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)?;
    if mnemonic.word_count() != 24 {
        return Err(format!("expected exactly 24 words, got {}", mnemonic.word_count()).into());
    }

    // BIP39: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048).
    // The passphrase is deliberately the empty string for this checker.
    let mut bip39_seed = mnemonic.to_seed_normalized("");
    let address = address_from_keystone_seed(&bip39_seed);
    bip39_seed.zeroize();
    address
}

/// Reproduces a Keystone Arweave key and serializes it as a standard private
/// RSA JWK. This is kept separate from the public-only checker binary.
pub fn keyfile_from_mnemonic_empty_passphrase(
    phrase: &str,
) -> Result<ExportedKeyfile, Box<dyn Error>> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)?;
    if mnemonic.word_count() != 24 {
        return Err(format!("expected exactly 24 words, got {}", mnemonic.word_count()).into());
    }

    let mut bip39_seed = mnemonic.to_seed_normalized("");
    let result = (|| {
        let mut private_key = private_key_from_keystone_seed(&bip39_seed)?;
        let address = address_from_private_key(&private_key);
        let json = private_key_to_jwk_json(&mut private_key)?;
        Ok(ExportedKeyfile { address, json })
    })();
    bip39_seed.zeroize();
    result
}

fn address_from_keystone_seed(seed: &[u8]) -> Result<String, Box<dyn Error>> {
    let private_key = private_key_from_keystone_seed(seed)?;
    Ok(address_from_private_key(&private_key))
}

fn private_key_from_keystone_seed(seed: &[u8]) -> Result<RsaPrivateKey, Box<dyn Error>> {
    // Keystone get_rsa_seed(): SHA256(SHA256(seed)).
    let first_hash = Sha256::digest(seed);
    let mut rsa_seed: [u8; 32] = Sha256::digest(first_hash).into();

    // Keystone: ChaCha20Rng::from_seed followed by rsa 0.8.2 key generation.
    let mut rng = ChaCha20Rng::from_seed(rsa_seed);
    rsa_seed.zeroize();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|error| {
        std::io::Error::other(format!("Keystone-compatible RSA generation failed: {error}"))
    })?;
    Ok(private_key)
}

fn address_from_private_key(private_key: &RsaPrivateKey) -> String {
    // Arweave address = base64url-no-pad(SHA256(unsigned big-endian modulus)).
    let modulus = private_key.n().to_bytes_be();
    let address_hash = Sha256::digest(modulus);
    URL_SAFE_NO_PAD.encode(address_hash)
}

fn private_key_to_jwk_json(
    private_key: &mut RsaPrivateKey,
) -> Result<Zeroizing<String>, Box<dyn Error>> {
    private_key.precompute().map_err(|error| {
        std::io::Error::other(format!("RSA CRT precomputation failed: {error}"))
    })?;

    if private_key.primes().len() != 2 {
        return Err("expected an RSA key with exactly two primes".into());
    }

    let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let d = Zeroizing::new(URL_SAFE_NO_PAD.encode(private_key.d().to_bytes_be()));
    let p = Zeroizing::new(URL_SAFE_NO_PAD.encode(private_key.primes()[0].to_bytes_be()));
    let q = Zeroizing::new(URL_SAFE_NO_PAD.encode(private_key.primes()[1].to_bytes_be()));
    let dp = Zeroizing::new(URL_SAFE_NO_PAD.encode(
        private_key
            .dp()
            .ok_or("RSA key is missing dp")?
            .to_bytes_be(),
    ));
    let dq = Zeroizing::new(URL_SAFE_NO_PAD.encode(
        private_key
            .dq()
            .ok_or("RSA key is missing dq")?
            .to_bytes_be(),
    ));
    let qinv = private_key
        .qinv()
        .ok_or("RSA key is missing q inverse")?
        .to_biguint()
        .ok_or("RSA q inverse was negative")?;
    let qi = Zeroizing::new(URL_SAFE_NO_PAD.encode(qinv.to_bytes_be()));

    // All interpolated values are unpadded base64url and cannot contain JSON
    // control characters. Keep the private fields in zeroizing buffers.
    Ok(Zeroizing::new(format!(
        "{{\"kty\":\"RSA\",\"e\":\"{e}\",\"n\":\"{n}\",\"d\":\"{d}\",\"p\":\"{p}\",\"q\":\"{q}\",\"dp\":\"{dp}\",\"dq\":\"{dq}\",\"qi\":\"{qi}\"}}\n",
        d = d.as_str(),
        p = p.as_str(),
        q = q.as_str(),
        dp = dp.as_str(),
        dq = dq.as_str(),
        qi = qi.as_str(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published in Keystone's app_arweave test_generate_address and
    // keystore RSA tests. This checks the complete deterministic RSA and
    // Arweave-address path from their published raw seed vector.
    #[test]
    fn keystone_published_arweave_vector() {
        let seed = hex_to_bytes("2f1986623bdc5d4f908e5be9d6fa00ec");
        let mut private_key = private_key_from_keystone_seed(&seed).unwrap();
        let address = address_from_private_key(&private_key);
        assert_eq!(address, "ICwtdLdGrJJ5bIe7rTWS1dd2_8tpOv1ZZIKnChvb19Y");

        // Wander requires all eight private RSA members. Check that the
        // serialized object contains each one and the Arweave exponent 65537.
        let jwk = private_key_to_jwk_json(&mut private_key).unwrap();
        assert!(jwk.starts_with("{\"kty\":\"RSA\",\"e\":\"AQAB\","));
        for field in ["n", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(jwk.contains(&format!("\"{field}\":\"")));
        }

        // Decode the serialized JWK fields, rebuild and validate the RSA key,
        // and re-check the public address. This catches field-order,
        // base64url, CRT, or integer-encoding mistakes in the exporter.
        let n = rsa::BigUint::from_bytes_be(&decoded_jwk_field(&jwk, "n"));
        let e = rsa::BigUint::from_bytes_be(&decoded_jwk_field(&jwk, "e"));
        let d = rsa::BigUint::from_bytes_be(&decoded_jwk_field(&jwk, "d"));
        let p = rsa::BigUint::from_bytes_be(&decoded_jwk_field(&jwk, "p"));
        let q = rsa::BigUint::from_bytes_be(&decoded_jwk_field(&jwk, "q"));
        let mut rebuilt = RsaPrivateKey::from_components(n, e, d, vec![p, q]).unwrap();
        rebuilt.validate().unwrap();
        rebuilt.precompute().unwrap();
        assert_eq!(decoded_jwk_field(&jwk, "dp"), rebuilt.dp().unwrap().to_bytes_be());
        assert_eq!(decoded_jwk_field(&jwk, "dq"), rebuilt.dq().unwrap().to_bytes_be());
        assert_eq!(
            decoded_jwk_field(&jwk, "qi"),
            rebuilt.qinv().unwrap().to_biguint().unwrap().to_bytes_be()
        );
        assert_eq!(
            address_from_private_key(&rebuilt),
            "ICwtdLdGrJJ5bIe7rTWS1dd2_8tpOv1ZZIKnChvb19Y"
        );
    }

    // Published in the first-generation Keystone rcc_signer RSA recovery
    // test. The source gives this 64-byte seed and its exact RSA modulus;
    // hashing that modulus gives the expected address below. This also proves
    // rsa 0.8.2 reproduces the output originally generated with rsa 0.7.2.
    #[test]
    fn first_generation_keystone_published_vector() {
        let seed = hex_to_bytes(concat!(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1",
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ));
        let address = address_from_keystone_seed(&seed).unwrap();
        assert_eq!(address, "eMCuSpXHZnPZ3AJsWqqs3Td7YrgD4E44fdDyBKxPT0I");
    }

    // BIP39's canonical 256-bit-entropy vector, used only to ensure that the
    // CLI accepts and deterministically processes a valid dummy 24-word phrase.
    #[test]
    fn dummy_24_word_mnemonic_is_stable() {
        let phrase = concat!(
            "abandon abandon abandon abandon abandon abandon abandon abandon ",
            "abandon abandon abandon abandon abandon abandon abandon abandon ",
            "abandon abandon abandon abandon abandon abandon abandon art"
        );
        let address = address_from_mnemonic_empty_passphrase(phrase).unwrap();
        assert_eq!(address, "80eBG6iIco8YSllAcMJjKk4xiAaebCrjuIjncK3Ki68");
    }

    #[test]
    fn validates_public_arweave_addresses() {
        assert_eq!(
            validate_arweave_address("ICwtdLdGrJJ5bIe7rTWS1dd2_8tpOv1ZZIKnChvb19Y\n").unwrap(),
            "ICwtdLdGrJJ5bIe7rTWS1dd2_8tpOv1ZZIKnChvb19Y"
        );
        assert!(validate_arweave_address("not-an-address").is_err());
        assert!(validate_arweave_address("").is_err());
    }

    fn hex_to_bytes(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn decoded_jwk_field(jwk: &str, name: &str) -> Vec<u8> {
        let marker = format!("\"{name}\":\"");
        let value_start = jwk.find(&marker).unwrap() + marker.len();
        let value_end = value_start + jwk[value_start..].find('"').unwrap();
        URL_SAFE_NO_PAD.decode(&jwk[value_start..value_end]).unwrap()
    }
}
