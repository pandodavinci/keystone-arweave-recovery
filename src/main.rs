use keystone_arweave_checker::{
    address_from_mnemonic_empty_passphrase, validate_arweave_address,
};
use std::io::{self, Write};
use std::process::ExitCode;
use zeroize::Zeroize;

fn main() -> ExitCode {
    eprintln!("Keystone Arweave address checker");
    eprintln!("BIP39 passphrase: empty (the Keystone default wallet)");
    eprintln!("The expected address is public; the phrase will be hidden.");
    eprintln!("RSA derivation can take roughly 5-60 seconds.\n");

    let expected_address = match prompt_expected_address() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: could not read the expected address: {error}");
            return ExitCode::from(2);
        }
    };

    let mut phrase = match rpassword::prompt_password("Enter the 24-word recovery phrase: ") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: could not read the recovery phrase: {error}");
            return ExitCode::from(2);
        }
    };

    // Normalize ordinary whitespace without changing the BIP39 words.
    let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    phrase.zeroize();

    let result = address_from_mnemonic_empty_passphrase(&normalized);
    let mut normalized_to_clear = normalized;

    let exit = match result {
        Ok(derived) => {
            println!("\nDerived address:  {derived}");
            println!("Expected address: {expected_address}");
            if derived == expected_address {
                println!("\nMATCH");
                ExitCode::SUCCESS
            } else {
                println!("\nNO MATCH");
                ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("\nERROR: {error}");
            ExitCode::from(2)
        }
    };

    normalized_to_clear.zeroize();
    exit
}

fn prompt_expected_address() -> Result<String, Box<dyn std::error::Error>> {
    eprint!("Enter the expected public Arweave address: ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    validate_arweave_address(&input)
}
