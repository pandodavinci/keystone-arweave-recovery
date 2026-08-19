use keystone_arweave_checker::{
    keyfile_from_mnemonic_empty_passphrase, validate_arweave_address,
};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use zeroize::Zeroize;

const OUTPUT_PATH: &str = "/output/arweave-keyfile.json";

fn main() -> ExitCode {
    eprintln!("Keystone Arweave PRIVATE keyfile exporter");
    eprintln!("BIP39 passphrase: empty (Keystone default wallet)");
    eprintln!("Network access must remain disabled.");
    eprintln!("The keyfile will be written only after the address MATCHES.\n");

    let expected_address = match prompt_expected_address() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: could not read the expected address: {error}");
            return ExitCode::from(2);
        }
    };

    if Path::new(OUTPUT_PATH).exists() {
        eprintln!("ERROR: output file already exists; refusing to overwrite it.");
        return ExitCode::from(2);
    }

    let mut phrase = match rpassword::prompt_password("Enter the 24-word recovery phrase: ") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: could not read the recovery phrase: {error}");
            return ExitCode::from(2);
        }
    };

    let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    phrase.zeroize();
    let result = keyfile_from_mnemonic_empty_passphrase(&normalized);
    let mut normalized_to_clear = normalized;

    let exit = match result {
        Ok(exported) if exported.address == expected_address => {
            let file_result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(OUTPUT_PATH)
                .and_then(|mut file| {
                    file.write_all(exported.json.as_bytes())?;
                    file.sync_all()
                });

            match file_result {
                Ok(()) => {
                    println!("\nMATCH");
                    println!("Verified address: {}", exported.address);
                    println!("Private keyfile created with mode 0600.");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("\nERROR: address matched but keyfile writing failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Ok(exported) => {
            println!("\nNO MATCH — NO KEYFILE WAS WRITTEN");
            println!("Derived address:  {}", exported.address);
            println!("Expected address: {expected_address}");
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("\nERROR: {error}");
            eprintln!("NO KEYFILE WAS WRITTEN");
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
