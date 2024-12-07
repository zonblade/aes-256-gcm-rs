use aes_256_gcm::Client;

fn basic_encrypt_decrypt() {
    let client = Client::new("my secret");

    let encrypted = client.encrypt("Hello, World!", None);
    let enc_data = match encrypted {
        Ok(data) => data,
        Err(e) => {
            // handle your error here
            panic!("Error: {:?}", e)
        }
    };
    println!("Encrypted: {:?}", enc_data);

    let decrypted = client.decrypt::<String>(&enc_data);

    let dec_data = match decrypted {
        Ok(data) => data,
        Err(e) => {
            // handle your error here
            panic!("Error: {:?}", e)
        }
    };

    println!("Decrypted: {:?}", dec_data);
}

fn basic_encrypt_decrypt_non_panic() -> Result<(), String> {
    let client = match Client::try_new("my secret") {
        Ok(data) => data,
        Err(e) => return Err(e)
    };

    let encrypted = client.encrypt("Hello, World!", None);
    let enc_data = match encrypted {
        Ok(data) => data,
        Err(e) => return Err(format!("Error: {:?}", e))
    };
    println!("Encrypted: {:?}", enc_data);

    let decrypted = client.decrypt::<String>(&enc_data);

    let dec_data = match decrypted {
        Ok(data) => data,
        Err(e) => return Err(format!("Error: {:?}", e))
    };

    println!("Decrypted: {:?}", dec_data);

    Ok(())
}

fn main(){
    // To demonstrate basic encrypt and decrypt
    basic_encrypt_decrypt();

    // To demonstrate basic ecrypt and decrypt (non-panic version)
    if let Err(e) = basic_encrypt_decrypt_non_panic() {
        eprintln!("encrypt decrypt is error: {}", e);
    }
}
