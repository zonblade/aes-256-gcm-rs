use aes_256_gcm::Client;
fn main(){
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