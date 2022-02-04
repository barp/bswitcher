use base64;
use clap::{Parser, Subcommand};

mod api;

use crate::api::api::*;
use crate::api::keygen::*;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Discover,
    Register {
        ip: String,
        email: String,
        password: String,
    },
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Discover => discover_central_units().await.unwrap(),
        Commands::Register {
            ip,
            email,
            password,
        } => {
            let (pk, cert) = generate_keypair("barp12@gmail.com");
            let params = RegisterDeviceParams {
                name: email.to_string(),
                email: email.to_string(),
                key: password.to_string(),
                password: "".to_string(),
                pin: "".to_string(),
                device: "android_REL_HA".to_string(),
                deviceCertificate: base64::encode_config(cert.to_der().unwrap(), base64::URL_SAFE),
            };
            print!(
                "{}",
                String::from_utf8(pk.private_key_to_pem_pkcs8().unwrap()).unwrap()
            );
            println!("{}", String::from_utf8(cert.to_pem().unwrap()).unwrap());
            let client = get_default_https_client().await.unwrap();
            register_device(&client, ip, &params).await.unwrap();
        }
    }
    // let x = get_default_https_client()
    //     .await
    //     .unwrap()
    //     .post("http://asdas.com")
    //     .send()
    //     .await
    //     .unwrap()
    //     .text()
    //     .await
    //     .unwrap();
    // println!("{}", x)
    // discover_central_units().await.unwrap();
}
