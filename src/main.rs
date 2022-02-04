use async_std::fs;
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
        #[clap(long)]
        ip: Option<String>,
        email: String,
        password: String,
    },
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Discover => {
            let cus = discover_central_units(false).await.unwrap();
            println!("{:?}", cus)
        }
        Commands::Register {
            ip,
            email,
            password,
        } => {
            let real_ip = match ip {
                Some(p) => p.to_string(),
                None => {
                    let cu = discover_central_units(true).await.unwrap();
                    if cu.len() < 1 {
                        panic!("no central unit found")
                    }
                    cu[0].CUIP.to_owned()
                }
            };
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
            println!("saving private key in device.key");
            let pkcs12cert = openssl::pkcs12::Pkcs12::builder()
                .build("1234", "device cert", &pk, &cert)
                .unwrap();
            fs::write("./device.key", pkcs12cert.to_der().unwrap())
                .await
                .unwrap();
            let client = get_default_https_client().await.unwrap();
            let resp = register_device(&client, &real_ip, &params).await.unwrap();
            println!("resp: {:?}", resp);
        }
    }
}
