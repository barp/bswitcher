use async_std::fs;
use async_std::prelude::*;
use base64;
use clap::{Parser, Subcommand};
use hexplay::HexViewBuilder;

mod api;

use crate::api::api::*;
use crate::api::keygen::*;
use crate::api::protocol::*;

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
    SendCommand {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        message: String,
    },
}

async fn get_cu_ip(ip: &Option<String>) -> Result<String> {
    Ok(match ip {
        Some(p) => p.to_string(),
        None => {
            let cu = discover_central_units(true).await?;
            if cu.len() < 1 {
                panic!("no central unit found")
            }
            cu[0].CUIP.to_owned()
        }
    })
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
            let real_ip = get_cu_ip(ip).await.unwrap();
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
            let client = get_default_https_client().await.unwrap();
            let resp = register_device(&client, &real_ip, &params).await.unwrap();
            println!("resp: {:?}", resp);
            println!("saving private key in device.key");
            let pkcs12cert = openssl::pkcs12::Pkcs12::builder()
                .build("1234", "device cert", &pk, &cert)
                .unwrap();
            fs::write("./device.key", pkcs12cert.to_der().unwrap())
                .await
                .unwrap();
        }
        Commands::SendCommand {
            ip,
            certificate_path,
            message,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let message = MessageWrapper::new(MessageType::Request, 1, message.to_string());
            let message = create_prefixed_message(&message.serialize());
            let view = HexViewBuilder::new(&message)
                .address_offset(0)
                .row_width(16)
                .finish();
            println!("{}", view);
            let id = get_device_identity(certificate_path).await.unwrap();
            let mut stream = get_async_api_stream(ip, id).await;
            stream.write_all(&message).await.unwrap();
            let buf = read_prefixed_message(&mut stream).await.unwrap();
            let view = HexViewBuilder::new(&buf)
                .address_offset(0)
                .row_width(16)
                .finish();
            println!("{}", view);
            let response = MessageWrapper::deserialize(&buf).unwrap();
            println!("{}", response.message());
        }
    }
}
