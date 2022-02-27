use async_std::fs;
use base64;
use clap::{Parser, Subcommand};
use cli_clipboard;
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::io::prelude::*;

use bswitch::api::*;
use bswitch::bks::keystore::*;
use bswitch::keygen::*;
use bswitch::protocol::*;

// fn textwrap(input: &str) -> String {
//     let mut reader = BufReader::new(input.as_bytes());
//     let mut buf = BufWriter::new(Vec::new());
//     let mut temp: [u8; 64] = [0; 64];
//     let mut firstline = true;
//     loop {
//         match reader.read(&mut temp) {
//             Ok(n) => {
//                 if n == 0 {
//                     break;
//                 }
//                 if !firstline {
//                     buf.write(&['\n' as u8]).unwrap();
//                 }
//                 firstline = false;
//                 buf.write(&temp[..n]).unwrap();
//                 ()
//             }
//             Err(_) => break,
//         }
//     }
//
//     String::from_utf8(buf.into_inner().unwrap()).unwrap()
// }
//
// fn print_pem(header: &str, data: &[u8]) {
//     println!("-----BEGIN {}-----", header);
//     println!("{}", textwrap(&base64::encode(data)));
//     println!("-----END {}-----", header);
// }

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
        registration_name: String,
        email: String,
        password: String,
    },
    SendCommand {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        message: String,
    },
    GetAllUnits {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
    },
    TurnOn {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        #[clap(name = "type")]
        unit_type: i32,
        unit_id: i32,
    },
    TurnOff {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        #[clap(name = "type")]
        unit_type: i32,
        unit_id: i32,
    },
    GetGuestKey {
        apk_path: String,
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
            registration_name,
            email,
            password,
        } => {
            let real_ip = get_cu_ip(ip).await.unwrap();
            let (pk, cert) = generate_keypair(email, registration_name);
            let params = RegisterDeviceParams {
                name: email.to_owned(),
                email: email.to_owned(),
                key: password.to_owned(),
                password: "".to_owned(),
                pin: "".to_owned(),
                device: registration_name.to_owned(),
                device_certificate: base64::encode_config(cert.to_der().unwrap(), base64::URL_SAFE),
            };
            let identity = get_guest_identity().await.unwrap();
            let client = get_default_https_client(identity).await.unwrap();
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
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client.request(message).await.unwrap();
            println!("{}", resp);
        }
        Commands::GetAllUnits {
            ip,
            certificate_path,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client.get_all().await.unwrap();
            for zone in &resp.place.as_ref().unwrap().zones {
                for item in &zone.items {
                    println!("{:?}", item)
                }
            }
        }
        Commands::TurnOn {
            ip,
            certificate_path,
            unit_type,
            unit_id,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client
                .unit_operation(&UnitItemOperation {
                    unit_id: *unit_id,
                    unit_type: *unit_type,
                    new_state: 100,
                })
                .await
                .unwrap();
            println!("{:?}", resp)
        }
        Commands::TurnOff {
            ip,
            certificate_path,
            unit_type,
            unit_id,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client
                .unit_operation(&UnitItemOperation {
                    unit_id: *unit_id,
                    unit_type: *unit_type,
                    new_state: 0,
                })
                .await
                .unwrap();
            println!("{:?}", resp)
        }
        Commands::GetGuestKey { apk_path } => {
            let mut zipfile = zip::ZipArchive::new(std::fs::File::open(apk_path).unwrap()).unwrap();
            let mut data: Vec<u8> = Vec::new();
            zipfile
                .by_name("res/raw/client.bks")
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            let bks = BksKeyStore::load(&mut data.as_slice(), "SwitchBeePrivate".to_string())
                .await
                .unwrap();
            for (_, entry) in bks.entries().iter() {
                let pk = match entry.value() {
                    BksEntryValue::KeyEntry(key) => key.data(),
                    _ => return,
                };
                if entry.cert_chain().len() == 0 {
                    println!("failed to find certificate");
                    return;
                }
                let pk = PKey::private_key_from_pkcs8(pk).unwrap();
                let cert = X509::from_der(&entry.cert_chain()[0].data()).unwrap();
                let pkcs12cert = openssl::pkcs12::Pkcs12::builder()
                    .build("1234", "guest cert", &pk, &cert)
                    .unwrap();
                let key = base64::encode(pkcs12cert.to_der().unwrap());
                println!(
                    "Copy the following to the registration input (should be in your clipboard):"
                );
                println!("{}", key);

                match cli_clipboard::set_contents(key.to_owned()) {
                    Ok(()) => (),
                    Err(e) => println!("failed to copy to clipboard: {:?}", e),
                };
            }
        }
    }
}
