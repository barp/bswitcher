use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};
use std::time::SystemTime;

pub fn generate_keypair(email: &str, device_name: &str) -> (PKey<Private>, X509) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "SwitchBee")
        .unwrap();
    name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, device_name)
        .unwrap();
    name.append_entry_by_nid(Nid::LOCALITYNAME, email).unwrap();

    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(0).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_after(Asn1Time::days_from_now(365 * 10).as_ref().unwrap())
        .unwrap();
    builder
        .set_not_before(
            Asn1Time::from_unix(
                (SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 60 * 60 * 24)
                    .try_into()
                    .unwrap(),
            )
            .as_ref()
            .unwrap(),
        )
        .unwrap(); // from yesterday

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let certificate: X509 = builder.build();

    (pkey, certificate)
}
