use std::fs;
use std::path::Path;

use rcgen::{CertificateParams, CertifiedIssuer, KeyPair};

fn main() -> anyhow::Result<()> {
    let certs_dir = Path::new("certs");
    fs::create_dir_all(certs_dir)?;

    // CA
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, &ca_key)?;
    fs::write(certs_dir.join("ca.pem"), ca.as_ref().pem())?;

    // API server cert (for Meridian control plane)
    let api_key = KeyPair::generate()?;
    let api_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let api_cert = api_params.signed_by(&api_key, &*ca)?;
    fs::write(certs_dir.join("api-cert.pem"), api_cert.pem())?;
    fs::write(certs_dir.join("api-key.pem"), api_key.serialize_pem())?;

    // Backend server certs (server-1 through server-4)
    for i in 1..=4 {
        let key = KeyPair::generate()?;
        let hostname = format!("server-{i}.localhost");
        let params = CertificateParams::new(vec![hostname.clone()])?;
        let cert = params.signed_by(&key, &*ca)?;
        fs::write(certs_dir.join(format!("server-{i}-cert.pem")), cert.pem())?;
        fs::write(
            certs_dir.join(format!("server-{i}-key.pem")),
            key.serialize_pem(),
        )?;
        println!("generated certs for {hostname}");
    }

    println!("all certs written to {}", certs_dir.display());
    println!("\nfiles:");
    for entry in fs::read_dir(certs_dir)? {
        let entry = entry?;
        println!("  {}", entry.file_name().to_string_lossy());
    }

    Ok(())
}
