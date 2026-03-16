use std::io;

use rcgen::{CertificateParams, CertifiedIssuer, KeyPair};
use tokio::net::TcpListener;

pub struct TestCerts {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

pub fn generate_test_certs(hostname: &str) -> TestCerts {
    // CA (self-signed)
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, &ca_key).unwrap();
    let ca_cert_pem = ca.as_ref().pem();

    // Server cert signed by CA
    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec![hostname.to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &*ca).unwrap();

    // Client cert signed by CA
    let client_key = KeyPair::generate().unwrap();
    let client_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
    let client_cert = client_params.signed_by(&client_key, &*ca).unwrap();

    TestCerts {
        ca_cert_pem,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

/// Find a free TCP port by binding to :0
pub async fn free_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
