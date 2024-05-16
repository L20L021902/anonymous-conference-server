use async_native_tls::TlsAcceptor;
use async_native_tls::AcceptError;

const PFX_PASS: &str = "password";

pub async fn make_tls_acceptor() -> Result<TlsAcceptor, AcceptError> {
    let pfx = get_cert();
    let config = TlsAcceptor::new(&pfx[..], PFX_PASS).await?;
    Ok(config)
}

fn get_cert() -> Vec<u8> {
    include_bytes!("../certs/cert.pfx").to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_make_tls_acceptor() {
        let result = make_tls_acceptor().await;
        assert!(result.is_ok());
    }
}
