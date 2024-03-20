use async_native_tls::TlsAcceptor;
use async_native_tls::AcceptError;
use async_std::fs::File;

const PFX_PASS: &str = "password";

pub async fn make_tls_acceptor(pfx_file: &str) -> Result<TlsAcceptor, AcceptError> {
    let pfx_file = File::open(pfx_file).await.expect("could not find .pfx file");
    let config = TlsAcceptor::new(pfx_file, PFX_PASS).await?;
    Ok(config)
}
