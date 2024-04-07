use log::info;
use crate::protocol::enter_main_loop;

mod constants;
mod tls;
mod protocol_reader;
mod protocol;
mod broker;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7667;
const PFX_FILE: &str = "certs/cert.pfx";

#[async_std::main]
async fn main() {
    env_logger::init();
    info!("AnonymousConference server");
    info!("Starting protocol manager...");
    info!("Starting server on {}:{}", DEFAULT_BIND_ADDRESS, DEFAULT_PORT);
    enter_main_loop(DEFAULT_BIND_ADDRESS.to_string(), DEFAULT_PORT, PFX_FILE).await;
}
