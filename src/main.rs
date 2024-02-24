use std::sync::Arc;
use log::{info, error, warn};

mod protocol;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7667;

#[async_std::main]
async fn main() {
    env_logger::init();
    info!("AnonymousConference server");
    info!("Starting protocol manager...");
    info!("Starting server on {}:{}", DEFAULT_BIND_ADDRESS, DEFAULT_PORT);
    let protocol_manager = Arc::new(protocol::ProtocolManager::new(DEFAULT_BIND_ADDRESS.to_string(), DEFAULT_PORT));
    protocol_manager.enter_main_loop().await;
}
