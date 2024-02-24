use std::sync::Arc;

mod protocol;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7667;

#[async_std::main]
async fn main() {
    println!("AnonymousConference server");
    println!("Starting protocol manager...");
    println!("Starting server on {}:{}", DEFAULT_BIND_ADDRESS, DEFAULT_PORT);
    let protocol_manager = Arc::new(protocol::ProtocolManager::new(DEFAULT_BIND_ADDRESS.to_string(), DEFAULT_PORT));
    protocol_manager.enter_main_loop().await;
}
