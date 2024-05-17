use log::{error, info};
use crate::protocol::enter_main_loop;

mod constants;
mod tls;
mod protocol_reader;
mod protocol_writer;
mod protocol;
mod broker;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7667;

#[async_std::main]
async fn main() {
    env_logger::init();
    info!("AnonymousConference server");
    info!("Starting protocol manager...");
    let mut bind_address = DEFAULT_BIND_ADDRESS.to_string();
    let mut bind_port = DEFAULT_PORT;
    let mut args = std::env::args().skip(1); // skip binary name
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind-address" => {
                if let Some(address) = args.next() {
                    bind_address = address.to_string();
                }
            }
            "--bind-port" => {
                if let Some(port) = args.next() {
                    bind_port = port.parse().unwrap();
                }
            }
            _ => {
                error!("Unknown argument: {}", arg);
                return;
            }
        }
    }
    info!("Starting server on {}:{}", bind_address, bind_port);
    enter_main_loop(bind_address, bind_port).await;
}
