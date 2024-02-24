use std::sync::Arc;

use {
    log::{info, error, warn, debug},
    async_std::net::{TcpListener, TcpStream},
    async_std::io::{BufReader, ReadExt, WriteExt},
    async_std::task,
    futures::StreamExt,
};
pub const PROTOCOL_HEADER: &[u8] = b"\x1CAnonymousConference protocol";
// The handshake starts with character twenty eight (decimal) followed by the string
// 'AnonymousConference protocol'. The leading character is a length prefix.

struct ConnectionError {
    kind: ConnectionErrorKind,
    message: String,
}

enum ConnectionErrorKind {
    IoError,
    ProtocolError,
}

struct Peer {
    address: String,
    port: String,
}

struct Conference {
    id: String,
    password_hash: String,
}

pub struct ProtocolManager {
    listening_address: String,
    listening_port: u16,
    peers: Vec<Peer>,
    conferences: Vec<Conference>,
}

impl ProtocolManager {
    pub fn new(listening_address: String, listening_port: u16) -> ProtocolManager {
        ProtocolManager {
            listening_address,
            listening_port,
            peers: Vec::new(),
            conferences: Vec::new(),
        }
    }

    pub async fn enter_main_loop(self: Arc<Self>) {
        let listener = TcpListener::bind(format!("{}:{}", &self.listening_address, &self.listening_port)).await.expect("Could not bind to address");

        listener.incoming().for_each_concurrent(None, |stream| async {
            if let Ok(stream) = stream {
                debug!("Connection established!");
                task::spawn({
                    let protocol_manager = Arc::clone(&self);
                    async move {
                        protocol_manager.handle_connection(stream).await
                    }
                });
            } else {
                warn!("Failed to establish connection");
            }
        })
        .await;
    }

    fn report_error(&self, error: ConnectionError) {
        match error.kind {
            ConnectionErrorKind::IoError => warn!("Connection failed due to IO error: {}", error.message),
            ConnectionErrorKind::ProtocolError => warn!("Connection failed due to protocol error: {}", error.message),
        }
    }

    fn shutdown_connection(&self, stream: TcpStream) {
        if stream.shutdown(std::net::Shutdown::Both).is_err() {
            error!("Failed to close connection");
        }
    }

    async fn handle_connection(&self, stream: TcpStream) {
        let mut buf_reader = BufReader::new(&stream);
        
        if let Err(e) = self.handle_handshake(&mut buf_reader).await {
            self.report_error(e);
            self.shutdown_connection(stream);
            return;
        }

        debug!("Connection handled successfully");
        self.shutdown_connection(stream);
    }

    async fn handle_handshake(&self, reader: &mut BufReader<&TcpStream>) -> Result<(), ConnectionError> {
        let mut protocol_header_buffer: [u8; PROTOCOL_HEADER.len()] = [0; PROTOCOL_HEADER.len()];

        if reader.read_exact(&mut protocol_header_buffer).await.is_err() {
            return Err(ConnectionError {
                kind: ConnectionErrorKind::IoError,
                message: "Failed to read protocol header".to_string(),
            });
        }

        if PROTOCOL_HEADER != protocol_header_buffer {
            return Err(ConnectionError {
                kind: ConnectionErrorKind::ProtocolError,
                message: "Protocol header mismatch".to_string(),
            });
        }

        Ok(())
    }
}
