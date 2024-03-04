use std::{sync::Arc, net::IpAddr};

use futures::AsyncWriteExt;

use {
    log::{info, error, warn, debug},
    async_std::net::{TcpListener, TcpStream},
    async_std::io::{BufReader, ReadExt, WriteExt},
    async_std::task,
    async_std::prelude::*,
    futures::{StreamExt, channel::mpsc, sink::SinkExt},
    crate::broker::{Broker, Event, Sender, Void},
};

pub const PROTOCOL_HEADER: &[u8] = b"\x1CAnonymousConference protocol";
// The handshake starts with character twenty eight (decimal) followed by the string
// 'AnonymousConference protocol'. The leading character is a length prefix.

pub type PeerId = (IpAddr, u16);

pub type ConferenceId = u32;

struct ConnectionError {
    kind: ConnectionErrorKind,
    message: String,
}

enum ConnectionErrorKind {
    IoError,
    ProtocolError,
}

async fn read_stdio(mut sender: Sender<Event>) {
    let mut input = String::new();
    loop {
        async_std::io::stdin().read_line(&mut input).await.unwrap();
        input = input.trim().to_string();
        match input.as_str() {
            "peers" => {
                sender.send(Event::ListPeers).await.unwrap();
            },
            "conferences" => {
                sender.send(Event::ListConferences).await.unwrap();
            },
            "test" => {
                debug!("Sending test message");
            },
            "exit" => {
                sender.send(Event::CleanShutdown).await.unwrap();
                break;
            },
            _ => (),
        }
        input.clear();
    }
}

pub async fn enter_main_loop(listening_address: String, listening_port: u16) {
    let listener = TcpListener::bind(format!("{}:{}", &listening_address, &listening_port)).await.expect("Could not bind to address");
    let (broker_sender, broker_receiver) = mpsc::unbounded();
    let broker = Broker::new(broker_receiver, broker_sender.clone());
    let broker_handle = task::spawn(broker.broker_loop());

    // start async io for stdin
    task::spawn(read_stdio(broker_sender.clone()));

    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        if let Ok(stream) = stream {
            debug!("Connection established!");
            let broker_sender_copy = broker_sender.clone();
            task::spawn(async move {
                handle_connection(broker_sender_copy, stream).await
            });
        } else {
            warn!("Failed to establish connection");
        }
    }
    drop(broker_sender);
    broker_handle.await;
}

async fn handle_connection(mut broker: Sender<Event>, stream: TcpStream) {
    let stream = Arc::new(stream);
    let mut buf_reader = BufReader::new(&*stream);

    // check handshake
    if let Err(e) = handle_handshake(&mut buf_reader).await {
        report_error(e);
        shutdown_connection(stream);
        return;
    }

    let peer_addr = stream.peer_addr().unwrap();
    broker.send(Event::NewPeer {
        peer_id: (peer_addr.ip(), peer_addr.port()),
        stream: Arc::clone(&stream),
    }).await.unwrap();

    // read incoming messages from the peer
    loop {
        match read_message(&stream).await {
            Ok(true) => {
                // keep connection open
                continue;
            },
            Ok(false) => {
                // close connection
                shutdown_connection(stream);
                return;
            },
            Err(e) => {
                report_error(e);
                shutdown_connection(stream);
                return;
            },
        }
    }
}

/// Reads a message from the peer.
/// returns true if the connection should be kept open, false if it should be closed.
///
/// * `stream`: The stream to read from.
async fn read_message(stream: &TcpStream) -> Result<bool, ConnectionError> {
    todo!()
}

fn report_error(error: ConnectionError) {
    match error.kind {
        ConnectionErrorKind::IoError => warn!("Connection failed due to IO error: {}", error.message),
        ConnectionErrorKind::ProtocolError => warn!("Connection failed due to protocol error: {}", error.message),
    }
}

fn shutdown_connection(stream: Arc<TcpStream>) {
    if stream.shutdown(std::net::Shutdown::Both).is_err() {
        error!("Failed to close connection");
    }
}

async fn handle_handshake(reader: &mut BufReader<&TcpStream>) -> Result<(), ConnectionError> {
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

#[repr(u8)]
pub enum MessageType<'a> {
    HandshakeAcknowledged = 0x00,
    ConferenceCreated(u32) = 0x01,
    ConferenceJoined = 0x02,
    ConferenceLeft = 0x03,
    MessageAccepted = 0x04,
    IncomingMessage(&'a Vec<u8>) = 0x05,

    GeneralError = 0x10,
    ConferenceCreationError = 0x11,
    ConferenceJoinError = 0x12,
    ConferenceLeaveError = 0x13,
    MessageError = 0x14,
}

pub async fn send_message_to_peer(message_type: MessageType<'_>, sender: &Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    todo!()
}
