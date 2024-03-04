use std::{sync::Arc, net::IpAddr};

use {
    log::{info, error, warn, debug},
    async_std::net::{TcpListener, TcpStream},
    async_std::io::{BufReader, ReadExt, WriteExt},
    async_std::task,
    async_std::prelude::*,
    futures::{StreamExt, channel::mpsc, sink::SinkExt},
    crate::constants::{PROTOCOL_HEADER, ConnectionError, ConnectionErrorKind, ClientAction, PeerId, ConferenceId, MessageNonce, MessageLength},
    crate::broker::{Broker, Event, Sender},
};

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
    let mut reader = BufReader::new(&*stream);

    // check handshake
    if let Err(e) = handle_handshake(&mut reader).await {
        report_error(e);
        shutdown_connection(stream);
        return;
    }

    let peer_addr = stream.peer_addr().unwrap();
    let peer_id = (peer_addr.ip(), peer_addr.port());
    broker.send(Event::NewPeer {
        peer_id,
        stream: Arc::clone(&stream),
    }).await.unwrap();

    loop {
        match read_message(&mut broker, &peer_id, &mut reader).await {
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
                broker.send(Event::RemovePeer {
                    peer_id,
                }).await.unwrap();
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
async fn read_message(broker: &mut Sender<Event>, peer_id: &PeerId, stream: &mut BufReader<&TcpStream>) -> Result<bool, ConnectionError> {
    let mut client_action: [u8; 1] = [0; 1];
    if let Err(e) = stream.read_exact(&mut client_action).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read client action: {}", e),
        });
    }

    if let Ok(client_action) = ClientAction::try_from(client_action[0]) {
        match client_action {
            ClientAction::CreateConference => {
                let mut password_hash: [u8; 32] = [0; 32];
                if let Err(e) = stream.read_exact(&mut password_hash).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read conference password hash: {}", e),
                    });
                }
                broker.send(Event::NewConference {
                    peer_id: *peer_id,
                    password_hash,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::JoinConference => {
                let mut conference_id: [u8; 4] = [0; 4];
                let mut password_hash: [u8; 32] = [0; 32];
                if let Err(e) = stream.read_exact(&mut conference_id).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read conference id: {}", e),
                    });
                }
                if let Err(e) = stream.read_exact(&mut password_hash).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read conference password hash: {}", e),
                    });
                }
                let conference_id = ConferenceId::from_be_bytes(conference_id);
                broker.send(Event::JoinConference {
                    peer_id: *peer_id,
                    conference_id,
                    password_hash,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::LeaveConference => {
                let mut conference_id: [u8; 4] = [0; 4];
                if let Err(e) = stream.read_exact(&mut conference_id).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read conference id: {}", e),
                    });
                }
                let conference_id = ConferenceId::from_be_bytes(conference_id);
                broker.send(Event::LeaveConference {
                    peer_id: *peer_id,
                    conference_id,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::SendMessage => {
                let mut buffer: [u8; 4] = [0; 4];

                if let Err(e) = stream.read_exact(&mut buffer).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read conference id: {}", e),
                    });
                }
                let conference_id = ConferenceId::from_be_bytes(buffer);

                if let Err(e) = stream.read_exact(&mut buffer).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read message nonce: {}", e),
                    });
                }
                let message_nonce = MessageNonce::from_be_bytes(buffer);

                if let Err(e) = stream.read_exact(&mut buffer).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read message length: {}", e),
                    });
                }
                let message_length = MessageLength::from_be_bytes(buffer);

                let mut message: Vec<u8> = Vec::with_capacity(message_length as usize);
                if let Err(e) = stream.read_exact(&mut message).await {
                    return Err(ConnectionError {
                        kind: ConnectionErrorKind::IoError,
                        message: format!("Failed to read message body: {}", e),
                    });
                }

                broker.send(Event::Message {
                    from: *peer_id,
                    to: conference_id,
                    nonce: message_nonce,
                    msg: message,
                }).await.unwrap();

                Ok(true)
            },
            ClientAction::Disconnect => {
                broker.send(Event::RemovePeer {
                    peer_id: *peer_id,
                }).await.unwrap();

                Ok(false)
            }
        }
    } else {
        Err(ConnectionError {
            kind: ConnectionErrorKind::ProtocolError,
            message: "Invalid client action".to_string(),
        })
    }
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
pub enum ServerToClientMessageType<'a> {
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

pub async fn send_message_to_peer(message_type: ServerToClientMessageType<'_>, sender: &Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    todo!()
}
