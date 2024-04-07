use {
    log::{info, error, warn, debug},
    async_std::net::{TcpListener, TcpStream},
    async_std::io::{BufReader, BufRead},
    async_std::task,
    async_native_tls::TlsStream,
    futures::{StreamExt, channel::mpsc, sink::SinkExt, AsyncReadExt, select, FutureExt},
    crate::constants::{
        PROTOCOL_HEADER,
        ConnectionError,
        ConnectionErrorKind,
        ClientAction,
        PeerId,
        ConferenceId,
        PacketNonce,
        MessageLength,
        ServerToClientMessageType,
        SKIP32_KEY,
        ConferenceEncryptionSalt,
        ConferenceJoinSalt,
        PasswordHash,
        Void,
    },
    crate::broker::{Broker, Event, Sender},
    crate::tls,
};

async fn read_stdio(mut sender: Sender<Event>, shutdown_sender: Sender<Void>) {
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
                drop(shutdown_sender); // first we stop accepting new clients
                sender.send(Event::CleanShutdown).await.unwrap(); // then we notify the sender to shutdown
                break;
            },
            _ => (),
        }
        input.clear();
    }
}

pub async fn enter_main_loop(listening_address: String, listening_port: u16, pfx_file: &str) {
    let tls_acceptor = tls::make_tls_acceptor(pfx_file).await.expect("Could not create TLS acceptor");
    let listener = TcpListener::bind(format!("{}:{}", &listening_address, &listening_port)).await.expect("Could not bind to address");
    let (broker_sender, broker_receiver) = mpsc::unbounded();
    let broker = Broker::new(broker_receiver, broker_sender.clone());
    let broker_handle = task::spawn(broker.broker_loop());
    let (shutdown_sender, mut shutdown_receiver) = mpsc::unbounded::<Void>();

    // start async io for stdin
    task::spawn(read_stdio(broker_sender.clone(), shutdown_sender));

    let mut incoming = listener.incoming();
    loop {
        select! {
            stream = incoming.next().fuse() => match stream {
                Some(stream) => match stream {
                    Ok(stream) => {
                        debug!("Connection established!");
                        let acceptor = tls_acceptor.clone();
                        let broker_sender_copy = broker_sender.clone();
                        task::spawn(async move {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                debug!("TLS handshake completed");
                                handle_connection(broker_sender_copy, stream).await
                            } else {
                                warn!("Failed to establish TLS connection");
                            };
                        });
                    },
                    Err(_) => {
                        warn!("Failed to establish connection");
                    },
                },
                None => break,
            },
            void = shutdown_receiver.next().fuse() => match void {
                Some(void) => match void {}, // compile time assert
                None => break,
            },
        }
    }

    drop(broker_sender);
    debug!("Waiting for broker to finish");
    broker_handle.await;
    debug!("Main loop exited");
}

async fn handle_connection(mut broker: Sender<Event>, stream: TlsStream<TcpStream>) {
    let peer_addr = stream.get_ref().peer_addr().unwrap();
    let peer_id = (peer_addr.ip(), peer_addr.port());
    let (read_stream, write_stream) = stream.split();
    let mut reader = BufReader::new(read_stream);

    // check handshake
    if let Err(e) = handle_handshake(&mut reader).await {
        report_error(e);
        return;
    }

    broker.send(Event::NewPeer {
        peer_id,
        stream: write_stream,
    }).await.unwrap();

    loop {
        match read_message(&mut broker, &peer_id, &mut reader).await {
            Ok(true) => {
                // keep connection open
                continue;
            },
            Ok(false) => {
                // close connection
                return;
            },
            Err(e) => {
                report_error(e);
                broker.send(Event::RemovePeer {
                    peer_id,
                }).await.unwrap();
                return;
            },
        }
    }
}

async fn read_nonce(reader: &mut (impl BufRead + Unpin)) -> Result<PacketNonce, ConnectionError> {
    let mut buffer: [u8; std::mem::size_of::<PacketNonce>()] = [0; std::mem::size_of::<PacketNonce>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read packet nonce: {}", e),
        });
    }

    Ok(PacketNonce::from_be_bytes(buffer))
}

async fn read_message_length(reader: &mut (impl BufRead + Unpin)) -> Result<MessageLength, ConnectionError> {
    let mut buffer: [u8; std::mem::size_of::<MessageLength>()] = [0; std::mem::size_of::<MessageLength>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read message length: {}", e),
        });
    }

    Ok(MessageLength::from_be_bytes(buffer))
}

async fn read_password_hash(reader: &mut (impl BufRead + Unpin)) -> Result<PasswordHash, ConnectionError> {
    let mut buffer: PasswordHash = [0; std::mem::size_of::<PasswordHash>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read conference password hash: {}", e),
        });
    }

    Ok(buffer)
}

async fn read_join_salt(reader: &mut (impl BufRead + Unpin)) -> Result<ConferenceJoinSalt, ConnectionError> {
    let mut buffer: ConferenceJoinSalt = [0; std::mem::size_of::<ConferenceJoinSalt>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read conference join salt: {}", e),
        });
    }

    Ok(buffer)
}

async fn read_encryption_salt(reader: &mut (impl BufRead + Unpin)) -> Result<ConferenceEncryptionSalt, ConnectionError> {
    let mut buffer: ConferenceEncryptionSalt = [0; std::mem::size_of::<ConferenceEncryptionSalt>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read conference encryption salt: {}", e),
        });
    }

    Ok(buffer)
}

async fn read_conference_id(reader: &mut (impl BufRead + Unpin)) -> Result<ConferenceId, ConnectionError> {
    let mut buffer: [u8; std::mem::size_of::<ConferenceId>()] = [0; std::mem::size_of::<ConferenceId>()];
    if let Err(e) = reader.read_exact(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read conference id: {}", e),
        });
    }

    Ok(deobfuscate_conference_id(buffer))
}

async fn read_message_body(reader: &mut (impl BufRead + Unpin), message_length: MessageLength) -> Result<Vec<u8>, ConnectionError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(message_length as usize);
    if let Err(e) = reader.take(message_length.into()).read_to_end(&mut buffer).await {
        return Err(ConnectionError {
            kind: ConnectionErrorKind::IoError,
            message: format!("Failed to read message body: {}", e),
        });
    }

    Ok(buffer)
}

/// Reads a message from the peer.
/// returns true if the connection should be kept open, false if it should be closed.
///
/// * `stream`: The stream to read from.
async fn read_message(broker: &mut Sender<Event>, peer_id: &PeerId, stream: &mut (impl BufRead + Unpin)) -> Result<bool, ConnectionError> {
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
                let nonce = read_nonce(stream).await?;
                let password_hash = read_password_hash(stream).await?;
                let join_salt = read_join_salt(stream).await?;
                let encryption_salt = read_encryption_salt(stream).await?;

                broker.send(Event::NewConference {
                    nonce,
                    peer_id: *peer_id,
                    password_hash,
                    join_salt,
                    encryption_salt,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::GetConferenceJoinSalt => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;

                broker.send(Event::GetConferenceJoinSalt {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::JoinConference => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;
                let password_hash = read_password_hash(stream).await?;

                broker.send(Event::JoinConference {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                    password_hash,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::LeaveConference => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;

                broker.send(Event::LeaveConference {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                }).await.unwrap();
                Ok(true)
            },
            ClientAction::SendMessage => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;
                let message_length = read_message_length(stream).await?;
                let message = read_message_body(stream, message_length).await?;

                broker.send(Event::Message {
                    nonce,
                    from: *peer_id,
                    to: conference_id,
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
            message: format!("Invalid client action: {}", client_action[0]),
        })
    }
}

fn report_error(error: ConnectionError) {
    match error.kind {
        ConnectionErrorKind::IoError => warn!("Connection failed due to IO error: {}", error.message),
        ConnectionErrorKind::ProtocolError => warn!("Connection failed due to protocol error: {}", error.message),
    }
}

async fn handle_handshake(reader: &mut (impl BufRead + Unpin)) -> Result<(), ConnectionError> {
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

pub async fn send_message_to_peer(message_type: ServerToClientMessageType<'_>, mut sender: Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut message = vec![message_type.value()];
    match message_type {
        ServerToClientMessageType::HandshakeAcknowledged => {
            // no additional data
        },
        ServerToClientMessageType::ConferenceCreated((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::ConferenceJoinSalt((nonce, conference_id, conference_join_salt)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
            message.extend(conference_join_salt);
        },
        ServerToClientMessageType::ConferenceJoined((nonce, conference_id, number_of_peers, encryption_salt)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
            message.extend(number_of_peers.to_be_bytes());
            message.extend(encryption_salt);
        },
        ServerToClientMessageType::ConferenceLeft((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::MessageAccepted((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::ConferenceRestructuring((conference_id, number_of_peers)) => {
            message.extend(obfuscate_conference_id(conference_id));
            message.extend(number_of_peers.to_be_bytes());
        },
        ServerToClientMessageType::IncomingMessage((conference_id, msg)) => {
            let message_length: u32 = msg.len().try_into()?;
            message.extend(obfuscate_conference_id(conference_id));
            message.extend(message_length.to_be_bytes());
            message.extend(msg);
        },
        ServerToClientMessageType::GeneralError => {
            // no additional data
        },
        ServerToClientMessageType::ConferenceCreationError(nonce) => {
            message.extend(nonce.to_be_bytes());
        },
        ServerToClientMessageType::ConferenceJoinSaltError((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::ConferenceJoinError((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::ConferenceLeaveError((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
        ServerToClientMessageType::MessageError((nonce, conference_id)) => {
            message.extend(nonce.to_be_bytes());
            message.extend(obfuscate_conference_id(conference_id));
        },
    }

    sender.send(message).await?;
    Ok(())
}

fn obfuscate_conference_id(conference_id: ConferenceId) -> [u8; 4] {
    let obfuscated_conference_id = skip32::encode(&SKIP32_KEY, conference_id);
    obfuscated_conference_id.to_be_bytes()
}

fn deobfuscate_conference_id(obfuscated_conference_id: [u8; 4]) -> ConferenceId {
    skip32::decode(&SKIP32_KEY, u32::from_be_bytes(obfuscated_conference_id))
}
