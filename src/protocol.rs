use {
    log::{warn, debug},
    async_std::net::{TcpListener, TcpStream},
    async_std::io::{BufReader, BufRead},
    async_std::task,
    async_native_tls::TlsStream,
    futures::{StreamExt, channel::mpsc, sink::SinkExt, AsyncReadExt, select, FutureExt},
    crate::constants::{
        PROTOCOL_HEADER,
        ConnectionError,
        ConnectionErrorKind,
        Void,
    },
    crate::protocol_reader::read_message,
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


