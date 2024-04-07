use crate::constants::{
    ConnectionError, ConnectionErrorKind, PacketNonce, MessageLength, ClientAction, PeerId,
    ConferenceId, ConferenceEncryptionSalt, ConferenceJoinSalt, PasswordHash, SKIP32_KEY,
};
use crate::broker::{Event, Sender};

use async_std::io::BufRead;
use futures::{AsyncReadExt, SinkExt};

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
pub async fn read_message(broker: &mut Sender<Event>, peer_id: &PeerId, stream: &mut (impl BufRead + Unpin)) -> Result<bool, ConnectionError> {
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

fn deobfuscate_conference_id(obfuscated_conference_id: [u8; 4]) -> ConferenceId {
    skip32::decode(&SKIP32_KEY, u32::from_be_bytes(obfuscated_conference_id))
}
