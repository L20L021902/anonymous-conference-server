use crate::constants::{
    ConnectionError, ConnectionErrorKind, PacketNonce, MessageLength, ClientAction, PeerId,
    ConferenceId, ConferenceEncryptionSalt, ConferenceJoinSalt, PasswordHash, SKIP32_KEY,
};
use crate::broker::Event;

use async_std::io::BufRead;
use futures::AsyncReadExt;

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
pub async fn read_message(peer_id: &PeerId, stream: &mut (impl BufRead + Unpin)) -> Result<Option<Event>, ConnectionError> {
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

                Ok(Some(Event::NewConference {
                    nonce,
                    peer_id: *peer_id,
                    password_hash,
                    join_salt,
                    encryption_salt,
                }))
            },
            ClientAction::GetConferenceJoinSalt => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;

                Ok(Some(Event::GetConferenceJoinSalt {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                }))
            },
            ClientAction::JoinConference => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;
                let password_hash = read_password_hash(stream).await?;

                Ok(Some(Event::JoinConference {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                    password_hash,
                }))
            },
            ClientAction::LeaveConference => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;

                Ok(Some(Event::LeaveConference {
                    nonce,
                    peer_id: *peer_id,
                    conference_id,
                }))
            },
            ClientAction::SendMessage => {
                let nonce = read_nonce(stream).await?;
                let conference_id = read_conference_id(stream).await?;
                let message_length = read_message_length(stream).await?;
                let message = read_message_body(stream, message_length).await?;

                Ok(Some(Event::Message {
                    nonce,
                    from: *peer_id,
                    to: conference_id,
                    msg: message,
                }))
            },
            ClientAction::Disconnect => {
                Ok(None)
            }
        }
    } else {
        Err(ConnectionError {
            kind: ConnectionErrorKind::ProtocolError,
            message: format!("Invalid client action: {}", client_action[0]),
        })
    }
}

pub fn deobfuscate_conference_id(obfuscated_conference_id: [u8; 4]) -> ConferenceId {
    skip32::decode(&SKIP32_KEY, u32::from_be_bytes(obfuscated_conference_id))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use async_std::io::Cursor;
    use rand::Rng;

    use super::*;

    #[async_std::test]
    async fn test_read_message_create_conference() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        message.extend_from_slice(b"\x01");

        let expected_nonce: PacketNonce = rng.gen();
        message.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_password_hash: PasswordHash = rng.gen();
        message.extend_from_slice(&expected_password_hash);
        let expected_join_salt: ConferenceJoinSalt = rng.gen();
        message.extend_from_slice(&expected_join_salt);
        let expected_encryption_salt: ConferenceEncryptionSalt = rng.gen();
        message.extend_from_slice(&expected_encryption_salt);

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_some());

        let actual_event = actual_event.unwrap();
        match actual_event {
            Event::NewConference { nonce, peer_id, password_hash, join_salt, encryption_salt } => {
                assert_eq!(nonce, expected_nonce);
                assert_eq!(peer_id, expected_peer_id);
                assert_eq!(password_hash, expected_password_hash);
                assert_eq!(join_salt, expected_join_salt);
                assert_eq!(encryption_salt, expected_encryption_salt);
            }
            _ => {
                panic!("Got wrong event type!");
            }
        }
    }

    #[async_std::test]
    async fn test_read_message_get_conference_join_salt() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        message.extend_from_slice(b"\x02");

        let expected_nonce: PacketNonce = rng.gen();
        message.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        message.extend_from_slice(&expected_conference_id.to_be_bytes());

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_some());

        let actual_event = actual_event.unwrap();
        match actual_event {
            Event::GetConferenceJoinSalt { nonce, peer_id, conference_id } => {
                assert_eq!(nonce, expected_nonce);
                assert_eq!(peer_id, expected_peer_id);
                assert_eq!(conference_id, deobfuscate_conference_id(expected_conference_id.to_be_bytes()));
            }
            _ => {
                panic!("Got wrong event type!");
            }
        }
    }

    #[async_std::test]
    async fn test_read_message_join_conference() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        message.extend_from_slice(b"\x03");

        let expected_nonce: PacketNonce = rng.gen();
        message.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        message.extend_from_slice(&expected_conference_id.to_be_bytes());

        let expected_password_hash: PasswordHash = rng.gen();
        message.extend_from_slice(&expected_password_hash);

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_some());

        let actual_event = actual_event.unwrap();
        match actual_event {
            Event::JoinConference { nonce, peer_id, conference_id, password_hash } => {
                assert_eq!(nonce, expected_nonce);
                assert_eq!(peer_id, expected_peer_id);
                assert_eq!(conference_id, deobfuscate_conference_id(expected_conference_id.to_be_bytes()));
                assert_eq!(password_hash, expected_password_hash);
            }
            _ => {
                panic!("Got wrong event type!");
            }
        }
    }

    #[async_std::test]
    async fn test_read_message_leave_conference() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        message.extend_from_slice(b"\x04");

        let expected_nonce: PacketNonce = rng.gen();
        message.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        message.extend_from_slice(&expected_conference_id.to_be_bytes());

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_some());

        let actual_event = actual_event.unwrap();
        match actual_event {
            Event::LeaveConference { nonce, peer_id, conference_id } => {
                assert_eq!(nonce, expected_nonce);
                assert_eq!(peer_id, expected_peer_id);
                assert_eq!(conference_id, deobfuscate_conference_id(expected_conference_id.to_be_bytes()));
            }
            _ => {
                panic!("Got wrong event type!");
            }
        }
    }

    #[async_std::test]
    async fn test_read_message_send_message() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut rng = rand::thread_rng();
        let mut message = Vec::new();
        message.extend_from_slice(b"\x05");

        let expected_nonce: PacketNonce = rng.gen();
        message.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        message.extend_from_slice(&expected_conference_id.to_be_bytes());

        let expected_message = b"this is a test message";
        let expected_message_length: MessageLength = expected_message.len().try_into().unwrap();
        message.extend_from_slice(&expected_message_length.to_be_bytes());
        message.extend_from_slice(&expected_message[..]);

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_some());

        let actual_event = actual_event.unwrap();
        match actual_event {
            Event::Message { nonce, from, to, msg } => {
                assert_eq!(nonce, expected_nonce);
                assert_eq!(from, expected_peer_id);
                assert_eq!(to, deobfuscate_conference_id(expected_conference_id.to_be_bytes()));
                assert_eq!(msg, expected_message);
            }
            _ => {
                panic!("Got wrong event type!");
            }
        }
    }

    #[async_std::test]
    async fn test_read_message_disconnect() {
        let expected_peer_id: PeerId = (std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut message = Vec::new();
        message.extend_from_slice(b"\x06");

        let mut reader = Cursor::new(message);
        let action = read_message(&expected_peer_id, &mut reader).await;
        assert!(action.is_ok());
        let actual_event = action.unwrap();
        assert!(actual_event.is_none());
    }

    #[test]
    fn test_conference_id_deobfuscation() {
        let conference_id: ConferenceId = 1;
        let deobfuscated = deobfuscate_conference_id(conference_id.to_be_bytes());
        assert!(conference_id != deobfuscated);
    } 

}
