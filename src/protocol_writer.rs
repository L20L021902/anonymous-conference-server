use {
    futures::SinkExt,
    crate::constants::{
        ServerToClientMessageType, ConferenceId, SKIP32_KEY, 
    },
    crate::broker::Sender,
};

pub async fn send_message_to_peer(message_type: &ServerToClientMessageType<'_>, mut sender: Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            message.extend(*msg);
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

pub fn obfuscate_conference_id(conference_id: &ConferenceId) -> [u8; 4] {
    let obfuscated_conference_id = skip32::encode(&SKIP32_KEY, *conference_id);
    obfuscated_conference_id.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use futures::channel::mpsc;
    use futures::StreamExt;

    use crate::constants::{ConferenceEncryptionSalt, ConferenceJoinSalt, MessageLength, NumberOfPeers, PacketNonce};

    use super::*;

    #[async_std::test]
    async fn test_send_message_handshake() {
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x00");

        let message = ServerToClientMessageType::HandshakeAcknowledged;
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_created() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x01");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::ConferenceCreated((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_join_salt() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x02");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let expected_conference_join_salt: ConferenceJoinSalt = rng.gen();
        expected.extend_from_slice(&expected_conference_join_salt);

        let message = ServerToClientMessageType::ConferenceJoinSalt((expected_nonce, expected_conference_id, expected_conference_join_salt));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_joined() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x03");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let expected_number_of_peers: NumberOfPeers = rng.gen();
        expected.extend_from_slice(&expected_number_of_peers.to_be_bytes());

        let expected_conference_encryption_salt: ConferenceEncryptionSalt = rng.gen();
        expected.extend_from_slice(&expected_conference_encryption_salt);

        let message = ServerToClientMessageType::ConferenceJoined((expected_nonce, expected_conference_id, expected_number_of_peers, expected_conference_encryption_salt));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_left() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x04");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::ConferenceLeft((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_message_accepted() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x05");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::MessageAccepted((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_restructuring() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x06");

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let expected_number_of_peers: NumberOfPeers = rng.gen();
        expected.extend_from_slice(&expected_number_of_peers.to_be_bytes());

        let message = ServerToClientMessageType::ConferenceRestructuring((expected_conference_id, expected_number_of_peers));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_incoming_message() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x07");

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let expected_message = b"this is a test message".to_vec();
        let expected_message_length: MessageLength = expected_message.len().try_into().unwrap();
        expected.extend_from_slice(&expected_message_length.to_be_bytes());
        expected.extend_from_slice(&expected_message);

        let message = ServerToClientMessageType::IncomingMessage((expected_conference_id, &expected_message));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_general_error() {
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x10");

        let message = ServerToClientMessageType::GeneralError;
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_creation_error() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x11");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let message = ServerToClientMessageType::ConferenceCreationError(expected_nonce);
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_join_salt_error() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x12");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::ConferenceJoinSaltError((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_join_error() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x13");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::ConferenceJoinError((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_leave_error() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x14");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::ConferenceLeaveError((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }

    #[async_std::test]
    async fn test_send_message_conference_message_error() {
        let mut rng = rand::thread_rng();
        let (sender, mut receiver) = mpsc::unbounded();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x15");

        let expected_nonce: PacketNonce = rng.gen();
        expected.extend_from_slice(&expected_nonce.to_be_bytes());

        let expected_conference_id: ConferenceId = rng.gen();
        expected.extend_from_slice(&obfuscate_conference_id(&expected_conference_id));

        let message = ServerToClientMessageType::MessageError((expected_nonce, expected_conference_id));
        assert!(send_message_to_peer(&message, sender).await.is_ok());

        let response = receiver.next().await;
        assert!(response.is_some());
        let result = response.unwrap();
        assert_eq!(result, expected);
    }
}

