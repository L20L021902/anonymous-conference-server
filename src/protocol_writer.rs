use {
    futures::SinkExt,
    crate::constants::{
        ServerToClientMessageType, ConferenceId, SKIP32_KEY, 
    },
    crate::broker::Sender,
};

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

