use std::net::IpAddr;

pub const PROTOCOL_HEADER: &[u8] = b"\x1CAnonymousConference protocol";
// The handshake starts with character twenty eight (decimal) followed by the string
// 'AnonymousConference protocol'. The leading character is a length prefix.

pub type PeerId = (IpAddr, u16);

pub type ConferenceId = u32;

pub type MessageNonce = u32;

pub type MessageLength = u32;

pub type PasswordHash = [u8; 32];

pub const SKIP32_KEY: [u8; 10] = [0x14, 0xd3, 0xa6, 0x1a, 0xec, 0xe3, 0x8a, 0x66, 0xd2, 0x82];

pub struct ConnectionError {
    pub kind: ConnectionErrorKind,
    pub message: String,
}

pub enum ConnectionErrorKind {
    IoError,
    ProtocolError,
}

#[derive(Copy, Clone)]
pub enum ClientAction {
    CreateConference = 0x01,
    JoinConference = 0x02,
    LeaveConference = 0x03,
    SendMessage = 0x04,
    Disconnect = 0x05,
}

impl TryFrom<u8> for ClientAction {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == ClientAction::CreateConference as u8 => Ok(ClientAction::CreateConference),
            x if x == ClientAction::JoinConference as u8 => Ok(ClientAction::JoinConference),
            x if x == ClientAction::LeaveConference as u8 => Ok(ClientAction::LeaveConference),
            x if x == ClientAction::SendMessage as u8 => Ok(ClientAction::SendMessage),
            x if x == ClientAction::Disconnect as u8 => Ok(ClientAction::Disconnect),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
pub enum ServerToClientMessageType<'a> {
    HandshakeAcknowledged = 0x00,
    ConferenceCreated((&'a PasswordHash, ConferenceId)) = 0x01,
    ConferenceJoined(ConferenceId) = 0x02,
    ConferenceLeft(ConferenceId) = 0x03,
    MessageAccepted((ConferenceId, MessageNonce)) = 0x04,
    IncomingMessage((ConferenceId, &'a Vec<u8>)) = 0x05,

    GeneralError = 0x10,
    ConferenceCreationError(&'a PasswordHash) = 0x11,
    ConferenceJoinError(ConferenceId) = 0x12,
    ConferenceLeaveError(ConferenceId) = 0x13,
    MessageError((ConferenceId, MessageNonce)) = 0x14,
}

impl ServerToClientMessageType<'_> {
    pub fn value(&self) -> u8 {
        unsafe { *(self as *const Self as *const u8) }
    }
}
