use std::net::IpAddr;

pub const PROTOCOL_HEADER: &[u8] = b"\x1CAnonymousConference protocol";
// The handshake starts with character twenty eight (decimal) followed by the string
// 'AnonymousConference protocol'. The leading character is a length prefix.

pub type PeerId = (IpAddr, u16);

pub type ConferenceId = u32;

pub type NumberOfPeers = u32;

pub type PacketNonce = u32;

pub type MessageLength = u32;

pub type PasswordHash = [u8; 32];

pub type ConferenceJoinSalt = [u8; 32];

pub type ConferenceEncryptionSalt = [u8; 32];

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
    GetConferenceJoinSalt = 0x02,
    JoinConference = 0x03,
    LeaveConference = 0x04,
    SendMessage = 0x05,
    Disconnect = 0x06,
}

impl TryFrom<u8> for ClientAction {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == ClientAction::CreateConference as u8 => Ok(ClientAction::CreateConference),
            x if x == ClientAction::GetConferenceJoinSalt as u8 => Ok(ClientAction::GetConferenceJoinSalt),
            x if x == ClientAction::JoinConference as u8 => Ok(ClientAction::JoinConference),
            x if x == ClientAction::LeaveConference as u8 => Ok(ClientAction::LeaveConference),
            x if x == ClientAction::SendMessage as u8 => Ok(ClientAction::SendMessage),
            x if x == ClientAction::Disconnect as u8 => Ok(ClientAction::Disconnect),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Clone)]
pub enum ServerToClientMessageType<'a> {
    HandshakeAcknowledged = 0x00,
    ConferenceCreated((PacketNonce, ConferenceId)) = 0x01,
    ConferenceJoinSalt((PacketNonce, ConferenceId, ConferenceJoinSalt)) = 0x02,
    ConferenceJoined((PacketNonce, ConferenceId, NumberOfPeers, ConferenceEncryptionSalt)) = 0x03,
    ConferenceLeft((PacketNonce, ConferenceId)) = 0x04,
    MessageAccepted((PacketNonce, ConferenceId)) = 0x05,
    ConferenceRestructuring((ConferenceId, NumberOfPeers)) = 0x06,
    IncomingMessage((ConferenceId, &'a Vec<u8>)) = 0x07,

    GeneralError = 0x10,
    ConferenceCreationError(PacketNonce) = 0x11,
    ConferenceJoinSaltError((PacketNonce, ConferenceId)) = 0x12,
    ConferenceJoinError((PacketNonce, ConferenceId)) = 0x13,
    ConferenceLeaveError((PacketNonce, ConferenceId)) = 0x14,
    MessageError((PacketNonce, ConferenceId)) = 0x15,
}

impl ServerToClientMessageType<'_> {
    pub fn value(&self) -> u8 {
        unsafe { *(self as *const Self as *const u8) }
    }
}

#[derive(Debug)]
pub enum Void {}

