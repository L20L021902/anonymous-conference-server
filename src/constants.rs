use std::net::IpAddr;

pub const PROTOCOL_HEADER: &[u8] = b"\x1CAnonymousConference protocol";
// The handshake starts with character twenty eight (decimal) followed by the string
// 'AnonymousConference protocol'. The leading character is a length prefix.

pub type PeerId = (IpAddr, u16);

pub type ConferenceId = u32;

pub type MessageNonce = u32;

pub type MessageLength = u32;

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
