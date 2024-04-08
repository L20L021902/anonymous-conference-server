use std::collections::hash_map::{Entry, HashMap};
use async_native_tls::TlsStream;
use async_std::{prelude::*, net::TcpStream};
use log::{warn, info, debug};
use futures::{channel::mpsc, io::WriteHalf, AsyncWriteExt};
use futures::sink::SinkExt;
use async_std::task::{self, JoinHandle};
use constant_time_eq::constant_time_eq_32;

use crate::constants::{ConferenceEncryptionSalt, ConferenceId, ConferenceJoinSalt, PacketNonce, PasswordHash, PeerId, ServerToClientMessageType, NumberOfPeers};
use crate::protocol_writer::send_message_to_peer;

struct Conference {
    id: ConferenceId,
    password_hash: PasswordHash,
    peers: Vec<PeerId>,
    join_salt: ConferenceJoinSalt,
    encryption_salt: ConferenceEncryptionSalt,
}

impl Conference {
    fn remove_peer(&mut self, peer_id: PeerId) -> bool {
        if let Some(pos) = self.peers.iter().position(|&x| x == peer_id) {
            self.peers.remove(pos);
            return true;
        }
        false
    }
}

#[derive(Debug)]
pub enum Event {
    NewPeer {
        peer_id: PeerId,
        stream: WriteHalf<TlsStream<TcpStream>>,
    },
    RemovePeer {
        peer_id: PeerId,
    },
    NewConference {
        nonce: PacketNonce,
        peer_id: PeerId,
        password_hash: [u8; 32],
        join_salt: ConferenceJoinSalt,
        encryption_salt: ConferenceEncryptionSalt,
    },
    GetConferenceJoinSalt {
        nonce: PacketNonce,
        peer_id: PeerId,
        conference_id: ConferenceId,
    },
    JoinConference {
        nonce: PacketNonce,
        peer_id: PeerId,
        conference_id: ConferenceId,
        password_hash: [u8; 32],
    },
    LeaveConference {
        nonce: PacketNonce,
        peer_id: PeerId,
        conference_id: ConferenceId,
    },
    Message {
        nonce: PacketNonce,
        from: PeerId,
        to: ConferenceId,
        msg: Vec<u8>,
    },
    ListPeers,
    ListConferences,
    CleanShutdown,
}

pub type Sender<T> = mpsc::UnboundedSender<T>;
pub type Receiver<T> = mpsc::UnboundedReceiver<T>;

struct PeerManager {
    broker_sender: Sender<Event>,
    peers: HashMap<PeerId, Sender<Vec<u8>>>,
    writers: Vec<JoinHandle<()>>,
}

impl PeerManager {
    pub fn new(broker_sender: Sender<Event>) -> Self {
        Self {
            broker_sender,
            peers: HashMap::new(),
            writers: Vec::new(),
        }
    }

    /// Add new peer, returns `true` if peer was added, otherwise returns `false`
    pub fn add_peer(&mut self, peer_id: PeerId, stream: WriteHalf<TlsStream<TcpStream>>) -> bool {
        match self.peers.entry(peer_id) {
            Entry::Vacant(entry) => {
                let (client_sender, client_receiver) = mpsc::unbounded();
                entry.insert(client_sender);
                info!("Added new peer {:?}", peer_id);
                let mut sender = self.broker_sender.clone();
                let writer_handle = task::spawn(async move {
                    if let Err(e) = connection_writer_loop(client_receiver, stream).await {
                        warn!("Error in connection writer loop: {}", e);
                        sender.send(Event::RemovePeer { peer_id }).await.unwrap(); // TODO: check
                    }
                });
                self.writers.push(writer_handle);
                true
            },
            Entry::Occupied(_) => {
                warn!("Peer already exists: {:?}", peer_id);
                false
            },
        }

    }

    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        debug!("Removed peer {:?}", peer_id);
    }

    async fn send_message(&self, peer_id: &PeerId, message_type: ServerToClientMessageType<'_>) {
        let mut sender = &self.broker_sender;
        if let Err(e) = send_message_to_peer(&message_type, self.peers.get(peer_id).unwrap().clone()).await {
            warn!("Failed to send message to peer {:?}: {}", peer_id, e);
            sender.send(Event::RemovePeer { peer_id: *peer_id }).await.unwrap();
        }
    }

    async fn batch_send_message(&self, peer_ids: &[PeerId], message_type: ServerToClientMessageType<'_>) {
        let mut sender = &self.broker_sender;
        for peer_id in peer_ids {
            if let Err(e) = send_message_to_peer(&message_type, self.peers.get(peer_id).unwrap().clone()).await {
                warn!("Failed to send message to peer {:?}: {}", peer_id, e);
                sender.send(Event::RemovePeer { peer_id: *peer_id }).await.unwrap();
            }
        }
    }

    pub async fn shutdown(self) {
        debug!("Shutting down peer manager");
        drop(self.peers);
        for writer in self.writers {
            writer.await;
        }
        debug!("Shut down peer manager");
    }

}

pub struct Broker {
    events: Receiver<Event>,
    conferences: HashMap<ConferenceId, Conference>,
    last_conference_id: u32,
    peer_manager: PeerManager,
}

impl Broker {
    pub fn new(events: Receiver<Event>, sender_copy: Sender<Event>) -> Broker {
        Broker {
            events,
            conferences: HashMap::new(),
            last_conference_id: 0,
            peer_manager: PeerManager::new(sender_copy),
        }
    }

    pub async fn broker_loop(mut self) {
        while let Some(event) = self.events.next().await {
            match event {
                Event::NewPeer { peer_id, stream } => self.process_new_peer(peer_id, stream).await,
                Event::RemovePeer { peer_id } => {
                    // remove peer from all conferences
                    let mut conferences_to_restructure = Vec::new();
                    for conference in self.conferences.values_mut() {
                        if conference.remove_peer(peer_id) {
                            conferences_to_restructure.push(conference.id);
                        }
                    }
                    for conference_id in conferences_to_restructure {
                        self.notify_peers_about_restructuring(conference_id).await;
                    }
                    debug!("Removed peer {:?} from all conferences", peer_id);
                    self.peer_manager.remove_peer(peer_id);
                },
                Event::NewConference { nonce, peer_id, password_hash, join_salt, encryption_salt } => 
                    self.process_new_conference(nonce, peer_id, password_hash, join_salt, encryption_salt).await,
                Event::GetConferenceJoinSalt { nonce, peer_id, conference_id } => self.process_get_conference_join_salt(nonce, peer_id, conference_id).await,
                Event::JoinConference { nonce, peer_id, conference_id, password_hash } => self.process_join_conference(nonce, peer_id, conference_id, password_hash).await,
                Event::LeaveConference { nonce, peer_id, conference_id } => self.process_leave_conference(nonce, peer_id, conference_id).await,
                Event::Message { from, to, nonce, msg } => self.process_message(&from, to, nonce, msg).await,
                Event::ListPeers => {
                    info!("Listing peers:");
                    for (i, (peer_id, _)) in self.peer_manager.peers.iter().enumerate(){
                        info!("Peer {}: {:?}", i, peer_id);
                    }
                    info!("End of peer list");
                },
                Event::ListConferences => {
                    info!("Listing conferences:");
                    for (i, (conference_id, conference)) in self.conferences.iter().enumerate(){
                        info!("Conference {}: id: {}, peers: {:?}", i, conference_id, conference.peers);
                    }
                    info!("End of conference list");
                },
                Event::CleanShutdown => {
                    info!("Broker shutting down");
                    break;
                },
            }
        }
        drop(self.conferences);
        self.peer_manager.shutdown().await;
        debug!("Broker loop finished");
    }

    async fn process_new_peer(&mut self, peer_id: PeerId, stream: WriteHalf<TlsStream<TcpStream>>) {
        if self.peer_manager.add_peer(peer_id, stream) {
            self.peer_manager.send_message(&peer_id, ServerToClientMessageType::HandshakeAcknowledged).await;
        }
    }

    async fn process_new_conference(
        &mut self, nonce: PacketNonce, peer_id: PeerId, password_hash: PasswordHash,
        join_salt: ConferenceJoinSalt, encryption_salt: ConferenceEncryptionSalt
    ) {
        self.last_conference_id = self.last_conference_id.wrapping_add(1);
        let id = self.last_conference_id;
        if self.conferences.contains_key(&id) {
            warn!("Conference storage reached maximum capacity");
            self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceCreationError(nonce)).await;
            return;
        }

        self.conferences.insert(id, Conference {
            id,
            password_hash,
            peers: Vec::new(),
            join_salt,
            encryption_salt,
        });

        info!("Conference created: id: {}, by peer_id: {:?}", id, peer_id);
        self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceCreated((nonce, id))).await;
    }

    async fn process_get_conference_join_salt(&mut self, nonce: PacketNonce, peer_id: PeerId, conference_id: ConferenceId) {
        if let Some(conference) = self.conferences.get(&conference_id) {
            self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinSalt((nonce, conference_id, conference.join_salt))).await;
        } else {
            warn!("Peer {:?} tried to get join salt for non-existent conference {}", peer_id, conference_id);
            self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinSaltError((nonce, conference_id))).await;
        }
    }

    async fn process_leave_conference(&mut self, nonce: PacketNonce, peer_id: PeerId, conference_id: ConferenceId) {
        if let Some(conference) = self.conferences.get_mut(&conference_id) {
            if conference.remove_peer(peer_id) {
                self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceLeft((nonce, conference_id))).await;
                info!("Peer {:?} left conference {}", peer_id, conference_id);
                self.notify_peers_about_restructuring(conference_id).await;
            } else {
                warn!("Peer {:?} tried to leave non-existent conference {}", peer_id, conference_id);
                self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceLeaveError((nonce, conference_id))).await;
            }
        }
    }

    async fn process_join_conference(&mut self, nonce: PacketNonce, peer_id: PeerId, conference_id: ConferenceId, password_hash: PasswordHash) {
        if let Some(conference) = self.conferences.get_mut(&conference_id) {
            // check password hash
            if constant_time_eq_32(&password_hash, &conference.password_hash) {
                if conference.peers.len() >= NumberOfPeers::MAX as usize {
                    warn!("Peer {:?} tried to join full conference", peer_id);
                    self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinError((nonce, conference_id))).await;
                    return;
                }
                conference.peers.push(peer_id);
                let new_number_of_peers: u32 = conference.peers.len().try_into().unwrap(); // TODO
                let encryption_salt = conference.encryption_salt;
                self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoined((nonce, conference_id, new_number_of_peers, encryption_salt))).await;
                info!("Peer {:?} joined conference {}", peer_id, conference_id);
                self.notify_peers_about_restructuring(conference_id).await;
            } else {
                warn!("Peer {:?} tried to join conference {} with wrong password", peer_id, conference_id);
                self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinError((nonce, conference_id))).await;
            }
        } else {
            warn!("Peer {:?} tried to join non-existent conference {}", peer_id, conference_id);
            self.peer_manager.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinError((nonce, conference_id))).await;
        }
    }

    async fn process_message(&mut self, peer_id: &PeerId, conference_id: ConferenceId, nonce: PacketNonce, msg: Vec<u8>) {
        if let Some(conference) = self.conferences.get(&conference_id) {
            if self.is_peer_in_conference(peer_id, &conference_id) {
                for peer in &conference.peers {
                    if peer != peer_id {
                        self.peer_manager.send_message(peer, ServerToClientMessageType::IncomingMessage((conference_id, &msg))).await;
                        debug!("Sent message from peer {:?} to peer {:?}, message length was {}", peer_id, peer, msg.len());
                    }
                }
                info!("Peer {:?} sent message to conference {}", peer_id, conference_id);
                self.peer_manager.send_message(peer_id, ServerToClientMessageType::MessageAccepted((nonce, conference_id))).await;
            } else {
                warn!("Peer {:?} tried to send message to conference {} they are not a part of", peer_id, conference_id);
                self.peer_manager.send_message(peer_id, ServerToClientMessageType::MessageError((nonce, conference_id))).await;
            }
        } else {
            warn!("Peer {:?} tried to send message to non-existent conference {}", peer_id, conference_id);
            self.peer_manager.send_message(peer_id, ServerToClientMessageType::MessageError((nonce, conference_id))).await;
        }
    }

    async fn notify_peers_about_restructuring(&self, conference_id: ConferenceId) {
        let conference = self.conferences.get(&conference_id).unwrap();
        let new_number_of_peers = conference.peers.len().try_into().unwrap();
        self.peer_manager.batch_send_message(&conference.peers, ServerToClientMessageType::ConferenceRestructuring((conference_id, new_number_of_peers))).await;
    }

    fn is_peer_in_conference(&self, peer_id: &PeerId, conference_id: &ConferenceId) -> bool {
        if let Some(conference) = self.conferences.get(conference_id) {
            conference.peers.contains(peer_id)
        } else {
            false
        }
    }
}

async fn connection_writer_loop<T>(
    mut messages: Receiver<Vec<u8>>,
    mut stream: WriteHalf<T>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
where T: AsyncWriteExt
{
    while let Some(msg) = messages.next().await {
        async_std::io::WriteExt::write_all(&mut stream, &msg).await?;
    }
    Ok(())
}


