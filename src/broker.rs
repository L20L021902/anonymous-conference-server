use std::collections::hash_map::{Entry, HashMap};
use async_native_tls::TlsStream;
use async_std::{prelude::*, net::TcpStream};
use log::{warn, info, debug};
use futures::{channel::mpsc, io::WriteHalf, AsyncWriteExt};
use futures::sink::SinkExt;
use async_std::task::{self, JoinHandle};
use constant_time_eq::constant_time_eq_32;

use crate::constants::{ConferenceEncryptionSalt, ConferenceId, ConferenceJoinSalt, PacketNonce, PasswordHash, PeerId, ServerToClientMessageType};
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

struct InternalSender {
    sender: Sender<Event>,
}

impl InternalSender {
    async fn _notify_peers_about_restructuring(&mut self, conference_id: ConferenceId, conference: &Conference, peers: &HashMap<PeerId, Sender<Vec<u8>>>) {
        let new_number_of_peers = conference.peers.len().try_into().unwrap();
        for peer in &conference.peers {
            self.send_message(peer, peers, ServerToClientMessageType::ConferenceRestructuring((conference_id, new_number_of_peers))).await;
        }
    }

    async fn send_message(&mut self, peer_id: &PeerId, peers: &HashMap<PeerId, Sender<Vec<u8>>>, message_type: ServerToClientMessageType<'_>) {
        if let Err(e) = send_message_to_peer(message_type, peers.get(peer_id).unwrap().clone()).await {
            warn!("Failed to send message to peer {:?}: {}", peer_id, e);
            self.remove_peer(peer_id).await;
        }
    }

    async fn remove_peer(&mut self, peer_id: &PeerId) {
        self.sender.send(Event::RemovePeer { peer_id: *peer_id }).await.unwrap();
    }

}

pub type Sender<T> = mpsc::UnboundedSender<T>;
pub type Receiver<T> = mpsc::UnboundedReceiver<T>;

pub struct Broker {
    events: Receiver<Event>,
    peers: HashMap<PeerId, Sender<Vec<u8>>>,
    conferences: HashMap<ConferenceId, Conference>,
    last_conference_id: u32,
    internal_sender: InternalSender,
    writers: Vec<JoinHandle<()>>
}

impl Broker {
    pub fn new(events: Receiver<Event>, sender_copy: Sender<Event>) -> Broker {
        Broker {
            events,
            peers: HashMap::new(),
            conferences: HashMap::new(),
            last_conference_id: 0,
            internal_sender: InternalSender{sender: sender_copy},
            writers: Vec::new(),
        }
    }

    pub async fn broker_loop(mut self) {
        mpsc::unbounded::<(String, Receiver<String>)>();

        while let Some(event) = self.events.next().await {
            match event {
                Event::NewPeer { peer_id, stream } => {
                    match self.peers.entry(peer_id) {
                        Entry::Occupied(..) => {
                            warn!("Peer already exists: {:?}", peer_id);
                            self.send_message(&peer_id, ServerToClientMessageType::HandshakeAcknowledged, &mut self.internal_sender.sender.clone()).await;
                        },
                        Entry::Vacant(entry) => {
                            let (client_sender, client_receiver) = mpsc::unbounded();
                            entry.insert(client_sender);
                            info!("Added new peer {:?}", peer_id);
                            self.send_message(&peer_id, ServerToClientMessageType::HandshakeAcknowledged, &mut self.internal_sender.sender.clone()).await; // message will be sent in the connection_writer_loop
                            let mut sender = self.internal_sender.sender.clone();
                            let writer_handle = task::spawn(async move {
                                if let Err(e) = connection_writer_loop(client_receiver, stream).await {
                                    warn!("Error in connection writer loop: {}", e);
                                    sender.send(Event::RemovePeer { peer_id }).await.unwrap(); // TODO: check
                                }
                            });
                            self.writers.push(writer_handle);
                        }
                    }
                },
                Event::RemovePeer { peer_id } => {
                    // remove peer from all conferences
                    for conference in self.conferences.values_mut() {
                        if conference.remove_peer(peer_id) {
                            self.internal_sender._notify_peers_about_restructuring(conference.id, conference, &self.peers).await;
                        }
                    }
                    debug!("Removed peer {:?} from all conferences", peer_id);
                    self.peers.remove(&peer_id);
                    debug!("Removed peer {:?}", peer_id);
                },
                Event::NewConference { nonce, peer_id, password_hash, join_salt, encryption_salt } => {
                    self.last_conference_id = self.last_conference_id.wrapping_add(1);
                    let id = self.last_conference_id;
                    if self.conferences.contains_key(&id) {
                        warn!("Conference storage reached maximum capacity");
                        self.send_message(&peer_id, ServerToClientMessageType::ConferenceCreationError(nonce), &mut self.internal_sender.sender.clone()).await;
                        continue;
                    }

                    self.conferences.insert(id, Conference {
                        id,
                        password_hash,
                        peers: Vec::new(),
                        join_salt,
                        encryption_salt,
                    });

                    info!("Conference created: id: {}, by peer_id: {:?}", id, peer_id);
                    self.send_message(&peer_id, ServerToClientMessageType::ConferenceCreated((nonce, id)), &mut self.internal_sender.sender.clone()).await;
                },
                Event::GetConferenceJoinSalt { nonce, peer_id, conference_id } => {
                    if let Some(conference) = self.conferences.get(&conference_id) {
                        self.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinSalt((nonce, conference_id, conference.join_salt)), &mut self.internal_sender.sender.clone()).await;
                    } else {
                        warn!("Peer {:?} tried to get join salt for non-existent conference {}", peer_id, conference_id);
                        self.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinSaltError((nonce, conference_id)), &mut self.internal_sender.sender.clone()).await;
                    }
                },
                Event::JoinConference { nonce, peer_id, conference_id, password_hash } => {
                    // TODO make this cleaner
                    let mut peer_list_changed = false;
                    if let Some(conference) = self.conferences.get_mut(&conference_id) {
                        // check password hash
                        if constant_time_eq_32(&password_hash, &conference.password_hash) {
                            conference.peers.push(peer_id);
                            peer_list_changed = true;
                            let new_number_of_peers: u32 = conference.peers.len().try_into().unwrap(); // TODO
                            let encryption_salt = conference.encryption_salt;
                            self.send_message(&peer_id, ServerToClientMessageType::ConferenceJoined((nonce, conference_id, new_number_of_peers, encryption_salt)), &mut self.internal_sender.sender.clone()).await;
                            info!("Peer {:?} joined conference {}", peer_id, conference_id);
                        } else {
                            warn!("Peer {:?} tried to join conference {} with wrong password", peer_id, conference_id);
                            self.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinError((nonce, conference_id)), &mut self.internal_sender.sender.clone()).await;
                        }
                    } else {
                        warn!("Peer {:?} tried to join non-existent conference {}", peer_id, conference_id);
                        self.send_message(&peer_id, ServerToClientMessageType::ConferenceJoinError((nonce, conference_id)), &mut self.internal_sender.sender.clone()).await;
                    }
                    if peer_list_changed {
                        let conference = &self.conferences.get(&conference_id).unwrap();
                        let new_number_of_peers = conference.peers.len().try_into().unwrap();
                        for peer in &conference.peers {
                            if peer != &peer_id {
                                self.send_message(peer, ServerToClientMessageType::ConferenceRestructuring((conference_id, new_number_of_peers)), &mut self.internal_sender.sender.clone()).await;
                            }
                        }
                    }
                },
                Event::LeaveConference { nonce, peer_id, conference_id } => self.process_leave_conference(nonce, peer_id, conference_id).await,
                Event::Message { from, to, nonce, msg } => {
                    if let Some(conference) = self.conferences.get(&to) {
                        if self.is_peer_in_conference(&from, &to) {
                            for peer in &conference.peers {
                                if peer != &from {
                                    self.send_message(peer, ServerToClientMessageType::IncomingMessage((to, &msg)), &mut self.internal_sender.sender.clone()).await;
                                    debug!("Sent message from peer {:?} to peer {:?}, message length was {}", from, peer, msg.len());
                                }
                            }
                            info!("Peer {:?} sent message to conference {}", from, to);
                            self.send_message(&from, ServerToClientMessageType::MessageAccepted((nonce, to)), &mut self.internal_sender.sender.clone()).await;
                        } else {
                            warn!("Peer {:?} tried to send message to conference {} they are not a part of", from, to);
                            self.send_message(&from, ServerToClientMessageType::MessageError((nonce, to)), &mut self.internal_sender.sender.clone()).await;
                        }
                    } else {
                        warn!("Peer {:?} tried to send message to non-existent conference {}", from, to);
                        self.send_message(&from, ServerToClientMessageType::MessageError((nonce, to)), &mut self.internal_sender.sender.clone()).await;
                    }
                },
                Event::ListPeers => {
                    info!("Listing peers:");
                    for (i, (peer_id, _)) in self.peers.iter().enumerate(){
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
                    drop(self.internal_sender);
                    break;
                },
            }
        }
        drop(self.conferences);
        drop(self.peers);
        for writer in self.writers {
            writer.await;
        }
        debug!("Broker loop finished");
    }

    async fn process_leave_conference(&mut self, nonce: PacketNonce, peer_id: PeerId, conference_id: ConferenceId) {
        if let Some(conference) = self.conferences.get_mut(&conference_id) {
            if conference.remove_peer(peer_id) {
                self.send_message(&peer_id, ServerToClientMessageType::ConferenceLeft((nonce, conference_id)), &mut self.internal_sender.sender.clone()).await;
                info!("Peer {:?} left conference {}", peer_id, conference_id);
                self._notify_peers_about_restructuring(conference_id).await;
            } else {
                warn!("Peer {:?} tried to leave non-existent conference {}", peer_id, conference_id);
                self.send_message(&peer_id, ServerToClientMessageType::ConferenceLeaveError((nonce, conference_id)), &mut self.internal_sender.sender.clone()).await;
            }
        }
    }

    async fn send_message(&self, peer_id: &PeerId, message_type: ServerToClientMessageType<'_>, sender: &mut Sender<Event>) {
        if let Err(e) = send_message_to_peer(message_type, self.peers.get(peer_id).unwrap().clone()).await {
            warn!("Failed to send message to peer {:?}: {}", peer_id, e);
            self.remove_peer(peer_id, sender).await;
        }
    }

    async fn remove_peer(&self, peer_id: &PeerId, sender: &mut Sender<Event>) {
        sender.send(Event::RemovePeer { peer_id: *peer_id }).await.unwrap();
    }

    async fn _notify_peers_about_restructuring(&self, conference_id: ConferenceId) {
        let conference = self.conferences.get(&conference_id).unwrap();
        let new_number_of_peers = conference.peers.len().try_into().unwrap();
        for peer in &conference.peers {
            self.send_message(peer, ServerToClientMessageType::ConferenceRestructuring((conference_id, new_number_of_peers)), &mut self.internal_sender.sender.clone()).await;
        }
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


