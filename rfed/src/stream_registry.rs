use std::collections::HashMap;

use reticulum_rust::link::LinkHandle;

#[derive(Default, Debug, Clone, Copy)]
pub struct StreamDispatchResult {
    pub matched: usize,
    pub sent: usize,
}

impl StreamDispatchResult {
    pub fn had_sessions(&self) -> bool {
        self.matched > 0
    }

    pub fn delivered(&self) -> bool {
        self.sent > 0
    }
}

#[derive(Clone)]
struct ChannelStreamSession {
    link: LinkHandle,
    subscriber_hash: Vec<u8>,
    channel_hashes: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct ChannelStreamRegistry {
    sessions: HashMap<Vec<u8>, ChannelStreamSession>,
}

impl ChannelStreamRegistry {
    pub fn configure(
        &mut self,
        link: LinkHandle,
        subscriber_hash: Vec<u8>,
        channel_hashes: Vec<Vec<u8>>,
    ) {
        let link_id = link.link_id();
        self.sessions.insert(
            link_id,
            ChannelStreamSession {
                link,
                subscriber_hash,
                channel_hashes,
            },
        );
    }

    pub fn remove(&mut self, link_id: &[u8]) -> bool {
        self.sessions.remove(link_id).is_some()
    }

    pub fn dispatch(
        &mut self,
        subscriber_hash: &[u8],
        channel_hash: &[u8],
        payload: &[u8],
    ) -> StreamDispatchResult {
        let matches: Vec<(Vec<u8>, LinkHandle)> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.subscriber_hash.as_slice() == subscriber_hash
                    && session
                        .channel_hashes
                        .iter()
                        .any(|configured| configured.as_slice() == channel_hash)
            })
            .map(|(link_id, session)| (link_id.clone(), session.link.clone()))
            .collect();

        let mut result = StreamDispatchResult {
            matched: matches.len(),
            sent: 0,
        };
        let mut stale_links = Vec::new();

        for (link_id, link) in matches {
            if !link.is_alive() {
                stale_links.push(link_id);
                continue;
            }

            match link.send_packet(payload) {
                Ok(()) => result.sent += 1,
                Err(_) => stale_links.push(link_id),
            }
        }

        for link_id in stale_links {
            self.sessions.remove(link_id.as_slice());
        }

        result
    }
}

#[derive(Clone)]
struct PropagationStreamSession {
    link: LinkHandle,
    delivery_hash: Vec<u8>,
}

#[derive(Default)]
pub struct PropagationStreamRegistry {
    sessions: HashMap<Vec<u8>, PropagationStreamSession>,
}

impl PropagationStreamRegistry {
    pub fn register(&mut self, link: LinkHandle, delivery_hash: Vec<u8>) -> Result<(), &'static str> {
        let link_id = link.link_id();
        if self.sessions.contains_key(&link_id) {
            return Err("already_open");
        }
        self.sessions
            .insert(link_id, PropagationStreamSession { link, delivery_hash });
        Ok(())
    }

    pub fn remove(&mut self, link_id: &[u8]) -> bool {
        self.sessions.remove(link_id).is_some()
    }

    pub fn dispatch(&mut self, delivery_hash: &[u8], payload: &[u8]) -> StreamDispatchResult {
        let matches: Vec<(Vec<u8>, LinkHandle)> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.delivery_hash.as_slice() == delivery_hash)
            .map(|(link_id, session)| (link_id.clone(), session.link.clone()))
            .collect();

        let mut result = StreamDispatchResult {
            matched: matches.len(),
            sent: 0,
        };
        let mut stale_links = Vec::new();

        for (link_id, link) in matches {
            if !link.is_alive() {
                stale_links.push(link_id);
                continue;
            }

            match link.send_packet(payload) {
                Ok(()) => result.sent += 1,
                Err(_) => stale_links.push(link_id),
            }
        }

        for link_id in stale_links {
            self.sessions.remove(link_id.as_slice());
        }

        result
    }
}