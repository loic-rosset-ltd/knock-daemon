//! A capture backend that replays a fixed list of events. Used by `--demo` to
//! showcase concurrent matching without root or libpcap, and by integration
//! tests.

use crate::matcher::PacketEvent;

use super::Capture;

pub struct ReplayCapture {
    events: Vec<PacketEvent>,
}

impl ReplayCapture {
    pub fn new(events: Vec<PacketEvent>) -> Self {
        Self { events }
    }
}

impl Capture for ReplayCapture {
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> anyhow::Result<()> {
        for ev in &self.events {
            sink(*ev);
        }
        Ok(())
    }
}
