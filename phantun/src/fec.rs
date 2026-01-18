use log::{debug, warn};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const FEC_MAGIC: u32 = 0x46454331; // "FEC1"
const FEC_VERSION: u8 = 1;
const HEADER_BASE_LEN: usize = 4 + 1 + 1 + 1 + 1 + 8 + 1;
const MAX_DATA_SHARDS: usize = 32;

#[derive(Clone, Debug)]
pub struct FecConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub flush_interval: Duration,
    pub group_ttl: Duration,
}

impl FecConfig {
    pub fn header_len(&self) -> usize {
        HEADER_BASE_LEN + self.data_shards * 2
    }

    pub fn max_payload(&self, max_packet_len: usize) -> usize {
        max_packet_len.saturating_sub(self.header_len())
    }
}

pub fn parse_fec_spec(spec: &str) -> Option<(usize, usize)> {
    let parts: Vec<&str> = spec.split(['/', ':']).collect();
    if parts.len() != 2 {
        return None;
    }
    let data_shards: usize = parts[0].parse().ok()?;
    let parity_shards: usize = parts[1].parse().ok()?;
    if data_shards == 0 || parity_shards == 0 || data_shards > MAX_DATA_SHARDS {
        return None;
    }
    Some((data_shards, parity_shards))
}

pub struct FecEncoder {
    config: FecConfig,
    max_packet_len: usize,
    group_id: u64,
    group_id_step: u64,
    pending: Vec<Vec<u8>>,
}

impl FecEncoder {
    pub fn new(config: FecConfig, max_packet_len: usize) -> Self {
        Self {
            config,
            max_packet_len,
            group_id: 0,
            group_id_step: 1,
            pending: Vec::new(),
        }
    }

    pub fn new_with_stride(
        config: FecConfig,
        max_packet_len: usize,
        group_id_start: u64,
        group_id_step: u64,
    ) -> Self {
        Self {
            config,
            max_packet_len,
            group_id: group_id_start,
            group_id_step: group_id_step.max(1),
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.len() > self.config.max_payload(self.max_packet_len) {
            warn!(
                "FEC payload size {} exceeds max {}, sending raw frame",
                payload.len(),
                self.config.max_payload(self.max_packet_len)
            );
            return vec![payload.to_vec()];
        }

        self.pending.push(payload.to_vec());
        if self.pending.len() >= self.config.data_shards {
            return self.encode_group(false);
        }
        Vec::new()
    }

    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.encode_group(true)
    }

    fn encode_group(&mut self, pad_empty: bool) -> Vec<Vec<u8>> {
        if pad_empty {
            while self.pending.len() < self.config.data_shards {
                self.pending.push(Vec::new());
            }
        }

        if self.pending.is_empty() {
            return Vec::new();
        }

        let data_shards = self.config.data_shards;
        let parity_shards = self.config.parity_shards;
        let total_shards = data_shards + parity_shards;
        let lengths: Vec<u16> = self
            .pending
            .iter()
            .take(data_shards)
            .map(|p| p.len().min(u16::MAX as usize) as u16)
            .collect();
        let max_len = self
            .pending
            .iter()
            .take(data_shards)
            .map(|p| p.len())
            .max()
            .unwrap_or(0);
        if max_len == 0 {
            return Vec::new();
        }

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        for data in self.pending.drain(..data_shards) {
            let mut shard = data;
            shard.resize(max_len, 0);
            shards.push(shard);
        }

        for _ in 0..parity_shards {
            shards.push(vec![0; max_len]);
        }

        if parity_shards > 0 {
            let rs = ReedSolomon::new(data_shards, parity_shards).expect("invalid shard sizes");
            rs.encode(&mut shards).expect("failed to encode FEC shards");
        }

        let group_id = self.group_id;
        self.group_id = self.group_id.wrapping_add(self.group_id_step);

        shards
            .into_iter()
            .enumerate()
            .map(|(idx, shard)| {
                encode_frame(
                    group_id,
                    data_shards as u8,
                    parity_shards as u8,
                    idx as u8,
                    &lengths,
                    &shard,
                )
            })
            .collect()
    }
}

pub struct FecDecoder {
    ttl: Duration,
    max_groups: usize,
    groups: HashMap<u64, GroupState>,
    completed: HashMap<u64, Instant>,
    completed_order: VecDeque<u64>,
}

impl FecDecoder {
    pub fn new(ttl: Duration, max_groups: usize) -> Self {
        Self {
            ttl,
            max_groups,
            groups: HashMap::new(),
            completed: HashMap::new(),
            completed_order: VecDeque::new(),
        }
    }

    pub fn push(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let Some(parsed) = decode_frame(frame) else {
            return vec![frame.to_vec()];
        };
        let now = Instant::now();
        self.prune(now);
        if self.completed.contains_key(&parsed.group_id) {
            return Vec::new();
        }

        let mut output = Vec::new();
        let ready = {
            let entry = self.groups.entry(parsed.group_id).or_insert_with(|| {
                GroupState::new(
                    parsed.data_shards,
                    parsed.parity_shards,
                    parsed.lengths.clone(),
                    parsed.payload.len(),
                    now,
                )
            });

            if parsed.payload.len() > entry.shard_size {
                entry.resize_shards(parsed.payload.len());
            }

            entry.last_seen = now;
            entry.insert_shard(parsed.shard_index as usize, parsed.payload);

            // Systematic behavior: deliver any available data shards immediately (in shard index order).
            output.extend(entry.deliver_ready());

            let ready = entry.ready_to_reconstruct();
            if ready {
                entry.reconstruct();
                output.extend(entry.deliver_ready());
            }
            ready
        };
        if ready {
            self.groups.remove(&parsed.group_id);
            self.completed.insert(parsed.group_id, now);
            self.completed_order.push_back(parsed.group_id);
        }

        output
    }

    fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.groups
            .retain(|_, group| now.duration_since(group.last_seen) <= ttl);
        if self.groups.len() > self.max_groups {
            let mut oldest: Vec<(u64, Instant)> = self
                .groups
                .iter()
                .map(|(id, group)| (*id, group.last_seen))
                .collect();
            oldest.sort_by_key(|(_, ts)| *ts);
            for (id, _) in oldest.into_iter().take(self.groups.len() - self.max_groups) {
                self.groups.remove(&id);
            }
        }

        // Keep completed group IDs around (bounded by max_groups) to suppress late duplicates,
        // even if they arrive well after the group TTL.
        if !self.completed_order.is_empty() {
            let mut filtered = VecDeque::with_capacity(self.completed_order.len());
            for id in self.completed_order.drain(..) {
                if self.completed.contains_key(&id) {
                    filtered.push_back(id);
                }
            }
            self.completed_order = filtered;
        }
        while self.completed.len() > self.max_groups {
            if let Some(id) = self.completed_order.pop_front() {
                self.completed.remove(&id);
            } else {
                break;
            }
        }
    }
}

struct GroupState {
    data_shards: usize,
    parity_shards: usize,
    lengths: Vec<u16>,
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
    shard_size: usize,
    last_seen: Instant,
}

impl GroupState {
    fn new(
        data_shards: u8,
        parity_shards: u8,
        lengths: Vec<u16>,
        shard_size: usize,
        now: Instant,
    ) -> Self {
        let total = data_shards as usize + parity_shards as usize;
        Self {
            data_shards: data_shards as usize,
            parity_shards: parity_shards as usize,
            lengths,
            shards: vec![None; total],
            delivered: vec![false; total],
            shard_size,
            last_seen: now,
        }
    }

    fn resize_shards(&mut self, new_size: usize) {
        self.shard_size = new_size;
        for shard in &mut self.shards {
            if let Some(data) = shard {
                data.resize(new_size, 0);
            }
        }
    }

    fn insert_shard(&mut self, index: usize, payload: Vec<u8>) {
        if index >= self.shards.len() {
            return;
        }
        let mut shard = payload;
        if shard.len() < self.shard_size {
            shard.resize(self.shard_size, 0);
        }
        self.shards[index] = Some(shard);
    }

    fn ready_to_reconstruct(&self) -> bool {
        let present = self.shards.iter().filter(|s| s.is_some()).count();
        present >= self.data_shards
    }

    fn reconstruct(&mut self) {
        let rs = ReedSolomon::new(self.data_shards, self.parity_shards)
            .expect("invalid shard sizes for reconstruction");
        if let Err(err) = rs.reconstruct(&mut self.shards) {
            debug!("FEC reconstruct failed: {}", err);
        }
    }

    fn deliver_ready(&mut self) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        for i in 0..self.data_shards {
            if self.delivered.get(i).copied().unwrap_or(false) {
                continue;
            }
            let len = *self.lengths.get(i).unwrap_or(&0) as usize;
            if len == 0 {
                // Empty payload shard (padding) — mark delivered to avoid blocking later shards.
                self.delivered[i] = true;
                continue;
            }
            match self.shards.get(i).and_then(|s| s.as_ref()) {
                Some(shard) => {
                    output.push(shard[..len.min(shard.len())].to_vec());
                    self.delivered[i] = true;
                }
                None => {
                    // Allow out-of-order delivery: skip missing shard; it can be delivered later when available.
                    continue;
                }
            }
        }
        output
    }
}

struct ParsedFrame {
    group_id: u64,
    data_shards: u8,
    parity_shards: u8,
    shard_index: u8,
    lengths: Vec<u16>,
    payload: Vec<u8>,
}

fn encode_frame(
    group_id: u64,
    data_shards: u8,
    parity_shards: u8,
    shard_index: u8,
    lengths: &[u16],
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_BASE_LEN + lengths.len() * 2 + payload.len());
    buf.extend_from_slice(&FEC_MAGIC.to_be_bytes());
    buf.push(FEC_VERSION);
    buf.push(data_shards);
    buf.push(parity_shards);
    buf.push(shard_index);
    buf.extend_from_slice(&group_id.to_be_bytes());
    buf.push(lengths.len() as u8);
    for len in lengths {
        buf.extend_from_slice(&len.to_be_bytes());
    }
    buf.extend_from_slice(payload);
    buf
}

fn decode_frame(frame: &[u8]) -> Option<ParsedFrame> {
    if frame.len() < HEADER_BASE_LEN {
        return None;
    }
    let magic = u32::from_be_bytes(frame[0..4].try_into().ok()?);
    if magic != FEC_MAGIC {
        return None;
    }
    if frame[4] != FEC_VERSION {
        return None;
    }
    let data_shards = frame[5];
    let parity_shards = frame[6];
    let shard_index = frame[7];
    let group_id = u64::from_be_bytes(frame[8..16].try_into().ok()?);
    let lengths_count = frame[16] as usize;
    let data_shards_usize = data_shards as usize;
    let parity_shards_usize = parity_shards as usize;
    let total_shards = data_shards_usize + parity_shards_usize;
    if data_shards == 0
        || parity_shards == 0
        || data_shards_usize > MAX_DATA_SHARDS
        || parity_shards_usize > MAX_DATA_SHARDS
        || shard_index as usize >= total_shards
        || lengths_count != data_shards_usize
    {
        return None;
    }
    let lengths_bytes = lengths_count.checked_mul(2)?;
    let header_len = HEADER_BASE_LEN + lengths_bytes;
    if frame.len() < header_len {
        return None;
    }
    let mut lengths = Vec::with_capacity(lengths_count);
    for i in 0..lengths_count {
        let start = HEADER_BASE_LEN + i * 2;
        lengths.push(u16::from_be_bytes(frame[start..start + 2].try_into().ok()?));
    }
    let payload = frame[header_len..].to_vec();
    Some(ParsedFrame {
        group_id,
        data_shards,
        parity_shards,
        shard_index,
        lengths,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fec_spec_rejects_invalid() {
        assert!(parse_fec_spec("0/2").is_none());
        assert!(parse_fec_spec("2/0").is_none());
        assert!(parse_fec_spec("33/2").is_none());
        assert!(parse_fec_spec("2").is_none());
        assert!(parse_fec_spec("2/x").is_none());
    }

    #[test]
    fn parse_fec_spec_accepts_valid() {
        assert_eq!(parse_fec_spec("4/2"), Some((4, 2)));
        assert_eq!(parse_fec_spec("8:3"), Some((8, 3)));
    }

    #[test]
    fn fec_round_trip_with_loss() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 2,
            flush_interval: Duration::from_millis(5),
            group_ttl: Duration::from_millis(200),
        };
        let mut encoder = FecEncoder::new(config.clone(), 1500);
        let payloads = vec![
            b"alpha".to_vec(),
            b"bravo".to_vec(),
            b"charlie".to_vec(),
            b"delta".to_vec(),
        ];

        let mut frames = Vec::new();
        for payload in &payloads {
            frames.extend(encoder.push(payload));
        }

        assert_eq!(frames.len(), config.data_shards + config.parity_shards);

        // Drop one frame to simulate loss.
        frames.remove(1);

        let mut decoder = FecDecoder::new(config.group_ttl, 8);
        let mut recovered = Vec::new();
        for frame in frames {
            recovered.extend(decoder.push(&frame));
        }

        let mut recovered_sorted = recovered.clone();
        recovered_sorted.sort();
        let mut expected_sorted = payloads.clone();
        expected_sorted.sort();
        assert_eq!(recovered_sorted, expected_sorted);
    }

    #[test]
    fn fec_encoder_group_id_stride_avoids_collisions() {
        let config = FecConfig {
            data_shards: 2,
            parity_shards: 1,
            flush_interval: Duration::from_millis(5),
            group_ttl: Duration::from_millis(200),
        };
        let mut encoder_a = FecEncoder::new_with_stride(config.clone(), 1500, 0, 2);
        let mut encoder_b = FecEncoder::new_with_stride(config.clone(), 1500, 1, 2);

        let mut frames_a = Vec::new();
        let mut frames_b = Vec::new();
        for payload in [b"alpha", b"bravo"] {
            frames_a.extend(encoder_a.push(payload));
            frames_b.extend(encoder_b.push(payload));
        }

        let mut ids_a = Vec::new();
        for frame in &frames_a {
            let parsed = decode_frame(frame).expect("decode frame A");
            ids_a.push(parsed.group_id);
        }
        let mut ids_b = Vec::new();
        for frame in &frames_b {
            let parsed = decode_frame(frame).expect("decode frame B");
            ids_b.push(parsed.group_id);
        }

        for id in ids_a {
            assert!(!ids_b.contains(&id));
        }
    }

    #[test]
    fn fec_immediate_delivery_single_shard() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 2,
            flush_interval: Duration::from_millis(5),
            group_ttl: Duration::from_millis(200),
        };
        let mut encoder = FecEncoder::new(config.clone(), 1500);
        let payload = b"hello".to_vec();

        encoder.push(&payload);
        let frames = encoder.flush();
        assert_eq!(frames.len(), config.data_shards + config.parity_shards);

        let mut decoder = FecDecoder::new(config.group_ttl, 8);
        // First frame should be data shard 0 and delivered immediately.
        let out = decoder.push(&frames[0]);
        assert_eq!(out, vec![payload]);
    }

    #[test]
    fn fec_delivery_out_of_order_when_gap_present() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 2,
            flush_interval: Duration::from_millis(5),
            group_ttl: Duration::from_millis(200),
        };
        let mut encoder = FecEncoder::new(config.clone(), 1500);
        let payloads = vec![
            b"alpha".to_vec(),
            b"bravo".to_vec(),
            b"charlie".to_vec(),
            b"delta".to_vec(),
        ];
        let mut frames = Vec::new();
        for p in &payloads {
            frames.extend(encoder.push(p));
        }
        frames.extend(encoder.flush());
        assert!(!frames.is_empty());
        // Drop shard 0 to create a gap, but keep others (including parity).
        frames.remove(0);

        let mut decoder = FecDecoder::new(config.group_ttl, 8);
        let mut out = Vec::new();
        for f in &frames {
            out.extend(decoder.push(f));
            if !out.is_empty() {
                break;
            }
        }
        // Should deliver shard 1 even though shard 0 is missing.
        assert_eq!(out, vec![payloads[1].clone()]);
    }

    #[test]
    fn non_fec_frame_passthrough() {
        let payload = b"plain-udp-packet".to_vec();
        let mut decoder = FecDecoder::new(Duration::from_millis(50), 8);
        let recovered = decoder.push(&payload);
        assert_eq!(recovered, vec![payload]);
    }

    #[test]
    fn completed_group_dedup_suppresses_duplicates() {
        let config = FecConfig {
            data_shards: 2,
            parity_shards: 1,
            flush_interval: Duration::from_millis(5),
            group_ttl: Duration::from_millis(200),
        };
        let mut encoder = FecEncoder::new(config.clone(), 1500);
        let payloads = vec![b"alpha".to_vec(), b"bravo".to_vec()];
        let mut frames = Vec::new();
        for payload in &payloads {
            frames.extend(encoder.push(payload));
        }
        assert_eq!(frames.len(), config.data_shards + config.parity_shards);

        let mut decoder = FecDecoder::new(config.group_ttl, 8);
        let mut recovered = Vec::new();
        for frame in &frames {
            recovered.extend(decoder.push(frame));
        }
        assert_eq!(recovered, payloads);

        let dup = decoder.push(&frames[0]);
        assert!(dup.is_empty());
    }
}
