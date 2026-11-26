/// Header size in bytes: flags (1) + seq_index (2 LE) + total_chunks (2 LE).
pub const FRAME_HEADER_SIZE: usize = 5;

const FLAG_LAST_CHUNK: u8 = 0x01;

/// Splits `data` into BLE MTU-sized chunks with a 5-byte framing header.
/// `max_packet_size` must be strictly greater than `FRAME_HEADER_SIZE` (e.g. 20 for default BLE ATT MTU).
pub fn chunk_message(data: &[u8], max_packet_size: usize) -> Result<Vec<Vec<u8>>, String> {
    if max_packet_size <= FRAME_HEADER_SIZE {
        return Err(format!(
            "max_packet_size ({max_packet_size}) must be > {FRAME_HEADER_SIZE}"
        ));
    }

    let max_payload = max_packet_size - FRAME_HEADER_SIZE;
    let total_chunks = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(max_payload)
    };

    if total_chunks > u16::MAX as usize {
        return Err(format!("Message too large: requires {total_chunks} chunks"));
    }

    let total_u16 = total_chunks as u16;
    let mut frames = Vec::with_capacity(total_chunks);

    if data.is_empty() {
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE);
        frame.push(FLAG_LAST_CHUNK);
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&1u16.to_le_bytes());
        frames.push(frame);
        return Ok(frames);
    }

    for (idx, chunk) in data.chunks(max_payload).enumerate() {
        let seq = idx as u16;
        let is_last = idx + 1 == total_chunks;
        let flags = if is_last { FLAG_LAST_CHUNK } else { 0 };

        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + chunk.len());
        frame.push(flags);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&total_u16.to_le_bytes());
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }

    Ok(frames)
}

/// Reassembles incoming framed chunks into complete messages.
#[derive(Default)]
pub struct FrameAssembler {
    expected_total: Option<u16>,
    received_count: u16,
    slots: Vec<Option<Vec<u8>>>,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the assembler state.
    pub fn reset(&mut self) {
        self.expected_total = None;
        self.received_count = 0;
        self.slots.clear();
    }

    /// Pushes one raw BLE packet. Returns `Ok(Some(full_message))` when all chunks have arrived.
    pub fn push_chunk(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if frame.len() < FRAME_HEADER_SIZE {
            return Err(format!("Frame too short: {} bytes", frame.len()));
        }

        let _flags = frame[0];
        let seq = u16::from_le_bytes([frame[1], frame[2]]);
        let total = u16::from_le_bytes([frame[3], frame[4]]);
        let payload = &frame[FRAME_HEADER_SIZE..];

        if total == 0 || seq >= total {
            return Err(format!("Invalid frame header: seq={seq}, total={total}"));
        }

        match self.expected_total {
            None => {
                self.expected_total = Some(total);
                self.slots = vec![None; total as usize];
            }
            Some(prev_total) if prev_total != total => {
                self.reset();
                return Err(format!(
                    "Inconsistent total_chunks: expected {prev_total}, got {total}"
                ));
            }
            _ => {}
        }

        let idx = seq as usize;
        if self.slots[idx].is_none() {
            self.slots[idx] = Some(payload.to_vec());
            self.received_count += 1;
        }

        if self.received_count == total {
            let mut full = Vec::new();
            for slot in self.slots.drain(..) {
                full.extend_from_slice(&slot.unwrap_or_default());
            }
            self.reset();
            Ok(Some(full))
        } else {
            Ok(None)
        }
    }
}
