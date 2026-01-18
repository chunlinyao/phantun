use std::convert::TryFrom;

pub const CONTROL_MAGIC: [u8; 4] = *b"PHNT";
pub const CONTROL_VERSION: u8 = 1;
pub const CONTROL_FRAME_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlType {
    Init = 1,
    Resume = 2,
}

impl ControlType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ControlType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ControlType::Init),
            2 => Ok(ControlType::Resume),
            _ => Err(()),
        }
    }
}

pub fn build_control_frame(kind: ControlType, session_id: u64) -> [u8; CONTROL_FRAME_LEN] {
    let mut buf = [0u8; CONTROL_FRAME_LEN];
    buf[..4].copy_from_slice(&CONTROL_MAGIC);
    buf[4] = CONTROL_VERSION;
    buf[5] = kind.as_u8();
    buf[6..14].copy_from_slice(&session_id.to_be_bytes());
    buf
}

pub fn parse_control_frame(buf: &[u8]) -> Option<(ControlType, u64)> {
    if buf.len() < CONTROL_FRAME_LEN {
        return None;
    }
    if buf[..4] != CONTROL_MAGIC {
        return None;
    }
    if buf[4] != CONTROL_VERSION {
        return None;
    }
    let kind = ControlType::try_from(buf[5]).ok()?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&buf[6..14]);
    let session_id = u64::from_be_bytes(id);
    Some((kind, session_id))
}
