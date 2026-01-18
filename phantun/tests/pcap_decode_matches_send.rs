use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};
use phantun::fec::FecDecoder;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::Duration;

const FEC_MAGIC: [u8; 4] = *b"FEC1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

struct FlowPayload {
    flow: FlowKey,
    payload: Vec<u8>,
}

fn split_frames(payload: &[u8]) -> Vec<&[u8]> {
    let mut offsets = Vec::new();
    let mut i = 0;
    while i + 4 <= payload.len() {
        if &payload[i..i + 4] == FEC_MAGIC {
            offsets.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut frames = Vec::new();
    for (idx, &start) in offsets.iter().enumerate() {
        let end = offsets.get(idx + 1).copied().unwrap_or(payload.len());
        if start < end {
            frames.push(&payload[start..end]);
        }
    }
    frames
}

fn extract_fec_payloads(data: &[u8], linktype: Linktype) -> Option<FlowPayload> {
    let sliced = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        Linktype::RAW => SlicedPacket::from_ip(data).ok()?,
        Linktype::LINUX_SLL => SlicedPacket::from_ip(data.get(16..)?).ok()?,
        _ => return None,
    };
    let (src_ip, dst_ip) = match sliced.net.as_ref() {
        Some(net) => match net.ipv4_ref() {
            Some(ipv4) => (ipv4.header().source_addr(), ipv4.header().destination_addr()),
            None => return None,
        },
        None => return None,
    };
    if let Some(TransportSlice::Tcp(tcp)) = sliced.transport {
        let payload = tcp.payload();
        if payload.windows(FEC_MAGIC.len()).any(|w| w == FEC_MAGIC) {
            return Some(FlowPayload {
                flow: FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.source_port(),
                    dst_port: tcp.destination_port(),
                },
                payload: payload.to_vec(),
            });
        }
    }
    None
}

fn parse_pcap(bytes: &[u8]) -> Result<(Linktype, Vec<FlowPayload>), String> {
    let mut reader = LegacyPcapReader::new(65536, Cursor::new(bytes))
        .map_err(|e| format!("pcap open failed: {e:?}"))?;
    let mut linktype = None;
    let mut packets = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        linktype = Some(header.network);
                    }
                    PcapBlockOwned::Legacy(block) => {
                        if let Some(linktype) = linktype {
                            if let Some(entry) = extract_fec_payloads(block.data, linktype) {
                                packets.push(entry);
                            }
                        }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| format!("pcap refill failed: {e:?}"))?;
            }
            Err(e) => return Err(format!("pcap read failed: {e:?}")),
        }
    }
    let Some(linktype) = linktype else {
        return Err("pcap missing linktype header".to_string());
    };
    Ok((linktype, packets))
}

fn expected_from_send_txt() -> Vec<u8> {
    let content = include_str!("../../send.txt");
    let mut lines = content.lines();
    let mut collected = Vec::new();
    let mut started = false;
    for line in lines.by_ref() {
        let trimmed = line.trim_end();
        let is_letter = trimmed.len() == 1 && trimmed.as_bytes()[0].is_ascii_lowercase();
        if !started {
            if is_letter {
                started = true;
                collected.push(trimmed.to_string());
                if trimmed == "z" {
                    break;
                }
            }
            continue;
        }
        if trimmed.is_empty() || is_letter {
            collected.push(trimmed.to_string());
            if trimmed == "z" {
                break;
            }
        }
    }
    let mut out = collected.join("\n").into_bytes();
    out.push(b'\n');
    out
}

fn decode_flow(packets: &[FlowPayload]) -> Vec<u8> {
    let mut decoder = FecDecoder::new(Duration::from_millis(200), 256);
    let mut out = Vec::new();
    for packet in packets {
        for frame in split_frames(&packet.payload) {
            for data in decoder.push(frame) {
                out.extend_from_slice(&data);
            }
        }
    }
    out
}

#[test]
fn pcap_decoded_payload_matches_send_txt() {
    let pcap_bytes = include_bytes!("../../out.pcap");
    let (linktype, packets) = parse_pcap(pcap_bytes).expect("failed to parse pcap");
    assert!(
        !packets.is_empty(),
        "no TCP payloads extracted (linktype: {linktype:?})"
    );

    let mut flows: HashMap<FlowKey, Vec<FlowPayload>> = HashMap::new();
    for packet in packets {
        flows.entry(packet.flow).or_default().push(packet);
    }

    let mut best = Vec::new();
    for payloads in flows.values() {
        let decoded = decode_flow(payloads);
        if decoded.len() > best.len() {
            best = decoded;
        }
    }

    let expected = expected_from_send_txt();
    assert_eq!(best, expected);
}
