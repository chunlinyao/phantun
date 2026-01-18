use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};
use pcap_parser::traits::PcapReaderIterator;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

fn extract_tcp_seq(data: &[u8], linktype: Linktype) -> Option<(FlowKey, u32)> {
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
        if payload.starts_with(b"FEC1") {
            return Some((
                FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.source_port(),
                    dst_port: tcp.destination_port(),
                },
                tcp.sequence_number(),
            ));
        }
    }
    None
}

fn parse_legacy_pcap(bytes: &[u8]) -> Result<(Linktype, Vec<(FlowKey, u32)>), String> {
    let mut reader = LegacyPcapReader::new(65536, Cursor::new(bytes))
        .map_err(|e| format!("pcap open failed: {e:?}"))?;
    let mut linktype = None;
    let mut seqs = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        linktype = Some(header.network);
                    }
                    PcapBlockOwned::Legacy(block) => {
                        if let Some(linktype) = linktype {
                            if let Some(entry) = extract_tcp_seq(block.data, linktype) {
                                seqs.push(entry);
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
    Ok((linktype, seqs))
}

#[test]
fn out_pcap_has_no_duplicate_seq_starts_for_fec_payloads() {
    let pcap_bytes = include_bytes!("../../out.pcap");
    let (linktype, seqs) = parse_legacy_pcap(pcap_bytes).expect("failed to parse pcap");
    assert!(
        !seqs.is_empty(),
        "no TCP packets extracted (linktype: {linktype:?})"
    );
    let mut per_flow: HashMap<FlowKey, HashSet<u32>> = HashMap::new();
    for (flow, seq) in seqs {
        let seen = per_flow.entry(flow).or_default();
        assert!(
            seen.insert(seq),
            "duplicate TCP sequence start found in flow {:?}: {seq}",
            flow
        );
    }
}
