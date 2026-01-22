use clap::{Arg, ArgAction, Command, crate_version, value_parser};
use fake_tcp::{Socket, Stack};
use fake_tcp::packet::MAX_PACKET_LEN;
use log::{debug, error, info};
use phantun::fec::{parse_fec_spec, peek_frame_len, FecConfig, FecDecoder, FecEncoder, FrameParse};
use phantun::proto::{parse_control_frame, ControlType};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock};
use tokio::time::{self, MissedTickBehavior};
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

const DEFAULT_FEC_FLUSH_MS_STR: &str = "5";
const DEFAULT_FEC_TTL_MS_STR: &str = "200";
const DEFAULT_SERVER_ROTATE_GRACE_MS_STR: &str = "200";
const MAX_FEC_GROUPS: usize = 256;
const CONTROL_READ_TIMEOUT_MS: u64 = 5000;

struct ServerConnection {
    socket: Arc<fake_tcp::Socket>,
    packet_received: Arc<Notify>,
    quit: CancellationToken,
    session_id: u64,
}

struct SessionState {
    udp_local_addr: std::net::SocketAddr,
    active: Arc<ServerConnection>,
}

fn next_session_id() -> u64 {
    static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("fec")
                .long("fec")
                .required(false)
                .value_name("K/N")
                .help("Enable FEC with K data shards and N parity shards, e.g. 8/2")
        )
        .arg(
            Arg::new("fec_flush_ms")
                .long("fec-flush-ms")
                .required(false)
                .value_name("MS")
                .value_parser(value_parser!(u64))
                .help("FEC encoder flush interval in milliseconds")
                .default_value(DEFAULT_FEC_FLUSH_MS_STR)
        )
        .arg(
            Arg::new("fec_ttl_ms")
                .long("fec-ttl-ms")
                .required(false)
                .value_name("MS")
                .value_parser(value_parser!(u64))
                .help("FEC decoder group TTL in milliseconds")
                .default_value(DEFAULT_FEC_TTL_MS_STR)
        )
        .arg(
            Arg::new("rotate_grace_ms")
                .long("rotate-grace-ms")
                .required(false)
                .value_name("MS")
                .value_parser(value_parser!(u64))
                .help("Grace period before closing old connection after session resume")
                .default_value(DEFAULT_SERVER_ROTATE_GRACE_MS_STR)
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;
    let fec_ttl = time::Duration::from_millis(*matches.get_one::<u64>("fec_ttl_ms").unwrap());
    let fec_config = matches
        .get_one::<String>("fec")
        .and_then(|spec| parse_fec_spec(spec))
        .map(|(data_shards, parity_shards)| FecConfig {
            data_shards,
            parity_shards,
            flush_interval: time::Duration::from_millis(
                *matches.get_one::<u64>("fec_flush_ms").unwrap(),
            ),
            group_ttl: fec_ttl,
        });
    let rotate_grace =
        time::Duration::from_millis(*matches.get_one::<u64>("rotate_grace_ms").unwrap());

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .unwrap_or_else(|e| {
            error!(
                "Failed to create TUN device {}: {}. Hint: run as root/CAP_NET_ADMIN and ensure /dev/net/tun exists.",
                tun_name, e
            );
            panic!("failed to create TUN device");
        });

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let sessions: Arc<RwLock<HashMap<u64, Arc<SessionState>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let main_loop = tokio::spawn(async move {

        loop {
            let sock = Arc::new(stack.accept().await);
            info!("New connection: {}", sock);
            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }
            let mut control_buf = [0u8; MAX_PACKET_LEN];
            let Some((control_kind, session_id, first_payload)) =
                read_initial_control(&sock, &mut control_buf).await
            else {
                continue;
            };

            let existing = sessions.read().await.get(&session_id).cloned();
            let udp_local_addr = if let Some(ref state) = existing {
                state.udp_local_addr
            } else {
                match allocate_udp_local_addr(remote_addr).await {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("Unable to allocate UDP local address: {}", e);
                        continue;
                    }
                }
            };

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();
            let entry = Arc::new(ServerConnection {
                socket: sock.clone(),
                packet_received: packet_received.clone(),
                quit: quit.clone(),
                session_id,
            });

            spawn_workers(
                entry.clone(),
                udp_local_addr,
                remote_addr,
                num_cpus,
                first_payload,
                fec_config.clone(),
                fec_ttl,
            );

            spawn_idle_timeout(
                entry.clone(),
                sessions.clone(),
                session_id,
                quit.clone(),
            );

            let state = Arc::new(SessionState {
                udp_local_addr,
                active: entry.clone(),
            });
            sessions.write().await.insert(session_id, state);

            if let Some(old) = existing {
                info!(
                    "Session {} resumed ({:?}), scheduling old connection close",
                    session_id, control_kind
                );
                let old_quit = old.active.quit.clone();
                tokio::spawn(async move {
                    time::sleep(rotate_grace).await;
                    old_quit.cancel();
                });
            } else {
                info!("Session {} started ({:?})", session_id, control_kind);
            }
        }
    });

    tokio::join!(main_loop).0.unwrap()
}

async fn read_initial_control(
    sock: &Socket,
    buf: &mut [u8],
) -> Option<(ControlType, u64, Option<Vec<u8>>)> {
    let size = match time::timeout(
        time::Duration::from_millis(CONTROL_READ_TIMEOUT_MS),
        sock.recv(buf),
    )
    .await
    {
        Ok(Some(size)) => size,
        Ok(None) => {
            info!("Connection closed before control frame");
            return None;
        }
        Err(_) => {
            error!("Timed out waiting for control frame");
            return None;
        }
    };

    if let Some((kind, session_id)) = parse_control_frame(&buf[..size]) {
        return Some((kind, session_id, None));
    }

    debug!("No control frame detected, falling back to legacy session");
    Some((ControlType::Init, next_session_id(), Some(buf[..size].to_vec())))
}

async fn allocate_udp_local_addr(remote_addr: std::net::SocketAddr) -> io::Result<std::net::SocketAddr> {
    let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    let local_addr = udp_sock.local_addr()?;
    drop(udp_sock);
    Ok(local_addr)
}

fn spawn_workers(
    entry: Arc<ServerConnection>,
    udp_local_addr: std::net::SocketAddr,
    remote_addr: std::net::SocketAddr,
    num_cpus: usize,
    first_payload: Option<Vec<u8>>,
    fec_config: Option<FecConfig>,
    fec_ttl: time::Duration,
) {
    for i in 0..num_cpus {
        let entry = entry.clone();
        let sock = entry.socket.clone();
        let quit = entry.quit.clone();
        let packet_received = entry.packet_received.clone();
        let udp_sock = new_udp_reuseport(udp_local_addr);
        let fec_config = fec_config.clone();
        let fec_ttl = fec_ttl;
        let initial_payload = if i == 0 { first_payload.clone() } else { None };

        tokio::spawn(async move {
            let mut buf_udp = [0u8; MAX_PACKET_LEN];
            let mut buf_tcp = [0u8; MAX_PACKET_LEN];
            udp_sock.connect(remote_addr).await.unwrap();
            let mut encoder = fec_config.as_ref().map(|cfg| {
                FecEncoder::new_with_stride(
                    cfg.clone(),
                    MAX_PACKET_LEN,
                    i as u64,
                    num_cpus as u64,
                )
            });
            let mut decoder = FecDecoder::new(fec_ttl, MAX_FEC_GROUPS);
            let mut recv_buffer = Vec::new();
            let mut flush_interval = fec_config.as_ref().map(|cfg| {
                let mut interval = time::interval(cfg.flush_interval);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                interval
            });

            if let Some(payload) = initial_payload {
                let packets = decoder.push(&payload);
                for packet in packets {
                    if let Err(e) = udp_sock.send(&packet).await {
                        error!(
                            "Unable to send UDP packet to {}: {}, closing connection",
                            e, remote_addr
                        );
                        quit.cancel();
                        return;
                    }
                }
                packet_received.notify_one();
            }

            if let Some(ref mut flush_interval) = flush_interval {
                flush_interval.tick().await;
            }

            if encoder.is_some() {
                loop {
                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            if let Some(ref mut encoder) = encoder {
                                let frames = encoder.push(&buf_udp[..size]);
                                for frame in frames {
                                    if sock.send(&frame).await.is_none() {
                                        quit.cancel();
                                        return;
                                    }
                                }
                            }
                            packet_received.notify_one();
                        },
                        res = sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    if size > 0 {
                                        recv_buffer.extend_from_slice(&buf_tcp[..size]);
                                        loop {
                                            if recv_buffer.is_empty() {
                                                break;
                                            }
                                            match peek_frame_len(&recv_buffer) {
                                                FrameParse::Complete(frame_len) => {
                                                    let frame: Vec<u8> =
                                                        recv_buffer.drain(..frame_len).collect();
                                                    let packets = decoder.push(&frame);
                                                    for packet in packets {
                                                        if let Err(e) = udp_sock.send(&packet).await {
                                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                            quit.cancel();
                                                            return;
                                                        }
                                                    }
                                                }
                                                FrameParse::Incomplete => break,
                                                FrameParse::Invalid => {
                                                    let frame = std::mem::take(&mut recv_buffer);
                                                    let packets = decoder.push(&frame);
                                                    for packet in packets {
                                                        if let Err(e) = udp_sock.send(&packet).await {
                                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                            quit.cancel();
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                None => {
                                    quit.cancel();
                                    return;
                                },
                            }

                            packet_received.notify_one();
                        },
                        _ = flush_interval.as_mut().unwrap().tick() => {
                            if let Some(ref mut encoder) = encoder {
                                let frames = encoder.flush();
                                for frame in frames {
                                    if sock.send(&frame).await.is_none() {
                                        quit.cancel();
                                        return;
                                    }
                                }
                            }
                        },
                        _ = quit.cancelled() => {
                            debug!("worker {} terminated (session {})", i, entry.session_id);
                            return;
                        },
                    };
                }
            } else {
                loop {
                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            if sock.send(&buf_udp[..size]).await.is_none() {
                                quit.cancel();
                                return;
                            }

                            packet_received.notify_one();
                        },
                        res = sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    if size > 0 {
                                        recv_buffer.extend_from_slice(&buf_tcp[..size]);
                                        loop {
                                            if recv_buffer.is_empty() {
                                                break;
                                            }
                                            match peek_frame_len(&recv_buffer) {
                                                FrameParse::Complete(frame_len) => {
                                                    let frame: Vec<u8> =
                                                        recv_buffer.drain(..frame_len).collect();
                                                    let packets = decoder.push(&frame);
                                                    for packet in packets {
                                                        if let Err(e) = udp_sock.send(&packet).await {
                                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                            quit.cancel();
                                                            return;
                                                        }
                                                    }
                                                }
                                                FrameParse::Incomplete => break,
                                                FrameParse::Invalid => {
                                                    let frame = std::mem::take(&mut recv_buffer);
                                                    let packets = decoder.push(&frame);
                                                    for packet in packets {
                                                        if let Err(e) = udp_sock.send(&packet).await {
                                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                            quit.cancel();
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                None => {
                                    quit.cancel();
                                    return;
                                },
                            }

                            packet_received.notify_one();
                        },
                        _ = quit.cancelled() => {
                            debug!("worker {} terminated (session {})", i, entry.session_id);
                            return;
                        },
                    };
                }
            }
        });
    }
}

fn spawn_idle_timeout(
    entry: Arc<ServerConnection>,
    sessions: Arc<RwLock<HashMap<u64, Arc<SessionState>>>>,
    session_id: u64,
    quit: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let read_timeout = time::sleep(UDP_TTL);
            let packet_received_fut = entry.packet_received.notified();

            tokio::select! {
                _ = read_timeout => {
                    info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                    remove_if_current(&sessions, session_id, &entry).await;
                    quit.cancel();
                    return;
                },
                _ = quit.cancelled() => {
                    remove_if_current(&sessions, session_id, &entry).await;
                    return;
                },
                _ = packet_received_fut => {},
            }
        }
    });
}

async fn remove_if_current(
    sessions: &Arc<RwLock<HashMap<u64, Arc<SessionState>>>>,
    session_id: u64,
    entry: &Arc<ServerConnection>,
) {
    let mut map = sessions.write().await;
    let Some(state) = map.get(&session_id) else {
        return;
    };
    if Arc::ptr_eq(&state.active, entry) {
        map.remove(&session_id);
    }
}
