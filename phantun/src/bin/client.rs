use clap::{Arg, ArgAction, Command, crate_version, value_parser};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use phantun::fec::{FecConfig, FecDecoder, FecEncoder, parse_fec_spec};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport, udp_recv_pktinfo};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::time::{self, MissedTickBehavior};
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

const DEFAULT_FEC_FLUSH_MS_STR: &str = "5";
const DEFAULT_FEC_TTL_MS_STR: &str = "200";
const DEFAULT_ROTATE_GRACE_MS_STR: &str = "200";
const MAX_FEC_GROUPS: usize = 256;

struct ConnectionEntry {
    socket: Arc<Socket>,
    udp_local_addr: IpAddr,
    packet_received: Arc<Notify>,
    quit: CancellationToken,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the server.\n\
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
            Arg::new("rotate_interval")
                .long("rotate-interval")
                .required(false)
                .value_name("SECONDS")
                .help("Periodically rebuild fake TCP connections to rotate source port")
        )
        .arg(
            Arg::new("rotate_grace_ms")
                .long("rotate-grace-ms")
                .required(false)
                .value_name("MS")
                .value_parser(value_parser!(u64))
                .help("Grace period before closing old connection after rotation")
                .default_value(DEFAULT_ROTATE_GRACE_MS_STR)
        )
        .get_matches();

    let local_addr: SocketAddr = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local address");

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
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
    let fec_config = matches
        .get_one::<String>("fec")
        .and_then(|spec| parse_fec_spec(spec))
        .map(|(data_shards, parity_shards)| FecConfig {
            data_shards,
            parity_shards,
            flush_interval: time::Duration::from_millis(
                *matches.get_one::<u64>("fec_flush_ms").unwrap(),
            ),
            group_ttl: time::Duration::from_millis(*matches.get_one::<u64>("fec_ttl_ms").unwrap()),
        });
    let rotate_interval = matches
        .get_one::<String>("rotate_interval")
        .and_then(|value| value.parse::<u64>().ok())
        .map(time::Duration::from_secs);
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

    if remote_addr.is_ipv6() {
        assign_ipv6_address(tun[0].name(), tun_local6.unwrap(), tun_peer6.unwrap());
    }

    info!("Created TUN device {}", tun[0].name());

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(
        HashMap::<SocketAddr, Arc<ConnectionEntry>>::new(),
    ));
    let (rotate_tx, mut rotate_rx) = mpsc::unbounded_channel::<SocketAddr>();

    let mut stack = Stack::new(tun, tun_peer, tun_peer6);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            tokio::select! {
                res = udp_recv_pktinfo(&udp_sock, &mut buf_r) => {
                    let (size, udp_remote_addr, udp_local_addr) = res?;
                    let payload = &buf_r[..size];
                    handle_udp_packet(
                        payload,
                        udp_remote_addr,
                        udp_local_addr,
                        &connections,
                        &mut stack,
                        remote_addr,
                        local_addr,
                        num_cpus,
                        handshake_packet.as_ref(),
                        fec_config.clone(),
                        rotate_interval,
                        rotate_tx.clone(),
                    )
                    .await;
                }
                Some(udp_remote_addr) = rotate_rx.recv() => {
                    handle_rotate_request(
                        udp_remote_addr,
                        &connections,
                        &mut stack,
                        remote_addr,
                        local_addr,
                        num_cpus,
                        handshake_packet.as_ref(),
                        fec_config.clone(),
                        rotate_interval,
                        rotate_grace,
                        rotate_tx.clone(),
                    )
                    .await;
                }
            }
        }
    });

    tokio::join!(main_loop).0.unwrap()
}

async fn handle_udp_packet(
    payload: &[u8],
    udp_remote_addr: SocketAddr,
    udp_local_addr: IpAddr,
    connections: &Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionEntry>>>>,
    stack: &mut Stack,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    num_cpus: usize,
    handshake_packet: Option<&Vec<u8>>,
    fec_config: Option<FecConfig>,
    rotate_interval: Option<time::Duration>,
    rotate_tx: mpsc::UnboundedSender<SocketAddr>,
) {
    // seen UDP packet to listening socket, this means:
    // 1. It is a new UDP connection, or
    // 2. It is some extra packets not filtered by more specific
    //    connected UDP socket yet
    if let Some(entry) = connections.read().await.get(&udp_remote_addr) {
        entry.socket.send(payload).await;
        return;
    }

    info!("New UDP client from {}", udp_remote_addr);
    let Some(entry) = build_connection(
        udp_remote_addr,
        udp_local_addr,
        Some(payload.to_vec()),
        connections,
        stack,
        remote_addr,
        local_addr,
        num_cpus,
        handshake_packet,
        fec_config,
        rotate_interval,
        rotate_tx,
    )
    .await
    else {
        return;
    };

    connections.write().await.insert(udp_remote_addr, entry);
}

async fn handle_rotate_request(
    udp_remote_addr: SocketAddr,
    connections: &Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionEntry>>>>,
    stack: &mut Stack,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    num_cpus: usize,
    handshake_packet: Option<&Vec<u8>>,
    fec_config: Option<FecConfig>,
    rotate_interval: Option<time::Duration>,
    rotate_grace: time::Duration,
    rotate_tx: mpsc::UnboundedSender<SocketAddr>,
) {
    let current = connections.read().await.get(&udp_remote_addr).cloned();
    let Some(current) = current else {
        return;
    };

    info!("Rotating fake TCP connection for {}", udp_remote_addr);
    let Some(entry) = build_connection(
        udp_remote_addr,
        current.udp_local_addr,
        None,
        connections,
        stack,
        remote_addr,
        local_addr,
        num_cpus,
        handshake_packet,
        fec_config,
        rotate_interval,
        rotate_tx,
    )
    .await
    else {
        return;
    };

    connections.write().await.insert(udp_remote_addr, entry);

    let quit = current.quit.clone();
    tokio::spawn(async move {
        time::sleep(rotate_grace).await;
        quit.cancel();
    });
}

async fn build_connection(
    udp_remote_addr: SocketAddr,
    udp_local_addr: IpAddr,
    first_payload: Option<Vec<u8>>,
    connections: &Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionEntry>>>>,
    stack: &mut Stack,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    num_cpus: usize,
    handshake_packet: Option<&Vec<u8>>,
    fec_config: Option<FecConfig>,
    rotate_interval: Option<time::Duration>,
    rotate_tx: mpsc::UnboundedSender<SocketAddr>,
) -> Option<Arc<ConnectionEntry>> {
    let sock = stack.connect(remote_addr).await?;
    let sock = Arc::new(sock);
    if let Some(p) = handshake_packet {
        if sock.send(p).await.is_none() {
            error!("Failed to send handshake packet to remote, closing connection.");
            return None;
        }

        debug!("Sent handshake packet to: {}", sock);
    }

    let packet_received = Arc::new(Notify::new());
    let quit = CancellationToken::new();
    let entry = Arc::new(ConnectionEntry {
        socket: sock.clone(),
        udp_local_addr,
        packet_received: packet_received.clone(),
        quit: quit.clone(),
    });

    spawn_workers(
        entry.clone(),
        udp_remote_addr,
        local_addr,
        remote_addr,
        num_cpus,
        first_payload,
        fec_config.clone(),
    );

    spawn_idle_timeout(
        entry.clone(),
        udp_remote_addr,
        connections.clone(),
        quit.clone(),
    );

    if let Some(interval) = rotate_interval {
        let mut interval = time::interval(interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let rotate_quit = quit.clone();
        tokio::spawn(async move {
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = rotate_tx.send(udp_remote_addr);
                    }
                    _ = rotate_quit.cancelled() => {
                        return;
                    }
                }
            }
        });
    }

    Some(entry)
}

fn spawn_workers(
    entry: Arc<ConnectionEntry>,
    udp_remote_addr: SocketAddr,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    num_cpus: usize,
    first_payload: Option<Vec<u8>>,
    fec_config: Option<FecConfig>,
) {
    for i in 0..num_cpus {
        let sock = entry.socket.clone();
        let quit = entry.quit.clone();
        let packet_received = entry.packet_received.clone();
        let udp_local_addr = entry.udp_local_addr;
        let fec_config = fec_config.clone();
        let initial_payload = if i == 0 { first_payload.clone() } else { None };

        tokio::spawn(async move {
            let mut buf_udp = [0u8; MAX_PACKET_LEN];
            let mut buf_tcp = [0u8; MAX_PACKET_LEN];
            // Always reply from the same address that the peer used to communicate with
            // us. This avoids a frequent problem with IPv6 privacy extensions when we
            // erroneously bind to wrong short-lived temporary address even if the peer
            // explicitly used a persistent address to communicate to us.
            //
            // To do so, first bind to (<incoming packet dst_ip>, <local addr port>), and then
            // connect to (<incoming packet src_ip>, <incoming packet src_port>).
            let bind_addr = match (udp_remote_addr, udp_local_addr) {
                (SocketAddr::V4(_), IpAddr::V4(udp_local_ipv4)) => {
                    SocketAddr::V4(SocketAddrV4::new(udp_local_ipv4, local_addr.port()))
                }
                (SocketAddr::V6(udp_remote_addr), IpAddr::V6(udp_local_ipv6)) => {
                    SocketAddr::V6(SocketAddrV6::new(
                        udp_local_ipv6,
                        local_addr.port(),
                        udp_remote_addr.flowinfo(),
                        udp_remote_addr.scope_id(),
                    ))
                }
                (_, _) => {
                    panic!(
                        "unexpected family combination for udp_remote_addr={udp_remote_addr} and udp_local_addr={udp_local_addr}"
                    );
                }
            };
            let udp_sock = new_udp_reuseport(bind_addr);
            udp_sock.connect(udp_remote_addr).await.unwrap();

            let mut encoder = fec_config
                .as_ref()
                .map(|cfg| FecEncoder::new(cfg.clone(), MAX_PACKET_LEN));
            let mut decoder = fec_config
                .as_ref()
                .map(|cfg| FecDecoder::new(cfg.group_ttl, MAX_FEC_GROUPS));
            let mut flush_interval = fec_config.as_ref().map(|cfg| {
                let mut interval = time::interval(cfg.flush_interval);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                interval
            });

            if let Some(payload) = initial_payload {
                if let Some(ref mut encoder) = encoder {
                    let frames = encoder.push(&payload);
                    for frame in frames {
                        if sock.send(&frame).await.is_none() {
                            quit.cancel();
                            return;
                        }
                    }
                } else if sock.send(&payload).await.is_none() {
                    quit.cancel();
                    return;
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
                                        if let Some(ref mut decoder) = decoder {
                                            let packets = decoder.push(&buf_tcp[..size]);
                                            for packet in packets {
                                                if let Err(e) = udp_sock.send(&packet).await {
                                                    error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                    quit.cancel();
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                },
                                None => {
                                    debug!("removed fake TCP socket from connections table");
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
                            debug!("worker {} terminated", i);
                            return;
                        },
                    };
                }
            } else {
                loop {
                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            if sock.send(&buf_udp[..size]).await.is_none() {
                                debug!("removed fake TCP socket from connections table");
                                quit.cancel();
                                return;
                            }

                            packet_received.notify_one();
                        },
                        res = sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    if size > 0
                                        && let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                            quit.cancel();
                                            return;
                                        }
                                },
                                None => {
                                    debug!("removed fake TCP socket from connections table");
                                    quit.cancel();
                                    return;
                                },
                            }

                            packet_received.notify_one();
                        },
                        _ = quit.cancelled() => {
                            debug!("worker {} terminated", i);
                            return;
                        },
                    };
                }
            }
        });
    }
}

fn spawn_idle_timeout(
    entry: Arc<ConnectionEntry>,
    udp_remote_addr: SocketAddr,
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionEntry>>>>,
    quit: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let read_timeout = time::sleep(UDP_TTL);
            let packet_received_fut = entry.packet_received.notified();

            tokio::select! {
                _ = read_timeout => {
                    info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                    remove_if_current(&connections, udp_remote_addr, &entry).await;
                    debug!("removed fake TCP socket from connections table");

                    quit.cancel();
                    return;
                },
                _ = quit.cancelled() => {
                    remove_if_current(&connections, udp_remote_addr, &entry).await;
                    debug!("removed fake TCP socket from connections table");
                    return;
                },
                _ = packet_received_fut => {},
            }
        }
    });
}

async fn remove_if_current(
    connections: &Arc<RwLock<HashMap<SocketAddr, Arc<ConnectionEntry>>>>,
    udp_remote_addr: SocketAddr,
    entry: &Arc<ConnectionEntry>,
) {
    let mut map = connections.write().await;
    let Some(current) = map.get(&udp_remote_addr) else {
        return;
    };
    if Arc::ptr_eq(current, entry) {
        map.remove(&udp_remote_addr);
    }
}
