//! NetLogAnalyzer — AI-powered Network Log Analyzer / Intrusion Detection System
//!
//! Architecture:
//!   Rust backend captures and parses packets, runs detection modules,
//!   and broadcasts packet + alert events to WebSocket clients in real time.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use chrono::Utc;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "net-log-analyzer",
    about = "Network packet analyzer with intrusion detection and WebSocket streaming"
)]
struct Cli {
    /// Network interface to sniff (e.g. eth0, en0). Omit to use the default device.
    #[arg(short, long)]
    interface: Option<String>,

    /// Number of unique destination ports an IP must hit within the time window
    /// before it is flagged as a port scan.
    #[arg(long, default_value_t = 20)]
    scan_threshold: usize,

    /// Rolling time window (seconds) used by the port scan detector.
    #[arg(long, default_value_t = 10)]
    window_secs: u64,

    /// Host interface for the Axum server.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Port for the Axum server.
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

// ─── Data model ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PacketData {
    pub timestamp: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// "TCP", "UDP", "ICMP", "OTHER"
    pub protocol: String,
    /// Total IP payload length in bytes.
    pub payload_size: u16,
    /// Optional alert raised by a detection module.
    pub alert: Option<Alert>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    pub module: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum WsEvent {
    Packet(PacketData),
    Alert(Alert),
}

// ─── Detection engine trait ────────────────────────────────────────────────────

pub trait DetectionEngine: Send + Sync {
    fn inspect(&mut self, packet: &PacketData) -> Option<Alert>;
}

// ─── Port-scan detector ────────────────────────────────────────────────────────

pub struct PortScanModule {
    state: HashMap<String, (Instant, HashSet<u16>, bool)>,
    threshold: usize,
    window: Duration,
}

impl PortScanModule {
    pub fn new(threshold: usize, window_secs: u64) -> Self {
        Self {
            state: HashMap::new(),
            threshold,
            window: Duration::from_secs(window_secs),
        }
    }
}

impl DetectionEngine for PortScanModule {
    fn inspect(&mut self, packet: &PacketData) -> Option<Alert> {
        let src = packet.src_ip.as_deref()?;
        let dst_port = packet.dst_port?;

        let now = Instant::now();
        let entry = self
            .state
            .entry(src.to_owned())
            .or_insert_with(|| (now, HashSet::new(), false));

        if now.duration_since(entry.0) > self.window {
            *entry = (now, HashSet::new(), false);
        }

        entry.1.insert(dst_port);

        if entry.1.len() >= self.threshold && !entry.2 {
            entry.2 = true;
            Some(Alert {
                module: "PortScanDetector".to_owned(),
                severity: Severity::High,
                message: format!(
                    "Potential port scan from {src}: {} unique ports probed in {}s",
                    entry.1.len(),
                    self.window.as_secs()
                ),
            })
        } else {
            None
        }
    }
}

// ─── Packet parser ─────────────────────────────────────────────────────────────

fn parse_packet(raw: &[u8]) -> Option<PacketData> {
    if raw.len() < 14 {
        return None;
    }

    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

    match ether_type {
        0x0800 => parse_ipv4(&raw[14..]),
        0x86DD => parse_ipv6(&raw[14..]),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8]) -> Option<PacketData> {
    if ip.len() < 20 {
        return None;
    }

    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    let protocol_byte = ip[9];

    let src_ip = Some(format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = Some(format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]));

    let payload = ip.get(ihl..)?;
    let payload_size = total_len.saturating_sub(ihl as u16);

    extract_transport(src_ip, dst_ip, protocol_byte, payload, payload_size)
}

fn parse_ipv6(ip: &[u8]) -> Option<PacketData> {
    if ip.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
    let next_header = ip[6];

    let src_bytes: [u8; 16] = ip[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = ip[24..40].try_into().ok()?;

    let src_ip = Some(IpAddr::from(src_bytes).to_string());
    let dst_ip = Some(IpAddr::from(dst_bytes).to_string());

    let payload = ip.get(40..)?;

    extract_transport(src_ip, dst_ip, next_header, payload, payload_len)
}

fn extract_transport(
    src_ip: Option<String>,
    dst_ip: Option<String>,
    protocol_byte: u8,
    payload: &[u8],
    payload_size: u16,
) -> Option<PacketData> {
    let (protocol, src_port, dst_port) = match protocol_byte {
        6 if payload.len() >= 4 => {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            ("TCP".to_owned(), Some(sp), Some(dp))
        }
        17 if payload.len() >= 4 => {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            ("UDP".to_owned(), Some(sp), Some(dp))
        }
        1 | 58 => ("ICMP".to_owned(), None, None),
        _ => ("OTHER".to_owned(), None, None),
    };

    Some(PacketData {
        timestamp: Utc::now().to_rfc3339(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        payload_size,
        alert: None,
    })
}

// ─── Capture loop ─────────────────────────────────────────────────────────────

fn capture_thread(
    device_name: String,
    tx: mpsc::Sender<PacketData>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cap = Capture::from_device(device_name.as_str())
        .map_err(|e| format!("Failed to open device '{device_name}': {e}"))?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| {
            if e.to_string().to_lowercase().contains("permission") {
                format!(
                    "Permission denied opening '{device_name}'. Try running with sudo or granting CAP_NET_RAW."
                )
            } else {
                format!("Failed to activate capture on '{device_name}': {e}")
            }
        })?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(parsed) = parse_packet(packet.data) {
                    if tx.blocking_send(parsed).is_err() {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Capture error: {e}");
                break;
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
struct AppState {
    ws_tx: broadcast::Sender<String>,
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state.ws_tx.subscribe()))
}

async fn handle_socket(socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    let (mut sender, mut receiver) = socket.split();

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Binary(_) => {}
            }
        }
    });

    while !recv_task.is_finished() {
        match rx.recv().await {
            Ok(payload) => {
                if sender
                    .send(Message::Text(Utf8Bytes::from(payload)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    recv_task.abort();
}

fn send_ws_event(tx: &broadcast::Sender<String>, event: &WsEvent) {
    match serde_json::to_string(event) {
        Ok(payload) => {
            let _ = tx.send(payload);
        }
        Err(e) => eprintln!("WebSocket serialisation error: {e}"),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let device_name = match cli.interface {
        Some(ref iface) => iface.clone(),
        None => match Device::lookup() {
            Ok(Some(dev)) => dev.name,
            Ok(None) => {
                eprintln!("No default network device found. Use --interface to specify one.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error looking up default device: {e}");
                std::process::exit(1);
            }
        },
    };

    eprintln!("NetLogAnalyzer starting on interface: {device_name}");
    eprintln!(
        "Port-scan threshold: {} ports / {}s window",
        cli.scan_threshold, cli.window_secs
    );

    let engine: Arc<Mutex<Box<dyn DetectionEngine>>> = Arc::new(Mutex::new(Box::new(
        PortScanModule::new(cli.scan_threshold, cli.window_secs),
    )));

    let (packet_tx, mut packet_rx) = mpsc::channel::<PacketData>(4096);
    let (ws_tx, _) = broadcast::channel::<String>(4096);

    let spawn_device = device_name.clone();
    let capture_task = tokio::task::spawn_blocking(move || {
        if let Err(e) = capture_thread(spawn_device, packet_tx) {
            eprintln!("Fatal capture error: {e}");
        }
    });

    let ws_event_tx = ws_tx.clone();
    let engine_ref = engine.clone();
    tokio::spawn(async move {
        while let Some(mut packet) = packet_rx.recv().await {
            {
                let mut eng = engine_ref.lock().await;
                packet.alert = eng.inspect(&packet);
            }

            send_ws_event(&ws_event_tx, &WsEvent::Packet(packet.clone()));
            if let Some(alert) = packet.alert {
                send_ws_event(&ws_event_tx, &WsEvent::Alert(alert));
            }
        }
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws", get(ws_handler))
        .with_state(AppState { ws_tx: ws_tx.clone() });

    let bind_addr = format!("{}:{}", cli.host, cli.port);
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind Axum server on {bind_addr}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("WebSocket server listening on ws://{bind_addr}/ws");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {e}");
    }

    let _ = capture_task.await;
}
