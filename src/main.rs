//! NetLogAnalyzer — AI-powered Network Log Analyzer / Intrusion Detection System
//!
//! Architecture:
//!   Rust core (this binary) captures and parses packets, runs detection modules,
//!   then emits one JSON object per line to stdout so a downstream consumer
//!   (e.g. a Node.js/TypeScript dashboard) can ingest the stream via a Unix pipe.
//!
//! Usage:
//!   sudo net-log-analyzer --interface eth0 [--scan-threshold 20] [--window-secs 10]

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use clap::Parser;
use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "net-log-analyzer",
    about = "High-performance network packet analyzer with intrusion detection"
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
}

// ─── Data model ───────────────────────────────────────────────────────────────

/// Every captured packet is serialised into this struct and emitted as one JSON line.
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketData {
    /// RFC-3339 timestamp of capture.
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Alert {
    pub module: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// ─── Detection engine trait ────────────────────────────────────────────────────

/// Every anomaly-detection module implements this trait.
/// Additional modules (DDoS detector, zero-day heuristics, ML scorer, …) can be
/// plugged in without touching the capture loop.
pub trait DetectionEngine: Send + Sync {
    /// Inspect a parsed packet and optionally return an alert.
    fn inspect(&mut self, packet: &PacketData) -> Option<Alert>;
}

// ─── Port-scan detector ────────────────────────────────────────────────────────

/// Tracks the unique destination ports contacted by each source IP within a
/// rolling time window.  When the count exceeds `threshold` the source IP is
/// flagged as performing a port scan.
pub struct PortScanModule {
    /// source IP → (window start, set of distinct dst ports seen, alert already raised)
    state: HashMap<String, (Instant, HashSet<u16>, bool)>,
    /// Ports-per-window threshold before an alert is raised.
    threshold: usize,
    /// Length of the rolling window.
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
        // Only track packets that have both a source IP and a destination port.
        let src = packet.src_ip.as_deref()?;
        let dst_port = packet.dst_port?;

        let now = Instant::now();
        let entry = self
            .state
            .entry(src.to_owned())
            .or_insert_with(|| (now, HashSet::new(), false));

        // Reset the window if it has expired.
        if now.duration_since(entry.0) > self.window {
            *entry = (now, HashSet::new(), false);
        }

        entry.1.insert(dst_port);

        // Only emit one alert per source IP per window to avoid alert storms.
        if entry.1.len() >= self.threshold && !entry.2 {
            entry.2 = true; // mark as alerted for this window
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

/// Parse a raw pcap packet buffer into a `PacketData`.
/// Supports Ethernet frames carrying IPv4/IPv6 with TCP, UDP, or ICMP.
fn parse_packet(raw: &[u8]) -> Option<PacketData> {
    // Minimum Ethernet header: 14 bytes.
    if raw.len() < 14 {
        return None;
    }

    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

    match ether_type {
        // IPv4
        0x0800 => parse_ipv4(&raw[14..]),
        // IPv6
        0x86DD => parse_ipv6(&raw[14..]),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8]) -> Option<PacketData> {
    // Minimum IPv4 header: 20 bytes.
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
    // Minimum IPv6 header: 40 bytes.
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
        // TCP
        6 if payload.len() >= 4 => {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            ("TCP".to_owned(), Some(sp), Some(dp))
        }
        // UDP
        17 if payload.len() >= 4 => {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            ("UDP".to_owned(), Some(sp), Some(dp))
        }
        // ICMP / ICMPv6
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

/// Runs in a dedicated blocking thread (pcap is synchronous) and sends parsed
/// packets over a tokio channel to the async analysis task.
fn capture_thread(
    device_name: String,
    tx: tokio::sync::mpsc::Sender<PacketData>,
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
                    "Permission denied opening '{device_name}'. \
                     Try running with sudo or granting CAP_NET_RAW."
                )
            } else {
                format!("Failed to activate capture on '{device_name}': {e}")
            }
        })?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(parsed) = parse_packet(packet.data) {
                    // If the async receiver has been dropped, exit cleanly.
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

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Resolve device name.
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

    // Build the detection pipeline.
    // Arc<Mutex<…>> lets us share the engine across the async boundary.
    let engine: Arc<Mutex<Box<dyn DetectionEngine>>> = Arc::new(Mutex::new(Box::new(
        PortScanModule::new(cli.scan_threshold, cli.window_secs),
    )));

    // Channel bridging the blocking capture thread and the async analysis task.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketData>(4096);

    // Spawn the blocking pcap loop in a dedicated OS thread so it never starves
    // the tokio executor.
    let spawn_device = device_name.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = capture_thread(spawn_device, tx) {
            eprintln!("Fatal capture error: {e}");
            std::process::exit(1);
        }
    });

    // Async analysis + output loop.
    while let Some(mut packet) = rx.recv().await {
        // Run every detection module.
        {
            let mut eng = engine.lock().await;
            packet.alert = eng.inspect(&packet);
        }

        // Serialise to a single JSON line and flush to stdout.
        match serde_json::to_string(&packet) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("Serialisation error: {e}"),
        }
    }
}
