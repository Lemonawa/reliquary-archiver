use std::path::PathBuf;
use std::time::{Duration, Instant};

use ::pktmon::filter::{DataLinkProtocol, PktMonFilter, TransportProtocol};
use ::pktmon::{Capture, PacketPayload};
use futures::StreamExt;
use tracing::{info, instrument, warn};

use super::compat::Recovery;
use super::*;

pub struct PktmonBackend;

#[derive(Debug)]
pub struct PktmonCaptureDevice;

impl DeviceBackend for PktmonBackend {
    type Device = PktmonCaptureDevice;

    fn list_devices(&self) -> Result<Vec<Self::Device>> {
        // PktMon doesn't need device selection - it captures all interfaces
        Ok(vec![PktmonCaptureDevice])
    }

    fn device_name(_device: &Self::Device) -> String {
        "pktmon".to_string()
    }

    #[instrument(skip_all)]
    fn open_device(_device: &Self::Device) -> Result<PacketStream> {
        let mut capture = Capture::new().map_err(|e| CaptureError::Capture(Box::new(e)))?;

        for port in [GAME_PORTS.0, GAME_PORTS.1] {
            let filter = PktMonFilter {
                name: "UDP Filter".to_string(),
                transport_protocol: Some(TransportProtocol::UDP),
                port: port.into(),
                ..PktMonFilter::default()
            };

            capture.add_filter(filter).map_err(|e| CaptureError::Filter(Box::new(e)))?;
        }

        // Windows' UDP filter misses received packets inside PPPoE Session
        // frames. Capture that EtherType too, then select game UDP in userland.
        capture
            .add_filter(PktMonFilter {
                name: "PPPoE Session".into(),
                data_link_protocol: Some(DataLinkProtocol::Custom(0x8864)),
                ..PktMonFilter::default()
            })
            .map_err(|e| CaptureError::Filter(Box::new(e)))?;

        capture.start().map_err(|e| CaptureError::Capture(Box::new(e)))?;

        let mut stream = capture.stream().map_err(|e| CaptureError::Capture(Box::new(e)))?;
        info!("PPPoE/IPv6 server capture and complete-message KCP recovery enabled");
        Ok(async_stream::stream! {
            let mut recovery = Recovery::default();
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            loop {
                let frames = tokio::select! {
                    packet = stream.next() => match packet {
                        Some(packet) => match packet.payload {
                            PacketPayload::Ethernet(bytes) => recovery.push(&bytes, Instant::now()),
                            _ => Vec::new(),
                        },
                        None => break,
                    },
                    _ = tick.tick() => recovery.flush(Instant::now(), false),
                };
                for frame in frames {
                    yield Ok(Packet { source_id: frame.source, data: frame.data });
                }
            }
        }
        .boxed())
    }
}

/// Reads packets from a recorded .etl file
pub struct EtlFileSource {
    path: PathBuf,
}

impl EtlFileSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl PacketSource for EtlFileSource {
    #[instrument(skip_all)]
    fn open(self: Box<Self>) -> Result<PacketStream> {
        info!("Capturing from etl file: {}", self.path.display());
        Ok(blocking_stream(move |send| {
            if let Err(error) = replay_etl(&self.path, send) {
                warn!(%error, "ETL replay failed");
            }
        }))
    }
}

fn replay_etl(path: &std::path::Path, send: &mut dyn FnMut(Packet) -> bool) -> std::io::Result<()> {
    use std::io::{BufReader, Read};
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temp = std::env::temp_dir().join(format!(
        "reliquary-{}-{}.pcapng",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Temp(temp.clone());
    let output = Command::new("pktmon.exe")
        .arg("etl2pcap")
        .arg(path)
        .arg("--out")
        .arg(&temp)
        .creation_flags(0x08000000)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(String::from_utf8_lossy(&output.stderr).into_owned()));
    }
    let mut input = BufReader::new(std::fs::File::open(temp)?);
    let mut recovery = Recovery::default();
    loop {
        let mut header = [0; 8];
        match input.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
        let size = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if !(12..=1024 * 1024).contains(&size) || size % 4 != 0 {
            return Err(std::io::Error::other("Invalid pktmon pcapng block"));
        }
        let mut body = vec![0; size - 8];
        input.read_exact(&mut body)?;
        if u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap()) as usize != size {
            return Err(std::io::Error::other("Invalid pcapng trailer"));
        }
        if kind == 0x0a0d0d0a && body.get(..4) != Some(&[0x4d, 0x3c, 0x2b, 0x1a]) {
            return Err(std::io::Error::other("Expected little-endian pktmon pcapng"));
        }
        if kind == 6 && body.len() >= 24 {
            let len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            if let Some(frame) = body.get(20..20 + len) {
                for f in recovery.push(frame, Instant::now()) {
                    if !send(Packet {
                        source_id: f.source,
                        data: f.data,
                    }) {
                        return Ok(());
                    }
                }
            }
        }
    }
    for f in recovery.flush(Instant::now(), true) {
        if !send(Packet {
            source_id: f.source,
            data: f.data,
        }) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reliquary::network::{GamePacket, GameSniffer};
    use reliquary_archiver::export::{Exporter, fribbels::OptimizerExporter};

    /// Exercises ETL conversion, EOF, normalization, recovery and export together.
    /// Fixtures remain outside the repository.
    #[test]
    #[ignore = "Set HSR_TEST_ETL and HSR_TEST_BASELINE to private capture fixtures"]
    fn private_etl_matches_reference_export() {
        let path = std::env::var_os("HSR_TEST_ETL").expect("HSR_TEST_ETL");
        let baseline = std::env::var_os("HSR_TEST_BASELINE").expect("HSR_TEST_BASELINE");
        let mut sniffers = HashMap::<u64, GameSniffer>::new();
        let mut exporter = OptimizerExporter::new();
        replay_etl(std::path::Path::new(&path), &mut |packet| {
            for event in sniffers.entry(packet.source_id).or_default().receive_packet(packet.data).unwrap() {
                if let GamePacket::Commands { result, .. } = event {
                    exporter.read_command(result.unwrap());
                }
            }
            true
        })
        .unwrap();
        assert!(exporter.is_initialized());
        let encoded = serde_json::to_vec(&exporter.export().unwrap()).unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let expected: serde_json::Value = serde_json::from_slice(&std::fs::read(baseline).unwrap()).unwrap();
        for field in ["relics", "light_cones", "characters", "materials"] {
            assert!(actual[field] == expected[field], "reference mismatch: {field}");
        }
    }
}
