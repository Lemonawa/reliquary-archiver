//! Replay private capture fixtures without storing account data in the repo.
//! Input records: little-endian u32 length followed by an Ethernet frame.
//! cargo run --release --example replay_frames -- <frames.bin> <export.json> [baseline.json]

#[path = "../src/capture/compat.rs"]
mod compat;

use reliquary::network::{GamePacket, GameSniffer};
use reliquary_archiver::export::{Exporter, fribbels::OptimizerExporter};
use std::{collections::HashMap, env, fs, time::Instant};

fn main() {
    let args: Vec<_> = env::args().collect();
    assert!(args.len() >= 3, "expected frames.bin export.json [baseline.json]");
    let input = fs::read(&args[1]).unwrap();
    let mut recovery = compat::Recovery::default();
    let mut sniffers = HashMap::<u64, GameSniffer>::new();
    let mut exporter = OptimizerExporter::new();
    let (mut commands, mut errors) = (0, 0);
    let mut consume = |frames: Vec<compat::Frame>| {
        for frame in frames {
            match sniffers.entry(frame.source).or_default().receive_packet(frame.data) {
                Ok(packets) => {
                    for packet in packets {
                        if let GamePacket::Commands { result, .. } = packet {
                            match result {
                                Ok(command) => {
                                    commands += 1;
                                    exporter.read_command(command);
                                }
                                Err(_) => errors += 1,
                            }
                        }
                    }
                }
                Err(_) => errors += 1,
            }
        }
    };
    let mut offset = 0;
    while offset < input.len() {
        let size = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        consume(recovery.push(&input[offset..offset + size], Instant::now()));
        offset += size;
    }
    consume(recovery.flush(Instant::now(), true));
    assert_eq!(errors, 0, "capture command integrity checks");
    assert!(exporter.is_initialized(), "complete inventory and character initialization");
    let encoded = serde_json::to_vec_pretty(&exporter.export().unwrap()).unwrap();
    let output: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    fs::write(&args[2], encoded).unwrap();
    if let Some(path) = args.get(3) {
        let baseline: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        for field in ["relics", "light_cones", "characters", "materials"] {
            assert!(output[field] == baseline[field], "baseline mismatch in {field}");
        }
    }
    println!(
        "commands={commands} errors={errors} initialized=true relics={} light_cones={} character_forms={}",
        output["relics"].as_array().unwrap().len(),
        output["light_cones"].as_array().unwrap().len(),
        output["characters"].as_array().unwrap().len()
    );
}
