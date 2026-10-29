//! End-to-end smoke tests for the perf binaries.

#![cfg(feature = "tokio")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected Ok(..), got Err({err:?})"),
    }
}

fn some<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("expected Some(..), got None"),
    }
}

fn bin_path(name: &str, fallback_name: &str) -> PathBuf {
    if let Ok(path) = std::env::var(name) {
        return PathBuf::from(path);
    }

    let exe = ok(std::env::current_exe());
    let target_dir = some(some(exe.parent()).parent());
    let path = target_dir.join(format!("{fallback_name}{}", std::env::consts::EXE_SUFFIX));
    if path.exists() {
        return path;
    }

    panic!("could not locate {fallback_name} binary");
}

#[test]
fn local_and_remote_thr_smoke() {
    let reserved = ok(std::net::TcpListener::bind("127.0.0.1:0"));
    let endpoint = format!("tcp://{}", ok(reserved.local_addr()));
    drop(reserved);

    let local_thr = bin_path("CARGO_BIN_EXE_local_thr", "local_thr");
    let remote_thr = bin_path("CARGO_BIN_EXE_remote_thr", "remote_thr");
    let mut receiver = ok(Command::new(&local_thr)
        .args([&endpoint, "16", "1000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn());

    thread::sleep(Duration::from_millis(150));

    let mut sender = ok(Command::new(&remote_thr)
        .args([&endpoint, "16", "1000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn());

    assert!(ok(sender.wait()).success());
    let stdout = some(receiver.stdout.take());
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let lines = reader.lines().collect::<Result<Vec<_>, _>>();
        let _ = line_tx.send(lines);
    });

    assert!(ok(receiver.wait()).success());
    let lines = ok(ok(line_rx.recv_timeout(Duration::from_secs(3))));
    assert!(lines.iter().any(|line| line.starts_with("throughput:")));
    assert!(lines.iter().any(|line| line.starts_with("bandwidth:")));
}

#[test]
fn local_and_remote_lat_smoke() {
    let reserved = ok(std::net::TcpListener::bind("127.0.0.1:0"));
    let endpoint = format!("tcp://{}", ok(reserved.local_addr()));
    drop(reserved);

    let local_lat = bin_path("CARGO_BIN_EXE_local_lat", "local_lat");
    let remote_lat = bin_path("CARGO_BIN_EXE_remote_lat", "remote_lat");
    let mut responder = ok(Command::new(&local_lat)
        .args([&endpoint, "16", "200"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn());

    thread::sleep(Duration::from_millis(150));

    let requester = ok(Command::new(&remote_lat)
        .args([&endpoint, "16", "200"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn());
    let output = ok(requester.wait_with_output());

    assert!(output.status.success());
    assert!(ok(responder.wait()).success());

    let stdout = ok(String::from_utf8(output.stdout));
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("average latency:"))
    );
}
