//! End-to-end CLI integration tests for `cel-cat`.

#![cfg(feature = "cli")]

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

fn cel_cat_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_cel-cat") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_cel_cat") {
        return PathBuf::from(path);
    }

    let exe = ok(std::env::current_exe());
    let target_dir = some(some(exe.parent()).parent());
    for candidate in ["cel-cat", "cel_cat"] {
        let path = target_dir.join(format!("{candidate}{}", std::env::consts::EXE_SUFFIX));
        if path.exists() {
            return path;
        }
    }

    panic!("could not locate cel-cat binary");
}

#[test]
fn cel_cat_pub_sub_smoke() {
    let reserved = ok(std::net::TcpListener::bind("127.0.0.1:0"));
    let endpoint = ok(reserved.local_addr()).to_string();
    drop(reserved);

    let binary = cel_cat_path();
    let publisher = Command::new(&binary)
        .args(["pub", "--linger-ms", "1500", &endpoint, "hello"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut publisher = ok(publisher);

    thread::sleep(Duration::from_millis(150));

    let subscriber = Command::new(&binary)
        .args(["sub", &endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut subscriber = ok(subscriber);

    let stdout = some(subscriber.stdout.take());
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = line_tx.send(result);
    });

    assert!(ok(publisher.wait()).success());
    let line = ok(ok(line_rx.recv_timeout(Duration::from_secs(3))));
    assert_eq!(line.trim_end(), "hello");

    let _ = subscriber.kill();
    let _ = subscriber.wait();
}

#[test]
fn cel_cat_sub_can_start_before_pub() {
    let reserved = ok(std::net::TcpListener::bind("127.0.0.1:0"));
    let endpoint = ok(reserved.local_addr()).to_string();
    drop(reserved);

    let binary = cel_cat_path();
    let subscriber = Command::new(&binary)
        .args(["sub", &endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut subscriber = ok(subscriber);

    let stdout = some(subscriber.stdout.take());
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = line_tx.send(result);
    });

    thread::sleep(Duration::from_millis(500));

    let publisher = Command::new(&binary)
        .args(["pub", "--linger-ms", "1500", &endpoint, "hello"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut publisher = ok(publisher);

    assert!(ok(publisher.wait()).success());
    let line = ok(ok(line_rx.recv_timeout(Duration::from_secs(4))));
    assert_eq!(line.trim_end(), "hello");

    let _ = subscriber.kill();
    let _ = subscriber.wait();
}
