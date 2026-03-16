//! Multipath QUIC end-to-end integration tests.
//!
//! These tests require a 3-namespace netns topology created by
//! `tools/netns-setup.sh`. All tests are `#[ignore]` and must be
//! run with:
//!
//! ```bash
//! sudo cargo test --features multipath -p quiche \
//!     --test multipath_e2e -- --ignored
//! ```

use std::io::Read;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Server port used for all E2E tests.
const PORT: u16 = 4433;

/// Path to the certificate file (relative to CARGO_MANIFEST_DIR).
fn cert_path() -> String {
    format!("{}/examples/cert.crt", env!("CARGO_MANIFEST_DIR"))
}

/// Path to the private key file (relative to CARGO_MANIFEST_DIR).
fn key_path() -> String {
    format!("{}/examples/cert.key", env!("CARGO_MANIFEST_DIR"))
}

/// Returns the path to a quiche-apps binary.
///
/// Checks `target/debug` relative to the workspace root.
fn bin_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // CARGO_MANIFEST_DIR is quiche/, workspace root is one level up.
    let workspace = format!("{}/..", manifest_dir);
    let debug_path = format!("{}/target/debug/{}", workspace, name);
    if std::path::Path::new(&debug_path).exists() {
        return debug_path;
    }
    let release_path = format!("{}/target/release/{}", workspace, name);
    if std::path::Path::new(&release_path).exists() {
        return release_path;
    }
    panic!(
        "Binary {} not found. Run `cargo build --features multipath` first.",
        name
    );
}

/// Check that the 3 test namespaces exist. Returns false if any is
/// missing, allowing tests to skip gracefully.
fn check_netns_ready() -> bool {
    let output = Command::new("ip")
        .args(["netns", "list"])
        .output()
        .expect("failed to run `ip netns list`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for ns in &["mp-client", "mp-router", "mp-server"] {
        if !stdout.lines().any(|line| line.starts_with(ns)) {
            eprintln!("netns {} not found, skipping test", ns);
            return false;
        }
    }
    true
}

/// Start quiche-server inside the given network namespace.
///
/// Returns the child process handle. stderr is piped for later
/// inspection. Panics if the process cannot be spawned.
fn start_server(ns: &str, bind_addr: &str, root: &str) -> Child {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            ns,
            &bin_path("quiche-server"),
            "--listen",
            &format!("{}:{}", bind_addr, PORT),
            "--cert",
            &cert_path(),
            "--key",
            &key_path(),
            "--root",
            root,
            "--multipath",
            "--no-retry",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start quiche-server")
}

/// Start quiche-client inside the given network namespace.
///
/// Runs to completion and returns the output. `extra_args` are
/// inserted before the URL (e.g., `["--second-path", "10.0.2.1"]`).
fn start_client(
    ns: &str, server_url: &str, extra_args: &[&str],
) -> Output {
    let mut cmd = Command::new("ip");
    cmd.args(["netns", "exec", ns, &bin_path("quiche-client")]);
    cmd.args(["--no-verify", "--multipath"]);
    cmd.args(extra_args);
    cmd.arg(server_url);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.output().expect("failed to start quiche-client")
}

/// Poll until the server's UDP port is open in the given namespace.
///
/// Uses `ss -uln` to check. Panics if the timeout is exceeded.
fn wait_for_server_ready(ns: &str, port: u16, timeout: Duration) {
    let start = Instant::now();
    loop {
        let output = Command::new("ip")
            .args(["netns", "exec", ns, "ss", "-uln"])
            .output()
            .expect("failed to run ss");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(&port.to_string()) {
            return;
        }
        if start.elapsed() > timeout {
            panic!(
                "server did not become ready on port {} within {:?}",
                port, timeout
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Create a temporary directory with a test file of the given size.
///
/// Returns the `TempDir` (directory is deleted on drop) and the
/// absolute path as a String.
fn setup_test_root(size_bytes: usize) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let file_path = dir.path().join("testfile");
    let data: Vec<u8> = (0..size_bytes).map(|i| (i % 256) as u8).collect();
    std::fs::write(&file_path, &data).expect("failed to write test file");
    let path = dir.path().to_str().unwrap().to_string();
    (dir, path)
}

/// Extract stderr as a String from a child process, killing it first.
fn collect_server_stderr(mut child: Child) -> String {
    child.kill().ok();
    let mut stderr = String::new();
    if let Some(ref mut err) = child.stderr {
        err.read_to_string(&mut stderr).ok();
    }
    child.wait().ok();
    stderr
}

#[test]
#[ignore]
fn multipath_negotiation_e2e() {
    if !check_netns_ready() {
        return;
    }

    // Create a minimal test root with an index.html
    let (_dir, root) = setup_test_root(64);
    let index_path = std::path::Path::new(&root).join("index.html");
    std::fs::write(&index_path, b"hello").unwrap();

    // Start server
    let server = start_server("mp-server", "10.0.3.1", &root);
    wait_for_server_ready("mp-server", PORT, Duration::from_secs(5));

    // Start client — single path, just negotiate multipath
    let output = start_client(
        "mp-client",
        &format!("https://10.0.3.1:{}/index.html", PORT),
        &[],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let _server_stderr = collect_server_stderr(server);

    eprintln!("--- client stderr ---\n{}", stderr);

    assert!(
        output.status.success(),
        "client should exit with code 0, got {:?}\nstderr: {}",
        output.status,
        stderr
    );

    assert!(
        stderr.contains("MP_PATH path_id=0"),
        "client should output MP_PATH stats\nstderr: {}",
        stderr
    );
}

#[test]
#[ignore]
fn multipath_second_path_creation() {
    if !check_netns_ready() {
        return;
    }

    let (_dir, root) = setup_test_root(64);
    let index_path = std::path::Path::new(&root).join("index.html");
    std::fs::write(&index_path, b"hello").unwrap();

    let server = start_server("mp-server", "10.0.3.1", &root);
    wait_for_server_ready("mp-server", PORT, Duration::from_secs(5));

    // Client with --second-path to create a second multipath path
    let output = start_client(
        "mp-client",
        &format!("https://10.0.3.1:{}/index.html", PORT),
        &["--second-path", "10.0.2.1"],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let _server_stderr = collect_server_stderr(server);

    eprintln!("--- client stderr ---\n{}", stderr);

    assert!(
        output.status.success(),
        "client should exit with code 0, got {:?}\nstderr: {}",
        output.status,
        stderr
    );

    // Both paths should appear in stats
    assert!(
        stderr.contains("MP_PATH path_id=0"),
        "should have path_id=0 in stats\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("MP_PATH path_id=1"),
        "should have path_id=1 in stats (second path)\nstderr: {}",
        stderr
    );
}

#[test]
#[ignore]
fn multipath_data_transfer_two_paths() {
    if !check_netns_ready() {
        return;
    }

    // Create 1MB test file
    let (_dir, root) = setup_test_root(1_000_000);

    let server = start_server("mp-server", "10.0.3.1", &root);
    wait_for_server_ready("mp-server", PORT, Duration::from_secs(5));

    // Create output directory for downloaded response
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().to_str().unwrap();

    let output = start_client(
        "mp-client",
        &format!("https://10.0.3.1:{}/testfile", PORT),
        &[
            "--second-path",
            "10.0.2.1",
            "--dump-responses",
            output_path,
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let _server_stderr = collect_server_stderr(server);

    eprintln!("--- client stderr ---\n{}", stderr);

    assert!(
        output.status.success(),
        "client should exit with code 0, got {:?}\nstderr: {}",
        output.status,
        stderr
    );

    // Verify downloaded file matches original
    let original =
        std::fs::read(std::path::Path::new(&root).join("testfile")).unwrap();
    // quiche-client dumps responses with URL-encoded filenames.
    // We expect exactly one response file for our single request.
    let response_files: Vec<_> = std::fs::read_dir(output_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        response_files.len(),
        1,
        "should have exactly one response file, got {:?}",
        response_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
    let downloaded = std::fs::read(response_files[0].path()).unwrap();
    assert_eq!(
        original.len(),
        downloaded.len(),
        "downloaded file size should match original"
    );
    assert_eq!(
        original, downloaded,
        "downloaded file content should match original"
    );

    // Both paths should have sent data with non-zero byte counts
    for path_id in 0..=1 {
        let marker = format!("MP_PATH path_id={}", path_id);
        let line = stderr
            .lines()
            .find(|l| l.contains(&marker))
            .unwrap_or_else(|| {
                panic!(
                    "should have {} in stats\nstderr: {}",
                    marker, stderr
                )
            });
        // Verify sent_bytes > 0
        let sent_bytes: u64 = line
            .split_whitespace()
            .find_map(|token| {
                token.strip_prefix("sent_bytes=")?.parse().ok()
            })
            .expect("MP_PATH line should contain sent_bytes=N");
        assert!(
            sent_bytes > 0,
            "path_id={} should have sent_bytes > 0, got {}",
            path_id, sent_bytes
        );
    }
}
