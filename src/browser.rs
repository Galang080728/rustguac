//! Process lifecycle manager for Xvnc + Chromium browser sessions.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

/// Allocates X display numbers from a fixed pool.
struct DisplayAllocator {
    in_use: Mutex<HashSet<u32>>,
    range_start: u32,
    range_end: u32,
}

impl DisplayAllocator {
    fn new(range_start: u32, range_end: u32) -> Self {
        Self {
            in_use: Mutex::new(HashSet::new()),
            range_start,
            range_end,
        }
    }

    fn allocate(&self) -> Option<u32> {
        let mut in_use = self.in_use.lock().unwrap();
        for n in self.range_start..=self.range_end {
            if !in_use.contains(&n) {
                in_use.insert(n);
                return Some(n);
            }
        }
        None
    }

    fn release(&self, n: u32) {
        let mut in_use = self.in_use.lock().unwrap();
        in_use.remove(&n);
    }
}

/// Handles for the spawned Xvnc and Chromium processes.
pub struct BrowserSession {
    pub display: u32,
    pub vnc_port: u16,
    pub xvnc_child: Child,
    pub chromium_child: Child,
    pub profile_dir: PathBuf,
}

/// Manages spawning and killing browser sessions.
pub struct BrowserManager {
    allocator: DisplayAllocator,
    xvnc_path: String,
    chromium_path: String,
}

impl BrowserManager {
    pub fn new(
        xvnc_path: String,
        chromium_path: String,
        display_range_start: u32,
        display_range_end: u32,
    ) -> Self {
        Self {
            allocator: DisplayAllocator::new(display_range_start, display_range_end),
            xvnc_path,
            chromium_path,
        }
    }

    /// Spawn Xvnc and Chromium for the given URL.
    /// Returns a BrowserSession with process handles and the VNC port.
    pub async fn spawn(
        &self,
        url: &str,
        width: u32,
        height: u32,
    ) -> Result<BrowserSession, BrowserError> {
        let display_num = self.allocator.allocate().ok_or_else(|| {
            tracing::error!(
                "No X display numbers available (range {}–{})",
                self.allocator.range_start,
                self.allocator.range_end
            );
            BrowserError::NoDisplayAvailable
        })?;

        let vnc_port = 5900 + display_num as u16;
        let geometry = format!("{}x{}", width, height);

        // Create a unique profile directory for this session (UUID avoids stale crash state)
        let profile_dir =
            std::env::temp_dir().join(format!("rustguac-chromium-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&profile_dir); // clean slate
        if let Err(e) = std::fs::create_dir_all(&profile_dir) {
            self.allocator.release(display_num);
            let msg = format!("Failed to create profile dir {:?}: {}", profile_dir, e);
            tracing::error!("{}", msg);
            return Err(BrowserError::ChromiumSpawn(msg));
        }

        tracing::info!(
            xvnc_path = %self.xvnc_path,
            display = %display_num,
            vnc_port = %vnc_port,
            geometry = %geometry,
            "Spawning Xvnc"
        );

        // Spawn Xvnc
        let mut xvnc_child = Command::new(&self.xvnc_path)
            .arg(format!(":{}", display_num))
            .args([
                "-geometry",
                &geometry,
                "-depth",
                "24",
                "-SecurityTypes",
                "None",
                "-localhost",
                "-AlwaysShared",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                self.allocator.release(display_num);
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.xvnc_path, e);
                tracing::error!("{}", msg);
                BrowserError::XvncSpawn(msg)
            })?;

        tracing::info!(
            display = %display_num,
            pid = ?xvnc_child.id(),
            "Xvnc process spawned, waiting for VNC port {} to accept connections",
            vnc_port
        );

        // Wait for VNC port to accept connections (up to 2s)
        let addr = format!("127.0.0.1:{}", vnc_port);
        let port_ready = timeout(Duration::from_secs(2), async {
            loop {
                if TcpStream::connect(&addr).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        if port_ready.is_err() {
            // Collect stderr to help diagnose why Xvnc didn't start
            let stderr_output = collect_stderr(&mut xvnc_child).await;
            let _ = xvnc_child.kill().await;
            self.allocator.release(display_num);
            let _ = std::fs::remove_dir_all(&profile_dir);
            let msg = format!(
                "Xvnc did not start listening on port {} within 2s{}",
                vnc_port,
                if stderr_output.is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {}", stderr_output)
                }
            );
            tracing::error!("{}", msg);
            return Err(BrowserError::XvncSpawn(msg));
        }

        tracing::info!(display = %display_num, vnc_port = %vnc_port, "Xvnc is ready and accepting connections");

        tracing::info!(
            chromium_path = %self.chromium_path,
            display = %display_num,
            profile_dir = %profile_dir.display(),
            url = %url,
            "Spawning Chromium"
        );

        // Spawn Chromium with isolated profile
        let window_size = format!("--window-size={},{}", width, height);
        let user_data_dir = format!("--user-data-dir={}", profile_dir.display());
        let chromium_result = Command::new(&self.chromium_path)
            .env("DISPLAY", format!(":{}", display_num))
            .args([
                "--start-fullscreen",
                "--no-first-run",
                "--noerrdialogs",
                "--disable-infobars",
                "--disable-translate",
                "--disable-features=TranslateUI,VizDisplayCompositor",
                "--no-sandbox",
                "--test-type",
                // GPU / rendering — safe for headless VMs without GPU
                "--disable-gpu",
                "--disable-gpu-compositing",
                "--disable-software-rasterizer",
                "--disable-dev-shm-usage",
                "--use-gl=angle",
                "--use-angle=swiftshader",
                "--in-process-gpu",
                // Stability
                "--disable-background-networking",
                "--disable-sync",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--no-default-browser-check",
                "--window-position=0,0",
                &window_size,
                &user_data_dir,
                url,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let chromium_child = match chromium_result {
            Ok(child) => {
                tracing::info!(
                    display = %display_num,
                    pid = ?child.id(),
                    url = %url,
                    "Chromium process spawned"
                );
                child
            }
            Err(e) => {
                let _ = xvnc_child.kill().await;
                self.allocator.release(display_num);
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.chromium_path, e);
                tracing::error!("{}", msg);
                return Err(BrowserError::ChromiumSpawn(msg));
            }
        };

        Ok(BrowserSession {
            display: display_num,
            vnc_port,
            xvnc_child,
            chromium_child,
            profile_dir,
        })
    }

    /// Kill both Chromium and Xvnc, release the display number, and clean up the profile dir.
    pub async fn kill(&self, session: &mut BrowserSession) {
        tracing::info!(
            display = %session.display,
            chromium_pid = ?session.chromium_child.id(),
            xvnc_pid = ?session.xvnc_child.id(),
            "Killing browser session processes"
        );
        let _ = session.chromium_child.kill().await;
        let _ = session.xvnc_child.kill().await;
        self.allocator.release(session.display);

        // Clean up the per-session Chromium profile directory
        let profile_dir = session.profile_dir.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = std::fs::remove_dir_all(&profile_dir) {
                tracing::warn!(path = %profile_dir.display(), error = %e, "Failed to clean up Chromium profile dir");
            }
        });

        tracing::info!(display = %session.display, "Browser session cleaned up, display released");
    }
}

/// Read whatever stderr is available from a child process (non-blocking, best-effort).
async fn collect_stderr(child: &mut Child) -> String {
    use tokio::io::AsyncReadExt;
    if let Some(ref mut stderr) = child.stderr {
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(200), stderr.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

#[derive(Debug)]
pub enum BrowserError {
    NoDisplayAvailable,
    XvncSpawn(String),
    ChromiumSpawn(String),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::NoDisplayAvailable => write!(f, "no X display numbers available"),
            BrowserError::XvncSpawn(msg) => write!(f, "Xvnc spawn failed: {}", msg),
            BrowserError::ChromiumSpawn(msg) => write!(f, "Chromium spawn failed: {}", msg),
        }
    }
}
