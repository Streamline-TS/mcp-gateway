use mcp_runner::{McpRunner, error::Result as McpResult};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process;
use std::sync::Arc;

extern crate chrono;
use tracing::{info, warn};

#[cfg(not(windows))]
use daemonize::Daemonize;

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

/// McpGateway represents the main application, combining configuration and behavior
#[derive(Clone)]
pub struct McpGateway {
    config_path: String,
    daemon: bool,
    pid_file: String,
    log_file: String,
    stdout_log: String,
    stderr_log: String,
}

impl McpGateway {
    /// Create a new McpGateway instance from command-line arguments
    pub fn new_from_args(args: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let args_vec: Vec<String> = args.collect();
        let mut help_requested = false;
        let mut stop_requested = false;

        // Default configuration
        let mut config_path = "./config.json".to_string();
        let mut daemon = false;
        let mut pid_file = "/tmp/mcp-gateway.pid".to_string();
        let mut log_file = "/tmp/mcp-gateway.log".to_string();
        let mut stdout_log = "/tmp/mcp-gateway.out.log".to_string();
        let mut stderr_log = "/tmp/mcp-gateway.err.log".to_string();

        // Process arguments to extract configuration parameters first
        for arg in &args_vec {
            if arg.starts_with("--config=") {
                config_path = arg.strip_prefix("--config=").unwrap_or("").to_string();
            } else if arg == "--daemon" {
                daemon = true;
            } else if arg.starts_with("--pid-file=") {
                pid_file = arg.strip_prefix("--pid-file=").unwrap_or("").to_string();
            } else if arg.starts_with("--log-file=") {
                log_file = arg.strip_prefix("--log-file=").unwrap_or("").to_string();
            } else if arg.starts_with("--stdout-log=") {
                stdout_log = arg.strip_prefix("--stdout-log=").unwrap_or("").to_string();
            } else if arg.starts_with("--stderr-log=") {
                stderr_log = arg.strip_prefix("--stderr-log=").unwrap_or("").to_string();
            } else if arg == "help" || arg == "--help" || arg == "-h" {
                help_requested = true;
            } else if arg == "stop" {
                stop_requested = true;
            }
        }

        // Create the gateway object
        let gateway = McpGateway {
            config_path,
            daemon,
            pid_file,
            log_file,
            stdout_log,
            stderr_log,
        };

        // Handle special commands
        if help_requested {
            Self::print_help();
            return Err("Help requested");
        }

        if stop_requested {
            if let Err(e) = gateway.stop() {
                eprintln!("Error stopping daemon: {}", e);
            }
            return Err("Stop command executed");
        }

        Ok(gateway)
    }

    /// Writes the current process ID to the PID file
    fn write_pid_file(&self) -> std::io::Result<()> {
        let pid = std::process::id().to_string();
        // Use OpenOptions with proper permissions for writing the PID file
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o666) // World writable
                .open(&self.pid_file)?;
            std::io::Write::write_all(&mut file, pid.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&self.pid_file, pid)?;
        }
        // Only log if tracing is already initialized
        if tracing::dispatcher::has_been_set() {
            info!("PID file written to {}", self.pid_file);
        }
        Ok(())
    }

    /// Reads the PID from the PID file
    fn read_pid_file(&self) -> std::io::Result<Option<u32>> {
        if Path::new(&self.pid_file).exists() {
            let mut file = fs::File::open(&self.pid_file)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            match contents.trim().parse::<u32>() {
                Ok(pid) => Ok(Some(pid)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Removes the PID file if it exists
    fn remove_pid_file(&self) -> std::io::Result<()> {
        if Path::new(&self.pid_file).exists() {
            fs::remove_file(&self.pid_file)?;
            info!("PID file removed from {}", self.pid_file);
        }
        Ok(())
    }

    /// Print help information about command usage
    fn print_help() {
        println!("MCP Gateway - Model Context Protocol Gateway");
        println!();
        println!("USAGE:");
        println!("  mcp-gateway [COMMAND] [OPTIONS]");
        println!();
        println!("COMMANDS:");
        println!("  help                  Print this help message");
        println!("  stop                  Stop a running daemon");
        println!();
        println!("OPTIONS:");
        println!("  --config=<path>       Path to config file (default: ./config.json)");
        println!("  --daemon              Run as a background daemon");
        println!("  --pid-file=<path>     Path to PID file (default: ./mcp-gateway.pid)");
        println!("  --log-file=<path>     Path to log file (default: ./mcp-gateway.log)");
        println!(
            "  --stdout-log=<path>   Path to stdout log when daemonized (default: ./mcp-gateway.out.log)"
        );
        println!(
            "  --stderr-log=<path>   Path to stderr log when daemonized (default: ./mcp-gateway.err.log)"
        );
        println!();
        println!("EXAMPLES:");
        println!("  mcp-gateway --config=/etc/mcp/config.json");
        println!("  mcp-gateway --daemon --config=/etc/mcp/config.json");
        println!("  mcp-gateway stop --pid-file=/var/run/mcp-gateway.pid");
    }

    /// Stop a running daemon process by reading the PID file and sending a termination signal
    fn stop(&self) -> std::io::Result<()> {
        println!("Attempting to stop MCP Gateway daemon...");
        println!("Using PID file: {}", self.pid_file);

        // Use read_pid_file to read the PID
        match self.read_pid_file()? {
            Some(pid) => {
                println!("Found PID: {}", pid);

                #[cfg(unix)]
                {
                    // On Unix systems, send SIGKILL directly since SIGTERM isn't working reliably
                    // Note: This is because the process is likely not setting up proper signal handlers
                    // or is ignoring SIGTERM. Using SIGKILL is more reliable but doesn't allow for
                    // graceful shutdown. Consider implementing proper SIGTERM handling in the future.
                    match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
                        Ok(_) => {
                            println!("SIGKILL sent to process {}.", pid);
                            // Give the process a brief moment to be cleaned up
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                        Err(e) => {
                            if e.to_string().contains("No such process") {
                                println!("Process {} is not running.", pid);
                            } else {
                                eprintln!("Failed to send SIGKILL: {}", e);
                            }
                        }
                    }
                }

                #[cfg(windows)]
                {
                    // On Windows, use taskkill
                    use std::process::Command;

                    let output = Command::new("taskkill")
                        .args(&["/PID", &pid.to_string(), "/F"])
                        .output();

                    match output {
                        Ok(output) => {
                            if output.status.success() {
                                println!("Successfully stopped process {}", pid);
                            } else {
                                let error = String::from_utf8_lossy(&output.stderr);
                                eprintln!("Failed to stop process: {}", error);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to execute taskkill: {}", e);
                        }
                    }
                }

                // Try to remove the PID file
                if let Err(e) = self.remove_pid_file() {
                    eprintln!("Failed to remove PID file: {}", e);
                } else {
                    println!("PID file removed successfully");
                }
            }
            None => {
                eprintln!("No valid PID found in PID file: {}", self.pid_file);
            }
        }

        process::exit(0);
    }

    // Interactive keyboard handler functionality has been completely removed

    /// Daemonize the process on Unix platforms
    #[cfg(not(windows))]
    fn daemonize(&mut self) -> McpResult<()> {
        use std::io::Write;
        println!("Starting in daemon mode");

        // Convert relative paths to absolute paths for daemon mode
        let current_dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
        let stdout_log = if Path::new(&self.stdout_log).is_absolute() {
            self.stdout_log.clone()
        } else {
            current_dir
                .join(&self.stdout_log)
                .to_string_lossy()
                .into_owned()
        };

        let stderr_log = if Path::new(&self.stderr_log).is_absolute() {
            self.stderr_log.clone()
        } else {
            current_dir
                .join(&self.stderr_log)
                .to_string_lossy()
                .into_owned()
        };

        let pid_file = if Path::new(&self.pid_file).is_absolute() {
            self.pid_file.clone()
        } else {
            current_dir
                .join(&self.pid_file)
                .to_string_lossy()
                .into_owned()
        };

        // Create paths for daemon log files and ensure directories exist
        for path in &[&stdout_log, &stderr_log, &pid_file] {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("Failed to create directory for {}: {}", path, e);
                        return Err(mcp_runner::error::Error::Other(format!(
                            "Failed to create directory: {}",
                            e
                        )));
                    }
                }
            }
        }

        // Create PID file with permissive permissions before daemonizing
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o666) // World writable
                .open(&pid_file)
            {
                Ok(mut file) => {
                    // Write PID directly to ensure the file has content
                    let pid = std::process::id().to_string();
                    if let Err(e) = std::io::Write::write_all(&mut file, pid.as_bytes()) {
                        eprintln!("Warning: Failed to write to PID file: {}", e);
                        // Continue anyway
                    }
                }
                Err(e) => {
                    eprintln!("Failed to create PID file {}: {}", pid_file, e);
                    return Err(mcp_runner::error::Error::Other(format!(
                        "Failed to create PID file: {}",
                        e
                    )));
                }
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(e) = std::fs::File::create(&pid_file) {
                eprintln!("Failed to create PID file {}: {}", pid_file, e);
                return Err(mcp_runner::error::Error::Other(format!(
                    "Failed to create PID file: {}",
                    e
                )));
            }
        }

        // Write pre-daemonize messages to log files
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // Write to stdout log
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&stdout_log)
        {
            let _ = writeln!(file, "[{}] Daemon starting process", timestamp);
        }

        // Write to stderr log
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&stderr_log)
        {
            let _ = writeln!(file, "[{}] Daemon starting process", timestamp);
        }

        // Make config path absolute if it's relative
        if !Path::new(&self.config_path).is_absolute() {
            self.config_path = current_dir
                .join(&self.config_path)
                .to_string_lossy()
                .into_owned();
        }

        // Don't change the working directory - this can break relative paths
        // Ensure PID file directory exists and we have write permission
        // This prevents "unable to open pid file" error
        if let Some(parent) = Path::new(&self.pid_file).parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!(
                        "Failed to create directory for PID file {}: {}",
                        self.pid_file, e
                    );
                    return Err(mcp_runner::error::Error::Other(format!(
                        "Failed to create directory for PID file: {}",
                        e
                    )));
                }
            }
        }

        // Test if we can write to the PID file before daemonizing
        // This prevents permission errors when the daemonize library tries to create it
        if let Err(e) = self.write_pid_file() {
            eprintln!("Failed to create PID file {}: {}", self.pid_file, e);
            return Err(mcp_runner::error::Error::Other(format!(
                "Failed to create PID file: {}",
                e
            )));
        }

        let daemonize = Daemonize::new()
            .pid_file(&pid_file) // Let the Daemonize library handle the initial PID file
            .working_directory(std::env::current_dir().unwrap()) // Keep current directory
            .umask(0o022) // More permissive umask for files (world readable)
            .stdout(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(&stdout_log)
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to open stdout log {}: {}", stdout_log, e);
                        std::process::exit(1)
                    }),
            )
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(&stderr_log)
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to open stderr log {}: {}", stderr_log, e);
                        std::process::exit(1)
                    }),
            );

        match daemonize.start() {
            Ok(_) => {
                // We're in the daemon process now
                // IMPORTANT: Immediately update the PID file with the child's PID
                let child_pid = std::process::id().to_string();
                if let Err(e) = std::fs::write(&pid_file, child_pid) {
                    eprintln!(
                        "[{}] Failed to update PID file with child PID: {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        e
                    );
                    // Continue anyway since this is non-fatal
                } else {
                    eprintln!(
                        "[{}] Successfully updated PID file with daemon PID: {}",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        std::process::id()
                    );
                }

                // Logging will be initialized in run() after this returns
                println!(
                    "[{}] Daemon process started with PID {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    std::process::id()
                );

                eprintln!(
                    "[{}] Daemon error output test",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                );

                Ok(())
            }
            Err(e) => {
                eprintln!("Error starting daemon: {}", e);
                process::exit(1);
            }
        }
    }

    /// Warn that daemon mode is not supported on Windows
    #[cfg(windows)]
    fn daemonize(&self) -> McpResult<()> {
        eprintln!("Windows does not support daemon mode directly.");
        eprintln!("Please use Windows Task Scheduler or create a Windows Service.");
        eprintln!("Continuing in foreground mode...");
        Ok(())
    }

    /// Initialize logging based on config
    fn setup_logging(&self) -> std::io::Result<()> {
        use std::fs::{self, OpenOptions};
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::Path;
        use tracing_subscriber::{EnvFilter, fmt};

        if self.daemon {
            // For daemon mode, log to file
            // First, make sure the directory exists
            if let Some(parent) = Path::new(&self.log_file).parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // Ensure file is writable by creating it with appropriate permissions
            // Touch the file first to ensure it exists with correct permissions
            // This is critical for daemon mode to work properly
            #[cfg(unix)]
            {
                match OpenOptions::new()
                    .create(true)
                    .write(true)
                    .mode(0o666) // World writable
                    .open(&self.log_file)
                {
                    Ok(mut file) => {
                        // Write an initial log entry directly
                        let init_msg = format!(
                            "Log file initialized at {}\n",
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                        );
                        let _ = std::io::Write::write_all(&mut file, init_msg.as_bytes());
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to create log file with proper permissions: {}",
                            e
                        );
                        // Continue anyway, we'll try standard permissions
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&self.log_file)?;
            }

            // Also check that our PID file exists with the correct content
            if let Err(e) = self.write_pid_file() {
                eprintln!("Warning: Failed to update PID file: {}", e);
                // Continue anyway, not critical for logging
            }

            // Write a direct test message to verify we can write to the file
            let test_message = format!(
                "[INIT] Daemon starting at {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            );

            fs::write(&self.log_file, &test_message)?;

            // Now set up logging with tracing
            let log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&self.log_file)?;

            // Initialize tracing to log file
            match fmt()
                .with_env_filter(
                    EnvFilter::from_env("MCP_GW_LOG").add_directive(tracing::Level::INFO.into()),
                )
                .with_target(true)
                .with_ansi(false) // Disable ANSI color codes in log files
                .with_writer(log_file)
                .try_init()
            {
                Ok(_) => {
                    // Use std::fs to append another message to confirm tracing is set up
                    let mut file = OpenOptions::new().append(true).open(&self.log_file)?;
                    writeln!(file, "[INIT] Tracing initialized successfully")?;
                }
                Err(e) => {
                    // Write the error directly to the log file since we can't log it
                    let mut file = OpenOptions::new().append(true).open(&self.log_file)?;
                    writeln!(file, "[ERROR] Failed to initialize tracing: {}", e)?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to initialize tracing: {}", e),
                    ));
                }
            }

            // Now try to log using tracing - this will work if initialization succeeded
            info!("Daemon logging initialized to file: {}", self.log_file);
        } else {
            // For interactive mode, log to console
            fmt()
                .with_env_filter(
                    EnvFilter::from_env("MCP_GW_LOG").add_directive(tracing::Level::INFO.into()),
                )
                .with_target(true)
                .init();

            info!("Console logging initialized");
        }

        Ok(())
    }

    /// Main function to run the MCP Gateway
    pub async fn run(mut self) -> McpResult<()> {
        // Handle daemon mode if requested
        if self.daemon {
            // Daemonize before setting up logging
            self.daemonize()?;
        }

        // Initialize logging based on run mode
        if let Err(e) = self.setup_logging() {
            // If in daemon mode, try to write error to stderr directly as a last resort
            if self.daemon {
                let message = format!("Failed to initialize logging: {}\n", e);
                let _ = std::fs::write(&self.stderr_log, message);
            }
            return Err(mcp_runner::error::Error::Other(format!(
                "Failed to initialize logging: {}",
                e
            )));
        }

        // Log system information
        info!("System information for debugging:");
        info!("  PID: {}", std::process::id());
        info!(
            "  Working dir: {}",
            std::env::current_dir().unwrap_or_default().display()
        );

        // Log startup mode
        if self.daemon {
            info!("Running in daemon mode with PID file: {}", self.pid_file);

            // Note: PID file should already contain daemon process ID (updated in daemonize())
            // But let's verify it just to be safe
            match self.read_pid_file() {
                Ok(Some(pid)) if pid == std::process::id() => {
                    info!(
                        "Confirmed PID file contains correct daemon process ID: {}",
                        pid
                    );
                }
                Ok(Some(pid)) => {
                    warn!(
                        "PID file contains incorrect process ID: {}. Updating to current PID: {}",
                        pid,
                        std::process::id()
                    );
                    if let Err(e) = self.write_pid_file() {
                        warn!("Failed to update PID file with daemon process ID: {}", e);
                    }
                }
                Ok(None) => {
                    warn!("PID file exists but contains no valid PID. Updating with current PID");
                    if let Err(e) = self.write_pid_file() {
                        warn!("Failed to update PID file with daemon process ID: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to read PID file: {}. Creating new one", e);
                    if let Err(e) = self.write_pid_file() {
                        warn!("Failed to update PID file with daemon process ID: {}", e);
                    } else {
                        info!(
                            "Updated PID file with daemon process ID: {}",
                            std::process::id()
                        );
                    }
                }
            }
        } else {
            info!("Running in foreground mode");
        }

        // Initialize McpRunner
        let mut runner = McpRunner::from_config_file(&self.config_path)?;

        // Check if SSE proxy is configured
        if runner.is_sse_proxy_configured() {
            // Start both servers first
            info!("Starting MCP servers");
            let server_ids = runner.start_all_servers().await?;
            info!("Started {} servers", server_ids.len());

            // Extract server names
            let server_names = vec!["fetch".to_string(), "filesystem".to_string()];

            // Make sure all servers are properly registered before starting the proxy
            for name in &server_names {
                if let Ok(server_id) = runner.get_server_id(name) {
                    let status = runner.server_status(server_id)?;
                    info!("Server '{}' status: {:?}", name, status);
                }
            }

            // Start the SSE proxy server - now using address and port from config
            info!("Starting SSE proxy");

            // Create runtime management structures before starting the server
            let runner_arc = Arc::new(tokio::sync::Mutex::new(runner));
            let runner_clone = Arc::clone(&runner_arc);

            // Use a oneshot channel to know when the server has fully started
            let (tx, rx) = tokio::sync::oneshot::channel();

            // Start the SSE proxy on a separate task to avoid initialization issues in daemon mode
            tokio::spawn(async move {
                let mut runner = runner_clone.lock().await;
                if let Err(e) = runner.start_sse_proxy().await {
                    // Signal failure
                    let _ = tx.send(Err(e));
                } else {
                    // Signal success
                    let _ = tx.send(Ok(()));
                }
            });

            // Wait for the server to start (with timeout)
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), rx).await {
                Ok(Ok(Ok(()))) => {
                    info!("SSE proxy started successfully!");
                }
                Ok(Ok(Err(e))) => {
                    return Err(mcp_runner::error::Error::Other(format!(
                        "Failed to start SSE proxy: {}",
                        e
                    )));
                }
                Ok(Err(_)) => {
                    return Err(mcp_runner::error::Error::Other(
                        "Internal channel error when starting SSE proxy".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(mcp_runner::error::Error::Other(
                        "Timeout waiting for SSE proxy to start".to_string(),
                    ));
                }
            }

            // Now that server is confirmed started, give it a moment to fully initialize worker threads
            // This is critical for daemon mode where background initialization may be interrupted
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            info!(
                "{} and waiting for signals",
                if self.daemon {
                    "Daemon running"
                } else {
                    "Running in foreground"
                }
            );

            // Create a future that never resolves
            let forever = std::future::pending::<()>();

            // Handle signals in a more robust way
            #[cfg(unix)]
            let signal_handler = async {
                use tokio::signal::unix::{SignalKind, signal};

                // Set up multiple signal handlers
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to set up SIGTERM handler");
                let mut sigint =
                    signal(SignalKind::interrupt()).expect("Failed to set up SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM signal");
                    },
                    _ = sigint.recv() => {
                        info!("Received SIGINT signal");
                    },
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received Ctrl+C signal");
                    },
                }
            };

            #[cfg(not(unix))]
            let signal_handler = tokio::signal::ctrl_c();

            // Wait for either a signal or the forever future (which never completes)
            tokio::select! {
                _ = signal_handler => {
                    info!("Termination signal received");
                },
                _ = forever => {
                    unreachable!("The forever future should never complete");
                },
            }

            info!("Termination signal received");

            // Ensure the PID file is removed if in daemon mode
            if self.daemon {
                if let Err(e) = self.remove_pid_file() {
                    warn!("Failed to remove PID file during shutdown: {}", e);
                } else {
                    info!("PID file removed during shutdown");
                }
            }

            info!("Shutting down");

            // Stop all servers and the proxy
            let mut runner_guard = runner_arc.lock().await;
            if let Err(e) = runner_guard.stop_all_servers().await {
                warn!("Error during shutdown: {}", e);
            }
        } else {
            warn!("mcp-gateway not configured in {}", self.config_path);
            warn!("Please add sseProxy configuration to your config file");
        }

        // Clean up PID file if in daemon mode
        if self.daemon {
            if let Err(e) = self.remove_pid_file() {
                warn!("Failed to remove PID file: {}", e);
            } else {
                info!(
                    "Daemon process exiting, removed PID file: {}",
                    self.pid_file
                );
            }
        }

        info!("mcp-gateway terminated");
        Ok(())
    }
}
