use mcp_runner::{McpRunner, error::Result as McpResult};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::select;
use tokio::task;
use tokio::time::Duration;
use tokio::time::sleep;

extern crate chrono;
use tracing::{info, warn};

#[cfg(not(windows))]
use daemonize::Daemonize;

#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
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
        let mut pid_file = "./mcp-gateway.pid".to_string();
        let mut log_file = "./mcp-gateway.log".to_string();
        let mut stdout_log = "./mcp-gateway.out.log".to_string();
        let mut stderr_log = "./mcp-gateway.err.log".to_string();
    
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
        fs::write(&self.pid_file, pid)?;
        info!("PID file written to {}", self.pid_file);
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
        println!("  --stdout-log=<path>   Path to stdout log when daemonized (default: ./mcp-gateway.out.log)");
        println!("  --stderr-log=<path>   Path to stderr log when daemonized (default: ./mcp-gateway.err.log)");
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
                    // On Unix systems, send SIGTERM
                    match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                        Ok(_) => println!("Signal sent to process {}. Daemon stopping.", pid),
                        Err(e) => {
                            eprintln!("Failed to send signal: {}", e);
                            return Ok(());
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
                        },
                        Err(e) => {
                            eprintln!("Failed to execute taskkill: {}", e);
                        }
                    }
                }
                
                // Try to remove the PID file
                if let Err(e) = self.remove_pid_file() {
                    eprintln!("Failed to remove PID file: {}", e);
                }
            },
            None => {
                eprintln!("No valid PID found in PID file: {}", self.pid_file);
            },
        }
        
        process::exit(0);
    }

    /// Handle keyboard input for interactive commands
    async fn interactive_keyboard_handler(
        shutdown_flag: Arc<AtomicBool>,
        runner: Arc<tokio::sync::Mutex<McpRunner>>,
        server_names: Arc<Vec<String>>,
    ) {
        // Create channel for command passing
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);
    
        // Spawn a blocking task for keyboard input
        task::spawn_blocking(move || {
            let mut buffer = String::new();
    
            // Initially show help message without cluttering log output
            println!("\nEnter a command ('h' for help):");
    
            loop {
                buffer.clear();
                if std::io::stdin().read_line(&mut buffer).is_ok() {
                    let cmd = buffer.trim().to_string();
                    if cmd == "q" {
                        println!("Quit command received");
                        shutdown_flag.store(true, Ordering::SeqCst);
                        break;
                    } else if cmd == "s" || cmd == "t" || cmd == "h" || cmd == "help" {
                        // Send the command through the channel
                        if tx.blocking_send(cmd).is_err() {
                            // Channel closed, exit the loop
                            break;
                        }
                    } else if !cmd.is_empty() {
                        println!("Unknown command: '{}'. Enter 'h' for help", cmd);
                    }
                }
            }
        });
    
        // Process commands from the channel
        while let Some(cmd) = rx.recv().await {
            match cmd.as_str() {
                "h" | "help" => {
                    println!("\nAvailable commands:");
                    println!(" - 's' : Show server status");
                    println!(" - 't' : Show available tools");
                    println!(" - 'h' : Show this help message");
                    println!(" - 'q' : Quit the application");
                }
                "s" => {
                    println!("\nServer Status:");
                    let runner_guard = runner.lock().await;
    
                    // Use the built-in method to get all statuses at once
                    let statuses = runner_guard.get_all_server_statuses();
    
                    // Display statuses for all running servers
                    if statuses.is_empty() {
                        println!(" - No servers are running");
                    } else {
                        // Use reference to avoid moving statuses
                        for (name, status) in &statuses {
                            println!(" - Server '{}': {:?}", name, status);
                        }
                    }
    
                    // Also show servers from our list that aren't running
                    for server_name in server_names.as_ref() {
                        if !statuses.contains_key(server_name) {
                            println!(" - Server '{}': Not started", server_name);
                        }
                    }
                }
                "t" => {
                    println!("\nAvailable Tools:");
                    let mut runner_guard = runner.lock().await;
    
                    // Use the built-in method to get all tools at once
                    let all_tools = runner_guard.get_all_server_tools().await;
    
                    if all_tools.is_empty() {
                        println!(" - No servers are running");
                    } else {
                        // Collect server names from the results first to avoid ownership issues
                        let server_names_with_tools: Vec<String> = all_tools.keys().cloned().collect();
    
                        // Now iterate through the tools
                        for server_name in server_names_with_tools {
                            println!("Server: {}", server_name);
    
                            match &all_tools[&server_name] {
                                Ok(tools) => {
                                    if tools.is_empty() {
                                        println!(" - No tools available");
                                    } else {
                                        for tool in tools {
                                            println!(" - Tool: {} ({})", tool.name, tool.description);
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!(" - Failed to list tools: {}", e);
                                }
                            }
                        }
    
                        // Check for servers from our list that aren't in the results
                        for server_name in server_names.as_ref() {
                            if !all_tools.contains_key(server_name) {
                                println!("Server: {}", server_name);
                                println!(" - Server not started");
                            }
                        }
                    }
                }
                _ => {} // Ignore other commands
            }
    
            // Re-display the prompt after processing a command
            println!("\nEnter a command ('h' for help):");
        }
    }

    /// Daemonize the process on Unix platforms
    #[cfg(not(windows))]
    fn daemonize(&self) -> McpResult<()> {
        use std::io::Write;
        println!("Starting in daemon mode");
        
        // Convert relative paths to absolute paths for daemon mode
        let current_dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
        let stdout_log = if Path::new(&self.stdout_log).is_absolute() {
            self.stdout_log.clone()
        } else {
            current_dir.join(&self.stdout_log).to_string_lossy().into_owned()
        };
        
        let stderr_log = if Path::new(&self.stderr_log).is_absolute() {
            self.stderr_log.clone()
        } else {
            current_dir.join(&self.stderr_log).to_string_lossy().into_owned()
        };
        
        // Create paths for daemon log files and ensure directories exist
        for path in &[&stdout_log, &stderr_log] {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("Failed to create log directory for {}: {}", path, e);
                        return Err(mcp_runner::error::Error::Other(format!(
                            "Failed to create log directory: {}", e
                        )));
                    }
                }
            }
        }
        
        // Write pre-daemonize messages to log files
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Write to stdout log
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&stdout_log) {
            let _ = writeln!(file, "[{}] Daemon starting process", timestamp);
        }
        
        // Write to stderr log
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&stderr_log) {
            let _ = writeln!(file, "[{}] Daemon starting process", timestamp);
        }
        
        // Don't change the working directory - this can break relative paths
        let daemonize = Daemonize::new()
            .pid_file(&self.pid_file)
            .chown_pid_file(true)
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
                // Logging will be initialized in run() after this returns
                println!("[{}] Daemon process started with PID {}", 
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    std::process::id());
                
                eprintln!("[{}] Daemon error output test", 
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
                    
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
        use std::path::Path;
        use std::io::Write;
        use tracing_subscriber::{EnvFilter, fmt};
        
        if self.daemon {
            // For daemon mode, log to file
            // First, make sure the directory exists
            if let Some(parent) = Path::new(&self.log_file).parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            
            // Write a direct test message to verify we can write to the file
            let test_message = format!("[INIT] Daemon starting at {}\n", 
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
            
            fs::write(&self.log_file, &test_message)?;
            
            // Now set up logging with tracing
            let log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&self.log_file)?;
            
            // Initialize tracing to log file
            match fmt()
                .with_env_filter(EnvFilter::from_env("MCP_GW_LOG").add_directive(tracing::Level::INFO.into()))
                .with_target(true)
                .with_ansi(false)  // Disable ANSI color codes in log files
                .with_writer(log_file)
                .try_init() {
                    Ok(_) => {
                        // Use std::fs to append another message to confirm tracing is set up
                        let mut file = OpenOptions::new()
                            .append(true)
                            .open(&self.log_file)?;
                        writeln!(file, "[INIT] Tracing initialized successfully")?;
                    }
                    Err(e) => {
                        // Write the error directly to the log file since we can't log it
                        let mut file = OpenOptions::new()
                            .append(true)
                            .open(&self.log_file)?;
                        writeln!(file, "[ERROR] Failed to initialize tracing: {}", e)?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other, 
                            format!("Failed to initialize tracing: {}", e)
                        ));
                    }
                }
                
            // Now try to log using tracing - this will work if initialization succeeded
            info!("Daemon logging initialized to file: {}", self.log_file);
        } else {
            // For interactive mode, log to console
            fmt()
                .with_env_filter(EnvFilter::from_env("MCP_GW_LOG").add_directive(tracing::Level::INFO.into()))
                .with_target(true)
                .init();
                
            info!("Console logging initialized");
        }
        
        Ok(())
    }

    /// Main function to run the MCP Gateway
    pub async fn run(self) -> McpResult<()> {
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
            return Err(mcp_runner::error::Error::Other(
                format!("Failed to initialize logging: {}", e)
            ));
        }
        
        // Log system information 
        info!("System information for debugging:");
        info!("  PID: {}", std::process::id());
        info!("  Working dir: {}", std::env::current_dir().unwrap_or_default().display());
        
        // Log startup mode
        if self.daemon {
            info!("Running in daemon mode with PID file: {}", self.pid_file);
            
            // Write PID file after daemonization
            if let Err(e) = self.write_pid_file() {
                warn!("Failed to write PID file: {}", e);
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
            runner.start_sse_proxy().await?;
    
            info!("SSE proxy started successfully!");
            info!("Available HTTP endpoints:");
    
            // Using values from the example config file
            let sse_proxy_config = runner.get_sse_proxy_config()?;
            let host = &sse_proxy_config.address;
            let port = &sse_proxy_config.port;
    
            info!(
                " - SSE events stream:           GET    http://{}:{}/sse",
                host, port
            );
            info!(
                " - JSON-RPC messages:           POST   http://{}:{}/sse/messages",
                host, port
            );
    
            info!("Example JSON-RPC tool call with curl:");
            info!("curl -X POST http://{}:{}/sse/messages \\", host, port);
            info!("  -H \"Content-Type: application/json\" \\");
            info!(
                "  -d '{{\"jsonrpc\":\"2.0\", \"id\":\"req-123\", \"method\":\"tools/call\", \"params\":{{\"server\":\"fetch\", \"tool\":\"fetch\", \"arguments\":{{\"url\":\"https://example.com\"}}}}}}' "
            );
    
            info!("Example SSE client with curl:");
            info!("curl -N http://{}:{}/sse", host, port);
    
            // Setup shutdown flag and server management
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let server_names = Arc::new(server_names);
            let runner_arc = Arc::new(tokio::sync::Mutex::new(runner));
        
            if !self.daemon {
                // Only set up interactive keyboard handler in non-daemon mode
                let shutdown_flag_clone = shutdown_flag.clone();
            
                // Start the interactive keyboard handler in the background
                let keyboard_handle = tokio::spawn(Self::interactive_keyboard_handler(
                    shutdown_flag_clone,
                    runner_arc.clone(),
                    server_names.clone(),
                ));
            
                // Wait for shutdown signal from keyboard handler or Ctrl+C
                select! {
                    _ = async {
                        while !shutdown_flag.load(Ordering::SeqCst) {
                            sleep(Duration::from_millis(100)).await;
                        }
                    } => {
                        info!("Shutdown requested via keyboard command");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutdown requested via Ctrl+C");
                        shutdown_flag.store(true, Ordering::SeqCst);
                    }
                }
            
                // Wait for the keyboard handler to finish
                if let Err(e) = keyboard_handle.await {
                    warn!("Keyboard handler task error: {:?}", e);
                }
            } else {
                // In daemon mode, set up a simple signal handler
                info!("Daemon running and waiting for signals");
                
                // Create a signal handler to wait for termination request
                #[cfg(unix)]
                let terminate = async {
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                        Ok(mut signal) => {
                            signal.recv().await;
                            info!("Received SIGTERM signal");
                        },
                        Err(e) => {
                            warn!("Failed to set up SIGTERM handler: {}", e);
                        }
                    }
                };

                #[cfg(not(unix))]
                let terminate = std::future::pending::<()>();
                
                // Wait for Ctrl+C or SIGTERM on Unix
                select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received Ctrl+C signal in daemon mode");
                    },
                    _ = terminate => {
                        info!("Received termination signal in daemon mode");
                    }
                }
                
                info!("Daemon termination signal received");
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
            }
            info!("Daemon process exiting, removed PID file: {}", self.pid_file);
        }
    
        info!("mcp-gateway terminated");
        Ok(())
    }
}