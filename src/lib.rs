// Copyright (C) 2025 Streamline Tech LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use mcp_runner::{McpRunner, error::Result as McpResult};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::select;
use tokio::task;
use tokio::time::{Duration, sleep};

use getch::Getch;
use tracing::{info, warn};

/// Handle keyboard input for interactive commands
async fn interactive_keyboard_handler(
    shutdown_flag: Arc<AtomicBool>,
    runner: Arc<tokio::sync::Mutex<McpRunner>>,
) {
    // Create channel for command passing
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);

    // Spawn a blocking task for keyboard input
    task::spawn_blocking(move || {
        // Use getch for cross-platform single-key input without terminal mode changes
        let g = Getch::new();
        println!("\nPress 'q' to quit, 'h' for help, 's' for status");

        // Main input loop
        loop {
            // Read a single key (blocks until a key is pressed)
            match g.getch() {
                Ok(b'q') => {
                    println!("\nQuit command received");
                    shutdown_flag.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(b's') => {
                    println!("\nGetting server status...");
                    if tx.blocking_send("s".to_string()).is_err() {
                        break;
                    }
                }
                Ok(b'h') => {
                    println!("\nShowing help...");
                    if tx.blocking_send("h".to_string()).is_err() {
                        break;
                    }
                }
                // Ignore other key presses or errors
                _ => {}
            }
        }
    });

    // Process commands from the channel
    while let Some(cmd) = rx.recv().await {
        match cmd.as_str() {
            "h" | "help" => {
                println!("\nAvailable commands:");
                println!(" - 's' : Show server status");
                println!(" - 'h' : Show this help message");
                println!(" - 'q' : Quit the application");
                println!("\nPress 'q' to quit, 'h' for help, 's' for status");
            }
            "s" => {
                println!("\nServer Status:");
                let runner_guard = runner.lock().await;

                // Display statuses for all running servers
                let statuses = runner_guard.get_all_server_statuses();
                if statuses.is_empty() {
                    println!(" - No servers are running");
                } else {
                    for (name, status) in &statuses {
                        println!(" - Server '{}': {:?}", name, status);
                    }
                }

                println!("\nPress 'q' to quit, 'h' for help, 's' for status");
            }
            _ => {} // Ignore other commands
        }
    }
}

/// McpGateway represents the main application
#[derive(Clone)]
pub struct McpGateway {
    config_path: String,
}

impl McpGateway {
    /// Create a new McpGateway instance from command-line arguments
    pub fn new_from_args(args: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let args_vec: Vec<String> = args.collect();
        let mut help_requested = false;

        // Default configuration
        let mut config_path = "./config.json".to_string();

        // Process arguments to extract configuration parameters
        for arg in &args_vec {
            if arg.starts_with("--config=") {
                config_path = arg.strip_prefix("--config=").unwrap_or("").to_string();
            } else if arg == "help" || arg == "--help" || arg == "-h" {
                help_requested = true;
            }
        }

        // Create the gateway object
        let gateway = McpGateway { config_path };

        // Handle special commands
        if help_requested {
            Self::print_help();
            return Err("Help requested");
        }

        Ok(gateway)
    }

    /// Print help information about command usage
    fn print_help() {
        println!("MCP Gateway - Model Context Protocol Gateway");
        println!();
        println!("USAGE:");
        println!("  mcp-gateway [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("  --config=<path>       Path to config file (default: ./config.json)");
        println!("  --help                Print this help message");
        println!();
        println!("EXAMPLES:");
        println!("  mcp-gateway --config=/etc/mcp/config.json");
    }

    /// Initialize logging
    fn setup_logging(&self) -> std::io::Result<()> {
        use tracing_subscriber::{EnvFilter, fmt};

        fmt()
            .with_env_filter(
                EnvFilter::from_env("MCP_GW_LOG").add_directive(tracing::Level::INFO.into()),
            )
            .with_target(true)
            .init();

        info!("Console logging initialized");
        Ok(())
    }

    /// Main function to run the MCP Gateway
    pub async fn run(self) -> McpResult<()> {
        // Initialize logging
        if let Err(e) = self.setup_logging() {
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

        // Initialize McpRunner
        let mut runner = McpRunner::from_config_file(&self.config_path)?;

        // Make sure SSE proxy is configured
        if runner.is_sse_proxy_configured() {
            // Start servers first
            info!("Starting MCP servers and SSE proxy");
            let (_server_ids, _proxy_started) = runner.start_all_with_proxy().await;
            let runner_arc = Arc::new(tokio::sync::Mutex::new(runner));

            // Setup shutdown flag for keyboard commands
            let shutdown_flag = Arc::new(AtomicBool::new(false));

            // Start the interactive keyboard handler in the background
            let keyboard_handle = {
                let shutdown_flag_clone = shutdown_flag.clone();
                let runner_arc_clone = Arc::clone(&runner_arc);
                tokio::spawn(interactive_keyboard_handler(
                    shutdown_flag_clone,
                    runner_arc_clone,
                ))
            };

            // Set up signal handling and wait for shutdown
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            // Handle signals
            let shutdown_signal = async move {
                #[cfg(unix)]
                {
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
                }

                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c()
                        .await
                        .expect("Failed to listen for ctrl+c signal");
                }

                let _ = shutdown_tx.send(());
            };

            // Spawn the signal handler task
            tokio::spawn(shutdown_signal);

            // Wait for shutdown from the keyboard handler or signal
            select! {
                _ = async {
                    while !shutdown_flag.load(Ordering::SeqCst) {
                        sleep(Duration::from_millis(100)).await;
                    }
                } => {
                    info!("Shutdown requested via keyboard command");
                }
                _ = shutdown_rx => {
                    info!("Shutdown signal received");
                }
            }

            // Wait for the keyboard handler to finish
            if let Err(e) = keyboard_handle.await {
                warn!("Keyboard handler task error: {:?}", e);
            }

            info!("Shutting down");

            // Stop all servers and the proxy
            let mut runner_guard = runner_arc.lock().await;
            if let Err(e) = runner_guard.stop_all_servers().await {
                warn!("Error during shutdown: {}", e);
            }
        } else {
            // Return an error if SSE proxy is not configured
            return Err(mcp_runner::error::Error::Other(format!(
                "SSE proxy not configured in {}. Please add sseProxy configuration to your config file.",
                self.config_path
            )));
        }

        info!("mcp-gateway terminated");
        Ok(())
    }
}
