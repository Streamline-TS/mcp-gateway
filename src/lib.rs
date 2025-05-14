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

use tracing::{info, warn};

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

        // Console logging
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

            // Start the SSE proxy server
            info!("Starting SSE proxy");

            // Create runtime management structures before starting the server
            let runner_arc = Arc::new(tokio::sync::Mutex::new(runner));

            // Start the server
            let start_server_handle = {
                let runner_clone = Arc::clone(&runner_arc);
                tokio::spawn(async move {
                    let mut runner = runner_clone.lock().await;
                    runner.start_sse_proxy().await
                })
            };

            match tokio::time::timeout(std::time::Duration::from_secs(10), start_server_handle)
                .await
            {
                Ok(Ok(Ok(()))) => {
                    info!("SSE proxy started successfully!");
                }
                Ok(Ok(Err(e))) => {
                    return Err(mcp_runner::error::Error::Other(format!(
                        "Failed to start SSE proxy: {}",
                        e
                    )));
                }
                Ok(Err(e)) => {
                    return Err(mcp_runner::error::Error::Other(format!(
                        "Task error when starting SSE proxy: {}",
                        e
                    )));
                }
                Err(_) => {
                    return Err(mcp_runner::error::Error::Other(
                        "Timeout waiting for SSE proxy to start".to_string(),
                    ));
                }
            }

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

            info!("Waiting for signals");

            // Wait for shutdown signal
            if shutdown_rx.await.is_err() {
                info!("Shutdown channel closed unexpectedly");
            } else {
                info!("Shutdown signal received");
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

        info!("mcp-gateway terminated");
        Ok(())
    }
}
