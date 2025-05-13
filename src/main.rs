use mcp_runner::error::Result;
use std::env;
use std::process;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

use mcp_gateway::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    fmt()
        .with_env_filter(EnvFilter::from_env("MCP_GW_LOG"))
        .with_target(true)
        .init();

    info!("Starting MCP Gateway");

    // Parse command-line arguments
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        error!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    info!("Using config file: {}", config.config_path);

    // Run the application
    if let Err(e) = mcp_gateway::run(config).await {
        error!("Application error: {e}");
        process::exit(1);
    }

    Ok(())
}
