use mcp_runner::error::Result;
use std::env;
use std::process;
use tracing::error;

use mcp_gateway::{Config, init_logging, run};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    init_logging();

    // Parse command-line arguments and handle special commands
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        // If error is from help or stop command, exit cleanly
        if err == "Help requested" || err == "Stop command executed" {
            process::exit(0);
        }
        
        error!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    // Run the application with the parsed configuration
    if let Err(e) = run(config).await {
        error!("Application error: {e}");
        process::exit(1);
    }

    Ok(())
}