use mcp_runner::error::Result;
use std::env;
use std::process;

use mcp_gateway::McpGateway;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments and create McpGateway
    let gateway = McpGateway::new_from_args(env::args()).unwrap_or_else(|err| {
        // If error is from help or stop command, exit cleanly
        if err == "Help requested" || err == "Stop command executed" {
            process::exit(0);
        }
        
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    // Run the application
    if let Err(e) = gateway.run().await {
        eprintln!("Application error: {e}");
        process::exit(1);
    }

    Ok(())
}