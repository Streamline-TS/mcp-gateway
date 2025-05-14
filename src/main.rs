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

use mcp_runner::error::Result;
use std::env;
use std::process;

use mcp_gateway::McpGateway;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments and create McpGateway
    let gateway = McpGateway::new_from_args(env::args()).unwrap_or_else(|err| {
        // If error is from help command, exit cleanly
        if err == "Help requested" {
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
