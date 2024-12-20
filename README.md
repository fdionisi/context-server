# Context Server

Context Server is a Rust library that implements the Model Context Protocol.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
context-server = { git = "https://github.com/yourusername/context-server.git" }
```

## Usage

Here's a basic example of how to set up and use the Context Server:

```rust
use std::sync::Arc;

use context_server::{ContextServerRpc, PromptRegistry, ToolRegistry};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut prompt_registry = PromptRegistry::new();
    prompt_registry.register(Arc::new(PiratePrompt));

    let mut tool_registry = ToolRegistry::new();
    tool_registry.register(Arc::new(NowTool));

    let rpc_server = ContextServerRpc::builder()
            .with_server_info(("My Server", "0.1.0"))
            .with_prompts(Arc::new(prompt_registry))
            .with_tools(Arc::new(tool_registry))
            .build()?,

    let mut stdin = BufReader::new(io::stdin()).lines();
    let mut stdout = io::stdout();

    while let Some(line) = stdin.next_line().await? {
        let request: ContextServerRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Error parsing request: {}", e);
                continue;
            }
        };

        if let Some(response) = rpc_server.process_request(request).await? {
            let response_json = serde_json::to_string(&response)?;
            stdout.write_all(response_json.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
}
```

## License

This project is licensed under the [MIT License](LICENSE).
