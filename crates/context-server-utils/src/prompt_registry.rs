use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use context_server::{ComputedPrompt, Prompt, PromptDelegate, PromptExecutor};
use parking_lot::RwLock;
use serde_json::Value;

#[derive(Default)]
pub struct PromptRegistry(RwLock<HashMap<String, Arc<dyn PromptExecutor>>>);

impl PromptRegistry {
    #[allow(unused)]
    pub fn register(&self, prompt: Arc<dyn PromptExecutor>) {
        self.0.write().insert(prompt.name().to_string(), prompt);
    }
}

#[async_trait]
impl PromptDelegate for PromptRegistry {
    async fn list(&self) -> Result<Vec<Prompt>> {
        Ok(self.0.read().values().map(|p| p.to_prompt()).collect())
    }

    async fn compute(&self, prompt: &str, arguments: Option<Value>) -> Result<ComputedPrompt> {
        let prompt = self
            .0
            .read()
            .get(prompt)
            .ok_or_else(|| anyhow!("Prompt not found: {}", prompt))?
            .clone();

        prompt.compute(arguments).await
    }
}
