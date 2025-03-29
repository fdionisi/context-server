use std::collections::HashMap;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use context_server::{Resource, ResourceContent, ResourceContentType, ResourceDelegate};

use parking_lot::RwLock;

#[derive(Default)]
pub struct ResourceRegistry {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    resources: HashMap<String, Resource>,
    contents: HashMap<String, String>,
}

impl ResourceRegistry {
    pub fn register(&self, resource: Resource, content: String) {
        let mut guard = self.inner.write();
        guard.contents.insert(resource.uri.clone(), content);
        guard.resources.insert(resource.uri.clone(), resource);
    }

    pub fn list_resources(&self) -> Vec<Resource> {
        let guard = self.inner.read();
        guard.resources.values().cloned().collect()
    }

    pub fn get_resource(&self, uri: &str) -> Option<Resource> {
        let guard = self.inner.read();
        guard.resources.get(uri).cloned()
    }

    pub fn read_content(&self, uri: &str) -> Option<String> {
        let guard = self.inner.read();
        guard.contents.get(uri).cloned()
    }
}

#[async_trait]
impl ResourceDelegate for ResourceRegistry {
    async fn list(&self) -> Result<Vec<Resource>> {
        Ok(self.list_resources())
    }

    async fn get(&self, uri: &str) -> Result<Option<Resource>> {
        Ok(self.get_resource(uri).clone())
    }

    async fn read(&self, uri: &str) -> Result<ResourceContent> {
        let resource = self
            .get_resource(uri)
            .ok_or_else(|| anyhow!("Resource not found: {}", uri))?;
        let content = self
            .read_content(uri)
            .ok_or_else(|| anyhow!("Content not found for resource: {}", uri))?;

        Ok(ResourceContent {
            uri: uri.to_string(),
            mime_type: resource
                .mime_type
                .clone()
                .unwrap_or_else(|| "text/plain".to_string()),
            content: ResourceContentType::Text {
                text: content.clone(),
            },
        })
    }

    async fn subscribe(&self, _uri: &str) -> Result<()> {
        Ok(())
    }

    async fn unsubscribe(&self, _uri: &str) -> Result<()> {
        Ok(())
    }
}
