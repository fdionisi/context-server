use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::Value;

use jsonrpc_types::{JsonRpcRequest, JsonRpcResponse, Response};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ClientCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
    pub experimental: Option<Value>,
    pub sampling: Option<Value>,
    pub roots: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EntityInfo {
    pub name: String,
    pub version: String,
}

impl<S> From<(S, S)> for EntityInfo
where
    S: Into<String>,
{
    fn from((name, version): (S, S)) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum LoggingLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum ContextServerMethod {
    Notification(NotificationKind),
    Reqest(RequestKind),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum Version {
    Number(u32),
    String(String),
}
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: EntityInfo,
}

#[derive(Default, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct PromptsListParams {
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsGetParams {
    pub name: String,
    pub arguments: Option<Value>,
}

#[derive(Default, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct ToolsListParams {
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCallParams {
    pub name: String,
    pub arguments: Option<Value>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesUnsubscribeParams {
    pub uri: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesSubscribeParams {
    pub uri: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesReadParams {
    pub uri: String,
}

#[derive(Default, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct ResourcesListParams {
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingSetLevelParams {
    pub level: LoggingLevel,
}

#[derive(Default, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct PingParams {
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

fn is_empty_params<T: Default + PartialEq>(params: &T) -> bool {
    params == &T::default()
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
pub enum RequestKind {
    #[serde(rename = "initialize", rename_all = "camelCase")]
    Initialize { params: InitializeParams },
    #[serde(rename = "prompts/list")]
    PromptsList {
        #[serde(default, skip_serializing_if = "is_empty_params")]
        params: PromptsListParams,
    },
    #[serde(rename = "prompts/get", rename_all = "camelCase")]
    PromptsGet { params: PromptsGetParams },
    #[serde(rename = "tools/list")]
    ToolsList {
        #[serde(default, skip_serializing_if = "is_empty_params")]
        params: ToolsListParams,
    },
    #[serde(rename = "tools/call", rename_all = "camelCase")]
    ToolsCall { params: ToolsCallParams },
    #[serde(rename = "resources/unsubscribe", rename_all = "camelCase")]
    ResourcesUnsubscribe { params: ResourcesUnsubscribeParams },
    #[serde(rename = "resources/subscribe", rename_all = "camelCase")]
    ResourcesSubscribe { params: ResourcesSubscribeParams },
    #[serde(rename = "resources/read", rename_all = "camelCase")]
    ResourcesRead { params: ResourcesReadParams },
    #[serde(rename = "resources/list")]
    ResourcesList {
        #[serde(default, skip_serializing_if = "is_empty_params")]
        params: ResourcesListParams,
    },
    #[serde(rename = "logging/setLevel", rename_all = "camelCase")]
    LoggingSetLevel { params: LoggingSetLevelParams },
    #[serde(rename = "ping")]
    Ping {
        #[serde(default, skip_serializing_if = "is_empty_params")]
        params: PingParams,
    },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method", content = "params")]
pub enum NotificationKind {
    #[serde(rename = "notifications/initialized")]
    Initialized,
    #[serde(rename = "notifications/progress")]
    Progress,
    #[serde(rename = "notifications/message")]
    Message,
    #[serde(rename = "notifications/resources/updated")]
    ResourcesUpdated,
    #[serde(rename = "notifications/resources/list_changed")]
    ResourcesListChanged,
    #[serde(rename = "notifications/tools/list_changed")]
    ToolsListChanged,
    #[serde(rename = "notifications/prompts/list_changed")]
    PromptsListChanged,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Prompt {
    pub name: String,
    pub arguments: Vec<PromptArgument>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: Option<bool>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptMessage {
    pub role: PromptRole,
    pub content: PromptContent,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptRole {
    User,
    Assistant,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PromptContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "resource")]
    Resource { resource: PromptContentResource },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptContentResource {
    pub mime_type: String,
    pub text: String,
    pub uri: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ToolContent {
    Text { text: String },
    Image { data: String, mime_type: String },
    Resource { resource: ToolContentResource },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolContentResource {
    pub uri: String,
    pub mime_type: String,
    pub text: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ContextServerRpcError {
    pub code: ErrorCode,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[repr(i32)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    ServerError = -32000,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingMessage {
    pub role: SamplingRole,
    pub content: SamplingContent,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SamplingRole {
    User,
    Assistant,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SamplingContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { data: String, mime_type: String },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPreferences {
    pub hints: Option<Vec<String>>,
    pub cost_priority: Option<f32>,
    pub speed_priority: Option<f32>,
    pub intelligence_priority: Option<f32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
    pub messages: Vec<SamplingMessage>,
    pub model_preferences: Option<ModelPreferences>,
    pub system_prompt: Option<String>,
    pub include_context: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    pub mime_type: String,
    #[serde(flatten)]
    pub content: ResourceContentType,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResourceContentType {
    Text { text: String },
    Blob { data: String },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Root {
    pub name: String,
    pub description: Option<String>,
    pub resources: Vec<Resource>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextServerResultEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
    #[serde(flatten)]
    pub result: ContextServerResult,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Cursor(String);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum ContextServerResult {
    #[serde(rename_all = "camelCase")]
    Initialize {
        protocol_version: String,
        server_info: EntityInfo,
        capabilities: ServerCapabilities,
    },
    PromptsList {
        prompts: Vec<Prompt>,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_cursor: Option<Cursor>,
    },
    PromptsGet {
        description: String,
        messages: Vec<PromptMessage>,
    },
    ToolsList {
        tools: Vec<Tool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_cursor: Option<Cursor>,
    },
    #[serde(rename_all = "camelCase")]
    ToolsCall {
        content: Vec<ToolContent>,
        is_error: bool,
    },
    ResourcesList {
        resources: Vec<Resource>,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_cursor: Option<Cursor>,
    },
    ResourcesRead {
        contents: Vec<ResourceContent>,
    },
    SamplingCreateMessage {
        messages: Vec<SamplingMessage>,
    },
    Pong {},
}

pub type ContextServerRpcRequest = JsonRpcRequest<ContextServerMethod>;
pub type ContextServerRpcResponse =
    JsonRpcResponse<ContextServerResultEnvelope, ContextServerRpcError>;

#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, arguments: Option<Value>) -> Result<Vec<ToolContent>>;
    fn to_tool(&self) -> Tool;
}

#[derive(Debug)]
pub struct ComputedPrompt {
    pub description: String,
    pub messages: Vec<PromptMessage>,
}

#[async_trait]
pub trait PromptExecutor: Send + Sync {
    fn name(&self) -> &str;
    async fn compute(&self, arguments: Option<Value>) -> Result<ComputedPrompt>;
    fn to_prompt(&self) -> Prompt;
}

pub trait NotificationDelegate: Send + Sync {
    fn on_initialized(&self) -> Result<()> {
        tracing::info!("Initialized notification received");
        Ok(())
    }

    fn on_progress(&self) -> Result<()> {
        tracing::debug!("Progress notification received");
        Ok(())
    }

    fn on_message(&self) -> Result<()> {
        tracing::debug!("Message notification received");
        Ok(())
    }

    fn on_resources_updated(&self) -> Result<()> {
        tracing::debug!("Resources updated notification received");
        Ok(())
    }

    fn on_resources_list_changed(&self) -> Result<()> {
        tracing::debug!("Resources list changed notification received");
        Ok(())
    }

    fn on_tools_list_changed(&self) -> Result<()> {
        tracing::debug!("Tools list changed notification received");
        Ok(())
    }

    fn on_prompts_list_changed(&self) -> Result<()> {
        tracing::debug!("Prompts list changed notification received");
        Ok(())
    }
}

#[async_trait]
pub trait PromptDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Prompt>>;
    async fn compute(&self, prompt: &str, arguments: Option<Value>) -> Result<ComputedPrompt>;
}

#[async_trait]
pub trait ResourceDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Resource>>;
    async fn get(&self, uri: &str) -> Result<Option<Resource>>;
    async fn read(&self, uri: &str) -> Result<ResourceContent>;
    async fn subscribe(&self, uri: &str) -> Result<()>;
    async fn unsubscribe(&self, uri: &str) -> Result<()>;
}

#[async_trait]
pub trait ToolDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Tool>>;
    async fn execute(&self, tool: &str, arguments: Option<Value>) -> Result<Vec<ToolContent>>;
}

#[async_trait]
pub trait SamplingDelegate: Send + Sync {
    async fn create_message(&self, request: SamplingRequest) -> Result<Vec<SamplingMessage>>;
}

#[derive(Clone)]
pub struct ContextServer {
    server_info: EntityInfo,
    prompts: Option<Arc<dyn PromptDelegate>>,
    resources: Option<Arc<dyn ResourceDelegate>>,
    tools: Option<Arc<dyn ToolDelegate>>,
    notification: Option<Arc<dyn NotificationDelegate>>,
    sampling: Option<Arc<dyn SamplingDelegate>>,
}

impl ContextServer {
    pub fn builder() -> ContextServerBuilder {
        tracing::debug!("Creating ContextServerBuilder");
        ContextServerBuilder {
            server_info: None,
            prompts: None,
            tools: None,
            notification: None,
            resources: None,
            sampling: None,
        }
    }

    pub async fn handle_incoming_message(
        &self,
        context_server_request: ContextServerRpcRequest,
    ) -> Result<Option<ContextServerRpcResponse>> {
        tracing::debug!("Handling incoming message");
        match context_server_request.payload {
            ContextServerMethod::Notification(notification) => {
                tracing::debug!("Processing notification");
                self.process_notification(notification).await?;

                Ok(None)
            }
            ContextServerMethod::Reqest(request) => {
                tracing::debug!("Processing request");
                let response = self.process_request(request).await?;
                Ok(Some(JsonRpcResponse(JsonRpcRequest {
                    header: context_server_request.header.clone(),
                    payload: Response {
                        result: Some(ContextServerResultEnvelope {
                            meta: None,
                            result: response,
                        }),
                        error: None,
                    },
                })))
            }
        }
    }

    async fn process_request(&self, request: RequestKind) -> Result<ContextServerResult> {
        tracing::debug!("Processing request: {:?}", request);
        match request {
            RequestKind::Initialize { params } => Ok(ContextServerResult::Initialize {
                protocol_version: params.protocol_version,
                server_info: self.server_info.clone(),
                capabilities: ServerCapabilities {
                    meta: None,
                    experimental: None,
                    prompts: self.prompts.as_ref().map(|_| Default::default()),
                    tools: self.tools.as_ref().map(|_| Default::default()),
                    resources: self.resources.as_ref().map(|_| Default::default()),
                    logging: self.notification.as_ref().map(|_| Default::default()),
                    sampling: self.sampling.as_ref().map(|_| Default::default()),
                },
            }),
            RequestKind::PromptsList { .. } => {
                if let Some(prompts) = &self.prompts {
                    tracing::debug!("Listing prompts");
                    Ok(ContextServerResult::PromptsList {
                        prompts: prompts.list().await?,
                        next_cursor: None,
                    })
                } else {
                    tracing::error!("Prompts not available");
                    Err(anyhow!("Prompts not available"))
                }
            }
            RequestKind::PromptsGet { params } => {
                if let Some(prompts) = &self.prompts {
                    tracing::debug!("Getting prompt: {}", params.name);
                    let ComputedPrompt {
                        description,
                        messages,
                    } = prompts.compute(&params.name, params.arguments).await?;
                    Ok(ContextServerResult::PromptsGet {
                        description,
                        messages,
                    })
                } else {
                    tracing::error!("Prompts not available");
                    Err(anyhow!("Prompts not available"))
                }
            }
            RequestKind::ToolsList { .. } => {
                if let Some(tools) = &self.tools {
                    tracing::debug!("Listing tools");
                    Ok(ContextServerResult::ToolsList {
                        tools: tools.list().await?,
                        next_cursor: None,
                    })
                } else {
                    tracing::error!("Tools not available");
                    Err(anyhow!("Tools not available"))
                }
            }
            RequestKind::ToolsCall { params } => {
                if let Some(tools) = &self.tools {
                    tracing::debug!("Calling tool: {}", params.name);
                    match tools.execute(&params.name, params.arguments).await {
                        Ok(content) => Ok(ContextServerResult::ToolsCall {
                            content,
                            is_error: false,
                        }),
                        Err(e) => Ok(ContextServerResult::ToolsCall {
                            content: vec![ToolContent::Text {
                                text: e.to_string(),
                            }],
                            is_error: true,
                        }),
                    }
                } else {
                    tracing::error!("Tools not available");
                    Err(anyhow!("Tools not available"))
                }
            }
            RequestKind::ResourcesList { .. } => {
                if let Some(resources) = &self.resources {
                    tracing::debug!("Listing resources");
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                        next_cursor: None,
                    })
                } else {
                    tracing::error!("Resources not available");
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesRead { params } => {
                if let Some(resources) = &self.resources {
                    tracing::debug!("Reading resource: {}", params.uri);
                    let content = resources.read(&params.uri).await?;
                    Ok(ContextServerResult::ResourcesRead {
                        contents: vec![content],
                    })
                } else {
                    tracing::error!("Resources not available");
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesUnsubscribe { params } => {
                if let Some(resources) = &self.resources {
                    tracing::debug!("Unsubscribing from resource: {}", params.uri);
                    resources.unsubscribe(&params.uri).await?;
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                        next_cursor: None,
                    })
                } else {
                    tracing::error!("Resources not available");
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesSubscribe { params } => {
                if let Some(resources) = &self.resources {
                    tracing::debug!("Subscribing to resource: {}", params.uri);
                    resources.subscribe(&params.uri).await?;
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                        next_cursor: None,
                    })
                } else {
                    tracing::error!("Resources not available");
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::Ping { .. } => {
                tracing::debug!("Received ping request");
                Ok(ContextServerResult::Pong {})
            }
            RequestKind::LoggingSetLevel { .. } => {
                tracing::warn!("LoggingSetLevel not implemented");
                unimplemented!()
            }
        }
    }

    async fn process_notification(&self, request: NotificationKind) -> Result<()> {
        tracing::debug!("Processing notification: {:?}", request);
        if let Some(notification) = &self.notification {
            match request {
                NotificationKind::Initialized => notification.on_initialized()?,
                NotificationKind::Progress => notification.on_progress()?,
                NotificationKind::Message => notification.on_message()?,
                NotificationKind::ResourcesUpdated => notification.on_resources_updated()?,
                NotificationKind::ResourcesListChanged => {
                    notification.on_resources_list_changed()?
                }
                NotificationKind::ToolsListChanged => notification.on_tools_list_changed()?,
                NotificationKind::PromptsListChanged => notification.on_prompts_list_changed()?,
            };
        }

        Ok(())
    }
}

pub struct ContextServerBuilder {
    server_info: Option<EntityInfo>,
    prompts: Option<Arc<dyn PromptDelegate>>,
    tools: Option<Arc<dyn ToolDelegate>>,
    notification: Option<Arc<dyn NotificationDelegate>>,
    resources: Option<Arc<dyn ResourceDelegate>>,
    sampling: Option<Arc<dyn SamplingDelegate>>,
}

impl ContextServerBuilder {
    pub fn with_server_info<I>(mut self, server_info: I) -> Self
    where
        I: Into<EntityInfo>,
    {
        tracing::debug!("Setting server info");
        self.server_info = Some(server_info.into());
        self
    }

    pub fn with_prompts(mut self, prompts: Arc<dyn PromptDelegate>) -> Self {
        tracing::debug!("Setting prompts delegate");
        self.prompts = Some(prompts);
        self
    }

    pub fn with_tools(mut self, tools: Arc<dyn ToolDelegate>) -> Self {
        tracing::debug!("Setting tools delegate");
        self.tools = Some(tools);
        self
    }

    pub fn with_notification(mut self, notification: Arc<dyn NotificationDelegate>) -> Self {
        tracing::debug!("Setting notification delegate");
        self.notification = Some(notification);
        self
    }

    pub fn with_resources(mut self, resources: Arc<dyn ResourceDelegate>) -> Self {
        tracing::debug!("Setting resources delegate");
        self.resources = Some(resources);
        self
    }

    pub fn with_sampling(mut self, sampling: Arc<dyn SamplingDelegate>) -> Self {
        tracing::debug!("Setting sampling delegate");
        self.sampling = Some(sampling);
        self
    }

    pub fn build(self) -> Result<ContextServer> {
        tracing::debug!("Building ContextServer");
        let server_info = self
            .server_info
            .ok_or_else(|| anyhow!("server_info is required"))?;

        Ok(ContextServer {
            server_info,
            prompts: self.prompts,
            resources: self.resources,
            tools: self.tools,
            notification: self.notification,
            sampling: self.sampling,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_types::{Header, Version};
    use serde_json::json;

    #[test]
    fn test_serialize_request_kind() {
        let cases = vec![
            (
                RequestKind::PromptsList {
                    params: PromptsListParams::default(),
                },
                json!({"method": "prompts/list"}),
            ),
            (
                RequestKind::ToolsList {
                    params: ToolsListParams::default(),
                },
                json!({"method": "tools/list"}),
            ),
            (
                RequestKind::ResourcesList {
                    params: ResourcesListParams::default(),
                },
                json!({"method": "resources/list"}),
            ),
            (
                RequestKind::Ping {
                    params: PingParams::default(),
                },
                json!({"method": "ping"}),
            ),
        ];

        for (kind, expected_json) in cases {
            let serialized = serde_json::to_value(&kind).unwrap();
            assert_eq!(serialized, expected_json);
        }
    }

    #[test]
    fn test_deserialize_request_kind() {
        let cases = vec![
            (
                json!({"method": "prompts/list"}),
                RequestKind::PromptsList {
                    params: PromptsListParams::default(),
                },
            ),
            (
                json!({"method": "tools/list"}),
                RequestKind::ToolsList {
                    params: ToolsListParams::default(),
                },
            ),
            (
                json!({"method": "resources/list"}),
                RequestKind::ResourcesList {
                    params: ResourcesListParams::default(),
                },
            ),
            (
                json!({"method": "ping"}),
                RequestKind::Ping {
                    params: PingParams::default(),
                },
            ),
        ];

        for (json, expected_kind) in cases {
            let deserialized: RequestKind = serde_json::from_value(json).unwrap();
            match (expected_kind, deserialized) {
                (RequestKind::PromptsList { .. }, RequestKind::PromptsList { .. }) => {}
                (RequestKind::ToolsList { .. }, RequestKind::ToolsList { .. }) => {}
                (RequestKind::ResourcesList { .. }, RequestKind::ResourcesList { .. }) => {}
                (RequestKind::Ping { .. }, RequestKind::Ping { .. }) => {}
                _ => panic!("Deserialization mismatch"),
            }
        }
    }

    #[test]
    fn test_deserialize_request_kind_with_empty_params() {
        let cases = vec![
            (
                json!({"method": "prompts/list", "params": {}}),
                RequestKind::PromptsList {
                    params: PromptsListParams::default(),
                },
            ),
            (
                json!({"method": "tools/list", "params": {}}),
                RequestKind::ToolsList {
                    params: ToolsListParams::default(),
                },
            ),
            (
                json!({"method": "resources/list", "params": {}}),
                RequestKind::ResourcesList {
                    params: ResourcesListParams::default(),
                },
            ),
            (
                json!({"method": "ping", "params": {}}),
                RequestKind::Ping {
                    params: PingParams::default(),
                },
            ),
        ];

        for (json, expected_kind) in cases {
            let deserialized: RequestKind = serde_json::from_value(json).unwrap();
            match (expected_kind, deserialized) {
                (RequestKind::PromptsList { .. }, RequestKind::PromptsList { .. }) => {}
                (RequestKind::ToolsList { .. }, RequestKind::ToolsList { .. }) => {}
                (RequestKind::ResourcesList { .. }, RequestKind::ResourcesList { .. }) => {}
                (RequestKind::Ping { .. }, RequestKind::Ping { .. }) => {}
                _ => panic!("Deserialization mismatch"),
            }
        }
    }

    #[test]
    fn test_serialize_deserialize_full_jsonrpc_request() {
        let original_request = ContextServerRpcRequest {
            header: Header {
                jsonrpc: Version::Two,
                id: Some(1),
            },
            payload: ContextServerMethod::Reqest(RequestKind::PromptsList {
                params: PromptsListParams::default(),
            }),
        };

        let _ = serde_json::to_string(&original_request).unwrap();

        let json_str = r#"{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{"_meta":{"progressToken":1}}}"#;
        let deserialized: ContextServerRpcRequest = serde_json::from_str(json_str).unwrap();

        match deserialized.payload {
            ContextServerMethod::Reqest(RequestKind::PromptsList { params }) => {
                assert!(params.meta.is_some());
            }
            _ => panic!("Failed to deserialize to the expected method"),
        }

        assert_eq!(deserialized.header.jsonrpc, Version::Two);
        assert_eq!(deserialized.header.id, Some(1));
    }

    #[test]
    fn test_deserialize_initialize_request() {
        let json_str = r#"{"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"claude-ai","version":"0.1.0"}},"jsonrpc":"2.0","id":0}"#;
        let deserialized: ContextServerRpcRequest = serde_json::from_str(json_str).unwrap();

        match deserialized.payload {
            ContextServerMethod::Reqest(RequestKind::Initialize { params }) => {
                assert_eq!(params.protocol_version, "2024-11-05");
                assert_eq!(params.client_info.name, "claude-ai");
                assert_eq!(params.client_info.version, "0.1.0");
            }
            _ => panic!("Failed to deserialize to the expected initialize method"),
        }

        assert_eq!(deserialized.header.jsonrpc, Version::Two);
        assert_eq!(deserialized.header.id, Some(0));
    }
}
