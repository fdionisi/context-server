use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::Value;

use jsonrpc_types::{JsonRpcRequest, JsonRpcResponse, Response};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ClientCapabilities {
    experimental: Option<Value>,
    sampling: Option<Value>,
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

#[derive(serde::Serialize, serde::Deserialize)]
pub enum LoggingLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(serde::Deserialize, serde::Serialize)]
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

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(tag = "method", content = "params")]
pub enum RequestKind {
    #[serde(rename = "initialize", rename_all = "camelCase")]
    Initialize {
        protocol_version: String,
        capabilities: ClientCapabilities,
        client_info: EntityInfo,
    },
    #[serde(rename = "prompts/list", rename_all = "camelCase")]
    PromptsList {},
    #[serde(rename = "prompts/get", rename_all = "camelCase")]
    PromptsGet {
        name: String,
        arguments: Option<Value>,
    },
    #[serde(rename = "tools/list", rename_all = "camelCase")]
    ToolsList {},
    #[serde(rename = "tools/call", rename_all = "camelCase")]
    ToolsCall {
        name: String,
        arguments: Option<Value>,
    },
    #[serde(rename = "resources/unsubscribe", rename_all = "camelCase")]
    ResourcesUnsubscribe { uri: String },
    #[serde(rename = "resources/subscribe", rename_all = "camelCase")]
    ResourcesSubscribe { uri: String },
    #[serde(rename = "resources/read", rename_all = "camelCase")]
    ResourcesRead { uri: String },
    #[serde(rename = "resources/list", rename_all = "camelCase")]
    ResourcesList {},
    #[serde(rename = "sampling/createMessage", rename_all = "camelCase")]
    SamplingCreateMessage(SamplingRequest),
    #[serde(rename = "logging/setLevel", rename_all = "camelCase")]
    LoggingSetLevel { level: LoggingLevel },
    #[serde(rename = "roots/list", rename_all = "camelCase")]
    RootsList {},
    #[serde(rename = "roots/get", rename_all = "camelCase")]
    RootsGet { name: String },
    #[serde(rename = "ping", rename_all = "camelCase")]
    Ping,
}

#[derive(serde::Deserialize, serde::Serialize)]
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
    #[serde(rename = "notifications/roots/list_changed")]
    RootsListChanged,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<HashMap<String, Value>>,
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

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
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
#[serde(tag = "type")]
pub enum ResourceContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "blob")]
    Blob { data: String },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Root {
    pub name: String,
    pub description: Option<String>,
    pub resources: Vec<Resource>,
}

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
    },
    PromptsGet {
        description: String,
        messages: Vec<SamplingMessage>,
    },
    ToolsList {
        tools: Vec<Tool>,
    },
    #[serde(rename_all = "camelCase")]
    ToolsCall {
        tool_result: String,
    },
    ResourcesList {
        resources: Vec<Resource>,
    },
    ResourcesRead {
        contents: Vec<ResourceContent>,
    },
    SamplingCreateMessage {
        messages: Vec<SamplingMessage>,
    },
    RootsList {
        roots: Vec<Root>,
    },
    RootsGet {
        root: Root,
    },
    Pong {},
}

pub type ContextServerRpcRequest = JsonRpcRequest<ContextServerMethod>;
pub type ContextServerRpcResponse = JsonRpcResponse<ContextServerResult, ContextServerRpcError>;

#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, arguments: Option<Value>) -> Result<String>;
    fn to_tool(&self) -> Tool;
}

#[async_trait]
pub trait PromptExecutor: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self, arguments: &Option<Value>) -> Result<String>;
    async fn execute(&self, arguments: &Option<Value>) -> Result<String>;
    fn to_prompt(&self) -> Prompt;
}

pub trait NotificationDelegate {
    fn on_initialized(&self) -> Result<()> {
        Ok(())
    }

    fn on_progress(&self) -> Result<()> {
        Ok(())
    }

    fn on_message(&self) -> Result<()> {
        Ok(())
    }

    fn on_resources_updated(&self) -> Result<()> {
        Ok(())
    }

    fn on_resources_list_changed(&self) -> Result<()> {
        Ok(())
    }

    fn on_tools_list_changed(&self) -> Result<()> {
        Ok(())
    }

    fn on_prompts_list_changed(&self) -> Result<()> {
        Ok(())
    }

    fn on_roots_list_changed(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct PromptRegistry(HashMap<String, Arc<dyn PromptExecutor>>);

impl PromptRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, prompt: Arc<dyn PromptExecutor>) {
        self.0.insert(prompt.name().to_string(), prompt);
    }

    pub fn list_prompts(&self) -> Vec<Prompt> {
        self.0.values().map(|p| p.to_prompt()).collect()
    }

    pub async fn execute_prompt(
        &self,
        prompt: &str,
        arguments: Option<Value>,
    ) -> Result<(String, String)> {
        let prompt = self
            .0
            .get(prompt)
            .ok_or_else(|| anyhow!("Prompt not found: {}", prompt))?;

        Ok((
            prompt.description(&arguments)?,
            prompt.execute(&arguments).await?,
        ))
    }
}

#[async_trait]
pub trait PromptDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Prompt>>;
    async fn execute(&self, prompt: &str, arguments: Option<Value>) -> Result<(String, String)>;
}

#[async_trait]
impl PromptDelegate for PromptRegistry {
    async fn list(&self) -> Result<Vec<Prompt>> {
        Ok(self.list_prompts())
    }

    async fn execute(&self, prompt: &str, arguments: Option<Value>) -> Result<(String, String)> {
        self.execute_prompt(prompt, arguments).await
    }
}

#[async_trait]
pub trait ResourceDelegate {
    async fn list(&self) -> Result<Vec<Resource>>;
    async fn get(&self, uri: &str) -> Result<Option<Resource>>;
    async fn read(&self, uri: &str) -> Result<ResourceContent>;
    async fn subscribe(&self, uri: &str) -> Result<()>;
    async fn unsubscribe(&self, uri: &str) -> Result<()>;
}

#[async_trait]
pub trait ToolDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Tool>>;
    async fn execute(&self, tool: &str, arguments: Option<Value>) -> Result<String>;
}

pub struct ToolRegistry(HashMap<String, Arc<dyn ToolExecutor>>);

impl ToolRegistry {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn register(&mut self, tool: Arc<dyn ToolExecutor>) {
        self.0.insert(tool.to_tool().name.clone(), tool);
    }

    pub fn list(&self) -> Vec<Tool> {
        self.0.values().map(|t| t.to_tool()).collect()
    }

    pub async fn execute(&self, tool: &str, arguments: Option<Value>) -> Result<String> {
        let tool = self
            .0
            .get(tool)
            .ok_or_else(|| anyhow!("Tool not found: {}", tool))?;

        tool.execute(arguments).await
    }
}

#[async_trait]
impl ToolDelegate for ToolRegistry {
    async fn list(&self) -> Result<Vec<Tool>> {
        Ok(self.list())
    }

    async fn execute(&self, tool: &str, arguments: Option<Value>) -> Result<String> {
        self.execute(tool, arguments).await
    }
}

#[async_trait]
pub trait SamplingDelegate: Send + Sync {
    async fn create_message(&self, request: SamplingRequest) -> Result<Vec<SamplingMessage>>;
}

#[async_trait]
pub trait RootDelegate: Send + Sync {
    async fn list(&self) -> Result<Vec<Root>>;
    async fn get(&self, name: &str) -> Result<Root>;
}

pub struct ContextServerRpc {
    server_info: EntityInfo,
    prompts: Option<Arc<dyn PromptDelegate>>,
    resources: Option<Arc<dyn ResourceDelegate>>,
    tools: Option<Arc<dyn ToolDelegate>>,
    notification: Option<Arc<dyn NotificationDelegate>>,
    sampling: Option<Arc<dyn SamplingDelegate>>,
    roots: Option<Arc<dyn RootDelegate>>,
}

impl ContextServerRpc {
    pub fn builder() -> ContextServerRpcBuilder {
        ContextServerRpcBuilder {
            server_info: None,
            prompts: None,
            tools: None,
            notification: None,
            resources: None,
            sampling: None,
            roots: None,
        }
    }

    pub async fn process_rpc_request(
        &self,
        context_server_request: ContextServerRpcRequest,
    ) -> Result<Option<ContextServerRpcResponse>> {
        match context_server_request.payload {
            ContextServerMethod::Notification(notification) => {
                self.process_notification(notification).await?;

                Ok(None)
            }
            ContextServerMethod::Reqest(request) => {
                let response = self.process_request(request).await?;
                Ok(Some(JsonRpcResponse(JsonRpcRequest {
                    header: context_server_request.header.clone(),
                    payload: Response {
                        result: Some(response),
                        error: None,
                    },
                })))
            }
        }
    }

    async fn process_request(&self, request: RequestKind) -> Result<ContextServerResult> {
        match request {
            RequestKind::Initialize {
                protocol_version, ..
            } => Ok(ContextServerResult::Initialize {
                protocol_version,
                server_info: self.server_info.clone(),
                capabilities: ServerCapabilities {
                    experimental: None,
                    prompts: self.prompts.as_ref().map(|_| Default::default()),
                    tools: self.tools.as_ref().map(|_| Default::default()),
                    resources: self.resources.as_ref().map(|_| Default::default()),
                    logging: self.notification.as_ref().map(|_| Default::default()),
                    sampling: self.sampling.as_ref().map(|_| Default::default()),
                    roots: self.roots.as_ref().map(|_| Default::default()),
                },
            }),
            RequestKind::PromptsList {} => {
                if let Some(prompts) = &self.prompts {
                    Ok(ContextServerResult::PromptsList {
                        prompts: prompts.list().await?,
                    })
                } else {
                    Err(anyhow!("Prompts not available"))
                }
            }
            RequestKind::PromptsGet { name, arguments } => {
                if let Some(prompts) = &self.prompts {
                    let (description, text) = prompts.execute(&name, arguments).await?;
                    Ok(ContextServerResult::PromptsGet {
                        description,
                        messages: vec![SamplingMessage {
                            role: SamplingRole::User,
                            content: SamplingContent::Text { text },
                        }],
                    })
                } else {
                    Err(anyhow!("Prompts not available"))
                }
            }
            RequestKind::ToolsList {} => {
                if let Some(tools) = &self.tools {
                    Ok(ContextServerResult::ToolsList {
                        tools: tools.list().await?,
                    })
                } else {
                    Err(anyhow!("Tools not available"))
                }
            }
            RequestKind::ToolsCall { name, arguments } => {
                if let Some(tools) = &self.tools {
                    let result = tools.execute(&name, arguments).await?;
                    Ok(ContextServerResult::ToolsCall {
                        tool_result: result,
                    })
                } else {
                    Err(anyhow!("Tools not available"))
                }
            }
            RequestKind::SamplingCreateMessage(sampling_request) => {
                if let Some(sampling) = &self.sampling {
                    let messages = sampling.create_message(sampling_request).await?;
                    Ok(ContextServerResult::SamplingCreateMessage { messages })
                } else {
                    Err(anyhow!("Sampling not available"))
                }
            }
            RequestKind::ResourcesList {} => {
                if let Some(resources) = &self.resources {
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                    })
                } else {
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesRead { uri } => {
                if let Some(resources) = &self.resources {
                    let content = resources.read(&uri).await?;
                    Ok(ContextServerResult::ResourcesRead {
                        contents: vec![content],
                    })
                } else {
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesUnsubscribe { uri } => {
                if let Some(resources) = &self.resources {
                    resources.unsubscribe(&uri).await?;
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                    })
                } else {
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::ResourcesSubscribe { uri } => {
                if let Some(resources) = &self.resources {
                    resources.subscribe(&uri).await?;
                    Ok(ContextServerResult::ResourcesList {
                        resources: resources.list().await?,
                    })
                } else {
                    Err(anyhow!("Resources not available"))
                }
            }
            RequestKind::RootsList {} => {
                if let Some(roots) = &self.roots {
                    Ok(ContextServerResult::RootsList {
                        roots: roots.list().await?,
                    })
                } else {
                    Err(anyhow!("Roots not available"))
                }
            }
            RequestKind::RootsGet { name } => {
                if let Some(roots) = &self.roots {
                    Ok(ContextServerResult::RootsGet {
                        root: roots.get(&name).await?,
                    })
                } else {
                    Err(anyhow!("Roots not available"))
                }
            }
            RequestKind::Ping => Ok(ContextServerResult::Pong {}),
            RequestKind::LoggingSetLevel { .. } => {
                unimplemented!()
            }
        }
    }

    async fn process_notification(&self, request: NotificationKind) -> Result<()> {
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
                NotificationKind::RootsListChanged => notification.on_roots_list_changed()?,
            };
        }

        Ok(())
    }
}

pub struct ContextServerRpcBuilder {
    server_info: Option<EntityInfo>,
    prompts: Option<Arc<dyn PromptDelegate>>,
    tools: Option<Arc<dyn ToolDelegate>>,
    notification: Option<Arc<dyn NotificationDelegate>>,
    resources: Option<Arc<dyn ResourceDelegate>>,
    sampling: Option<Arc<dyn SamplingDelegate>>,
    roots: Option<Arc<dyn RootDelegate>>,
}

impl ContextServerRpcBuilder {
    pub fn with_server_info<I>(mut self, server_info: I) -> Self
    where
        I: Into<EntityInfo>,
    {
        self.server_info = Some(server_info.into());
        self
    }

    pub fn with_prompts(mut self, prompts: Arc<dyn PromptDelegate>) -> Self {
        self.prompts = Some(prompts);
        self
    }

    pub fn with_tools(mut self, tools: Arc<dyn ToolDelegate>) -> Self {
        self.tools = Some(tools);
        self
    }

    pub fn with_notification(mut self, notification: Arc<dyn NotificationDelegate>) -> Self {
        self.notification = Some(notification);
        self
    }

    pub fn with_resources(mut self, resources: Arc<dyn ResourceDelegate>) -> Self {
        self.resources = Some(resources);
        self
    }

    pub fn with_sampling(mut self, sampling: Arc<dyn SamplingDelegate>) -> Self {
        self.sampling = Some(sampling);
        self
    }

    pub fn with_roots(mut self, roots: Arc<dyn RootDelegate>) -> Self {
        self.roots = Some(roots);
        self
    }

    pub fn build(self) -> Result<ContextServerRpc> {
        let server_info = self
            .server_info
            .ok_or_else(|| anyhow!("server_info is required"))?;

        Ok(ContextServerRpc {
            server_info,
            prompts: self.prompts,
            resources: self.resources,
            tools: self.tools,
            notification: self.notification,
            sampling: self.sampling,
            roots: self.roots,
        })
    }
}
