mod json_rpc;

use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::json_rpc::{JsonRpcRequest, JsonRpcResponse, Response};

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
    PromptsList,
    #[serde(rename = "prompts/get", rename_all = "camelCase")]
    PromptsGet {
        name: String,
        arguments: Option<Value>,
    },
    #[serde(rename = "tools/list", rename_all = "camelCase")]
    ToolsList,
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
    ResourcesRead,
    #[serde(rename = "resources/list", rename_all = "camelCase")]
    ResourcesList,
    #[serde(rename = "logging/setLevel", rename_all = "camelCase")]
    LoggingSetLevel { level: LoggingLevel },
    #[serde(rename = "completion/complete", rename_all = "camelCase")]
    CompletionComplete,
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
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    pub experimental: Option<serde_json::Value>,
    pub prompts: Option<HashMap<String, serde_json::Value>>,
    // logging: Option<HashMap<String, serde_json::Value>>,
    // resources: Option<ResourcesCapabilities>,
    tools: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Prompt {
    pub name: String,
    pub arguments: Option<Vec<PromptArgument>>,
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
    pub input_schema: serde_json::Value,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ContextServerRpcError {
    pub code: i32,
    pub message: String,
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
#[serde(tag = "type")]
pub enum SamplingContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { data: String, mime_type: String },
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
        description: Option<String>,
        messages: Vec<SamplingMessage>,
    },
    ToolsList {
        tools: Vec<Tool>,
    },
    ToolsCall {
        tool_result: String,
    },
}

pub type ContextServerRpcRequest = JsonRpcRequest<ContextServerMethod>;
pub type ContextServerRpcResponse = JsonRpcResponse<ContextServerResult, ContextServerRpcError>;

#[async_trait]
pub trait ToolExecutor {
    async fn execute(&self, arguments: Option<Map<String, Value>>) -> Result<String>;
    fn to_tool(&self) -> Tool;
}

#[async_trait]
pub trait PromptExecutor {
    fn name(&self) -> &str;
    async fn execute(&self, arguments: Option<Value>) -> Result<String>;
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

    pub fn list(&self) -> Vec<Prompt> {
        self.0.values().map(|p| p.to_prompt()).collect()
    }

    pub async fn execute(&self, prompt: &str, arguments: Option<Value>) -> Result<String> {
        let prompt = self
            .0
            .get(prompt)
            .ok_or_else(|| anyhow!("Prompt not found: {}", prompt))?;

        prompt.execute(arguments).await
    }
}

pub struct ContextServerRpc {
    server_info: EntityInfo,
    prompts: PromptRegistry,
    notification: Arc<dyn NotificationDelegate>,
}

impl ContextServerRpc {
    pub fn builder() -> ContextServerRpcBuilder {
        ContextServerRpcBuilder {
            server_info: None,
            prompts: PromptRegistry::new(),
            notification: None,
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
                    prompts: Some(Default::default()),
                    tools: Some(Default::default()),
                },
            }),
            RequestKind::PromptsList => Ok(ContextServerResult::PromptsList {
                prompts: self.prompts.list(),
            }),
            RequestKind::PromptsGet { name, arguments } => Ok(ContextServerResult::PromptsGet {
                description: None,
                messages: vec![SamplingMessage {
                    role: SamplingRole::User,
                    content: SamplingContent::Text {
                        text: self.prompts.execute(&name, arguments).await?,
                    },
                }],
            }),
            RequestKind::ToolsList { .. }
            | RequestKind::ToolsCall { .. }
            | RequestKind::ResourcesUnsubscribe { .. }
            | RequestKind::ResourcesSubscribe { .. }
            | RequestKind::ResourcesRead
            | RequestKind::ResourcesList
            | RequestKind::LoggingSetLevel { .. }
            | RequestKind::CompletionComplete => unimplemented!(),
        }
    }

    async fn process_notification(&self, request: NotificationKind) -> Result<()> {
        match request {
            NotificationKind::Initialized => self.notification.on_initialized()?,
            NotificationKind::Progress => self.notification.on_progress()?,
            NotificationKind::Message => self.notification.on_message()?,
            NotificationKind::ResourcesUpdated => self.notification.on_resources_updated()?,
            NotificationKind::ResourcesListChanged => {
                self.notification.on_resources_list_changed()?
            }
            NotificationKind::ToolsListChanged => self.notification.on_tools_list_changed()?,
            NotificationKind::PromptsListChanged => self.notification.on_prompts_list_changed()?,
        };

        Ok(())
    }
}

struct NotificationNoop;

impl NotificationDelegate for NotificationNoop {}

pub struct ContextServerRpcBuilder {
    server_info: Option<EntityInfo>,
    prompts: PromptRegistry,
    notification: Option<Arc<dyn NotificationDelegate>>,
}

impl ContextServerRpcBuilder {
    pub fn with_server_info<I>(mut self, server_info: I) -> Self
    where
        I: Into<EntityInfo>,
    {
        self.server_info = Some(server_info.into());
        self
    }

    pub fn with_prompt(mut self, prompt: Arc<dyn PromptExecutor>) -> Self {
        self.prompts.register(prompt);
        self
    }

    pub fn with_notification(mut self, notification: Arc<dyn NotificationDelegate>) -> Self {
        self.notification = Some(notification);
        self
    }

    pub fn build(self) -> Result<ContextServerRpc> {
        let server_info = self
            .server_info
            .ok_or_else(|| anyhow!("server_info is required"))?;

        Ok(ContextServerRpc {
            server_info,
            prompts: self.prompts,
            notification: self
                .notification
                .unwrap_or_else(|| Arc::new(NotificationNoop)),
        })
    }
}
