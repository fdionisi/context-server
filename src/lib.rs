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

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(tag = "method", content = "params")]
pub enum RequestKind {
    #[serde(rename = "initialize", rename_all = "camelCase")]
    Initialize {
        protocol_version: u32,
        capabilities: ClientCapabilities,
        client_info: EntityInfo,
    },
    #[serde(rename = "prompts/list", rename_all = "camelCase")]
    PromptsList,
    #[serde(rename = "prompts/get", rename_all = "camelCase")]
    PromptsGet {
        name: String,
        arguments: Option<Map<String, Value>>,
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
#[serde(untagged)]
pub enum ContextServerResult {
    #[serde(rename_all = "camelCase")]
    Initialize {
        protocol_version: u32,
        server_info: EntityInfo,
        capabilities: ServerCapabilities,
    },
    PromptsList {
        prompts: Vec<Prompt>,
    },
    PromptsGet {
        prompt: String,
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
    async fn execute(&self, arguments: Option<Map<String, Value>>) -> Result<String>;
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

pub struct ContextServerRpc {
    pub server_info: EntityInfo,
    pub prompts: HashMap<String, Box<dyn PromptExecutor>>,
    pub notification: Arc<dyn NotificationDelegate>,
}

impl ContextServerRpc {
    pub fn new(
        server_info: EntityInfo,
        prompts: HashMap<String, Box<dyn PromptExecutor>>,
        notification: Arc<dyn NotificationDelegate>,
    ) -> Self {
        Self {
            server_info,
            prompts,
            notification,
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
                prompts: self
                    .prompts
                    .iter()
                    .map(|(_, prompt)| prompt.to_prompt())
                    .collect(),
            }),
            RequestKind::PromptsGet { name, arguments } => Ok(ContextServerResult::PromptsGet {
                prompt: self
                    .prompts
                    .get(&name)
                    .ok_or_else(|| anyhow!(""))?
                    .execute(arguments)
                    .await?,
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
