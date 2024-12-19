#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum Version {
    #[serde(rename = "1.0")]
    One,
    #[serde(rename = "2.0")]
    Two,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Header {
    pub jsonrpc: Version,
    pub id: Option<usize>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct JsonRpcRequest<T> {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub payload: T,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct JsonRpcResponse<R, E>(pub JsonRpcRequest<Response<R, E>>);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Response<R, E> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<R>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<E>,
}
