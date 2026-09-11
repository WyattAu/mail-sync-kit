//! JMAP transport (RFC 8620/8621): session discovery, `Email/query` +
//! `Email/get`, `Mailbox/get`. State tokens map to the
//! [`SyncService`](crate::sync::SyncService)'s cursor model.
//!
//! Transport: HTTPS with the account's TLS config; each request is a JMAP
//! API call (`POST` to the session's `apiUrl`).

use crate::{
    error::{SyncError, SyncResult},
    secrets::SecretString,
};

/// JMAP session resource (subset of RFC 8620 §3).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct JmapSession {
    /// API URL for method calls.
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    /// Download URL template (for blobs).
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
    /// Upload URL.
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
    /// Primary accounts map.
    pub accounts: std::collections::HashMap<String, JmapAccount>,
    /// Primary accounts (accountId → capability URN).
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: std::collections::HashMap<String, String>,
}

/// Per-account JMAP capability data.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct JmapAccount {
    /// Account name.
    pub name: String,
    /// Whether the account is read-only.
    #[serde(rename = "isReadOnly")]
    pub is_read_only: bool,
    /// Mail capability (RFC 8621).
    #[serde(rename = "urn:ietf:params:jmap:mail", default)]
    pub mail: Option<JmapMailCapability>,
}

/// Mail capability (RFC 8621 §2).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct JmapMailCapability {
    /// Maximum mailbox name length in octets.
    #[serde(rename = "maxSizeMailboxNameLength")]
    pub max_mailbox_name_length: Option<u64>,
}

/// A JMAP request (RFC 8620 §3.3).
#[derive(serde::Serialize)]
pub struct JmapRequest {
    /// Capability URNs the client uses.
    pub using: Vec<String>,
    /// Method calls to execute.
    #[serde(rename = "methodCalls")]
    pub method_calls: Vec<serde_json::Value>,
    /// State token for delta requests.
    #[serde(rename = "sinceState", skip_serializing_if = "Option::is_none")]
    pub since_state: Option<String>,
}

/// A JMAP response (RFC 8620 §3.4).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct JmapResponse {
    /// Method responses, in order.
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<serde_json::Value>,
    /// New state token.
    #[serde(rename = "newState", skip_serializing_if = "Option::is_none")]
    pub new_state: Option<String>,
}

/// JMAP client over HTTPS.
pub struct JmapClient {
    http: reqwest::Client,
    api_url: String,
    auth_header: String,
}

impl JmapClient {
    /// Discovers the session via `/.well-known/jmap` on the account host.
    ///
    /// # Errors
    /// [`SyncError::Transport`] on HTTP failures or session parse errors.
    pub async fn discover(
        http: reqwest::Client,
        host: &str,
        token: &SecretString,
    ) -> SyncResult<Self> {
        let url = format!("https://{host}/.well-known/jmap");
        let resp = http
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.expose()))
            .send()
            .await
            .map_err(|e| SyncError::Transport {
                detail: e.to_string(),
            })?;
        if !resp.status().is_success() {
            return Err(SyncError::Transport {
                detail: format!("session discovery returned {}", resp.status()),
            });
        }
        let session: JmapSession = resp.json().await.map_err(|e| SyncError::Transport {
            detail: format!("session parse: {e}"),
        })?;
        Ok(Self {
            http,
            api_url: session.api_url,
            auth_header: format!("Bearer {}", token.expose()),
        })
    }

    /// Executes a batch of method calls.
    ///
    /// # Errors
    /// [`SyncError::Transport`] on transport failures.
    pub async fn call(
        &self,
        using: Vec<String>,
        method_calls: Vec<serde_json::Value>,
        since_state: Option<String>,
    ) -> SyncResult<JmapResponse> {
        let request = JmapRequest {
            using,
            method_calls,
            since_state,
        };
        let resp = self
            .http
            .post(&self.api_url)
            .header("Authorization", &self.auth_header)
            .json(&request)
            .send()
            .await
            .map_err(|e| SyncError::Transport {
                detail: e.to_string(),
            })?;
        if !resp.status().is_success() {
            return Err(SyncError::Transport {
                detail: format!("JMAP API returned {}", resp.status()),
            });
        }
        resp.json().await.map_err(|e| SyncError::Transport {
            detail: format!("JMAP response parse: {e}"),
        })
    }

    /// `Mailbox/get`: fetches the folder hierarchy (RFC 8621 §2).
    ///
    /// # Errors
    /// Transport failure.
    pub async fn get_mailboxes(&self) -> SyncResult<JmapResponse> {
        self.call(
            vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:mail".into(),
            ],
            vec![serde_json::json!([
                "Mailbox/get",
                { "accountId": null, "ids": null },
                "c1"
            ])],
            None,
        )
        .await
    }

    /// `Email/query` + `Email/get`: fetches messages (RFC 8621 §3/4).
    ///
    /// # Errors
    /// Transport failure.
    pub async fn query_emails(
        &self,
        mailbox_ids: Vec<String>,
        since_state: Option<String>,
        limit: u32,
    ) -> SyncResult<JmapResponse> {
        let calls = vec![
            serde_json::json!([
                "Email/query",
                {
                    "accountId": null,
                    "filter": { "inMailbox": mailbox_ids.first() },
                    "limit": limit,
                    "sort": [{ "property": "receivedAt", "isAscending": false }]
                },
                "q1"
            ]),
            serde_json::json!([
                "Email/get",
                {
                    "accountId": null,
                    "#ids": { "resultOf": "q1", "name": "Email/query", "path": "/ids" },
                    "properties": [
                        "id", "blobId", "threadId", "mailboxIds",
                        "from", "to", "cc", "bcc",
                        "subject", "receivedAt", "size", "keywords",
                        "header:Message-ID:asMessageIds",
                        "header:In-Reply-To:asMessageIds",
                        "preview"
                    ]
                },
                "g1"
            ]),
        ];
        self.call(
            vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:mail".into(),
            ],
            calls,
            since_state,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_parses_minimal() {
        let json = r#"{
            "apiUrl": "https://jmap.example/api",
            "downloadUrl": "https://jmap.example/download/{accountId}/{blobId}",
            "uploadUrl": "https://jmap.example/upload/{accountId}",
            "accounts": {},
            "primaryAccounts": {}
        }"#;
        let session: JmapSession = serde_json::from_str(json).unwrap();
        assert_eq!(session.api_url, "https://jmap.example/api");
    }

    #[test]
    fn request_serializes_with_since_state() {
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:core".into()],
            method_calls: vec![serde_json::json!(["Pong", {}, "c1"])],
            since_state: Some("abc".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["sinceState"], "abc");
        assert_eq!(json["using"][0], "urn:ietf:params:jmap:core");
    }

    #[test]
    fn response_parses_method_responses() {
        let json = r#"{
            "methodResponses": [["Mailbox/get", {"list": []}, "c1"]],
            "newState": "state2"
        }"#;
        let resp: JmapResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.method_responses.len(), 1);
        assert_eq!(resp.new_state.as_deref(), Some("state2"));
    }
}
