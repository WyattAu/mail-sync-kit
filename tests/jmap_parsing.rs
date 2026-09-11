//! JMAP response parsing validation tests.
//!
//! Tests JMAP response deserialization without a real server, using
//! realistic Fastmail session responses and error handling.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use mail_sync_kit::jmap::{JmapRequest, JmapResponse, JmapSession};

/// Realistic Fastmail JMAP session response.
const FASTMAIL_SESSION: &str = r#"{
    "apiUrl": "https://api.fastmail.com/jmap/",
    "downloadUrl": "https://storage.fastmail.com/jmap/download/{accountId}/{blobId}",
    "uploadUrl": "https://storage.fastmail.com/jmap/upload/{accountId}",
    "eventSourceUrl": "https://api.fastmail.com/jmap/event/",
    "accounts": {
        "u12345678": {
            "name": "User",
            "isReadOnly": false,
            "urn:ietf:params:jmap:mail": {
                "maxSizeMailboxNameLength": 256
            }
        }
    },
    "primaryAccounts": {
        "urn:ietf:params:jmap:core": "u12345678",
        "urn:ietf:params:jmap:mail": "u12345678",
        "urn:ietf:params:jmap:submission": "u12345678",
        "urn:ietf:params:jmap:vacation": "u12345678"
    }
}"#;

/// Realistic Mailbox/get response from Fastmail.
const MAILBOX_GET_RESPONSE: &str = r#"{
    "methodResponses": [
        [
            "Mailbox/get",
            {
                "accountId": "u12345678",
                "state": "0",
                "list": [
                    {
                        "id": "mb1",
                        "name": "INBOX",
                        "parentId": null,
                        "role": "inbox",
                        "sortOrder": 0,
                        "totalEmails": 42,
                        "unreadEmails": 5,
                        "totalThreads": 42,
                        "unreadThreads": 5,
                        "myRights": {
                            "mayReadItems": true,
                            "mayAddItems": true,
                            "mayRemoveItems": true,
                            "mayCreateChild": true,
                            "mayDeleteItems": true,
                            "mayRenameMailbox": true,
                            "maySubmit": true
                        },
                        "isSubscribed": true
                    },
                    {
                        "id": "mb2",
                        "name": "Sent",
                        "parentId": null,
                        "role": "sent",
                        "sortOrder": 1,
                        "totalEmails": 100,
                        "unreadEmails": 0,
                        "totalThreads": 100,
                        "unreadThreads": 0,
                        "myRights": {
                            "mayReadItems": true,
                            "mayAddItems": false,
                            "mayRemoveItems": false,
                            "mayCreateChild": true,
                            "mayDeleteItems": false,
                            "mayRenameMailbox": true,
                            "maySubmit": true
                        },
                        "isSubscribed": true
                    },
                    {
                        "id": "mb3",
                        "name": "Drafts",
                        "parentId": null,
                        "role": "drafts",
                        "sortOrder": 2,
                        "totalEmails": 3,
                        "unreadEmails": 0,
                        "totalThreads": 3,
                        "unreadThreads": 0,
                        "myRights": {
                            "mayReadItems": true,
                            "mayAddItems": true,
                            "mayRemoveItems": true,
                            "mayCreateChild": true,
                            "mayDeleteItems": true,
                            "mayRenameMailbox": true,
                            "maySubmit": true
                        },
                        "isSubscribed": true
                    }
                ],
                "notFound": []
            },
            "c1"
        ]
    ],
    "newState": "1234"
}"#;

/// Realistic Email/get response with multiple emails.
const EMAIL_GET_RESPONSE: &str = r#"{
    "methodResponses": [
        [
            "Email/get",
            {
                "accountId": "u12345678",
                "state": "0",
                "list": [
                    {
                        "id": "em1",
                        "blobId": "blob1",
                        "threadId": "th1",
                        "mailboxIds": { "mb1": true },
                        "keywords": { "$seen": true, "$flagged": true },
                        "from": [
                            { "name": "Alice Smith", "email": "alice@example.com" }
                        ],
                        "to": [
                            { "name": null, "email": "user@fastmail.com" }
                        ],
                        "cc": [],
                        "subject": "Meeting Tomorrow",
                        "receivedAt": "2026-08-30T14:30:00Z",
                        "size": 4521,
                        "preview": "Hi, just confirming our meeting tomorrow at 2pm."
                    },
                    {
                        "id": "em2",
                        "blobId": "blob2",
                        "threadId": "th2",
                        "mailboxIds": { "mb1": true },
                        "keywords": {},
                        "from": [
                            { "name": "Bob Jones", "email": "bob@company.org" }
                        ],
                        "to": [
                            { "name": "User", "email": "user@fastmail.com" }
                        ],
                        "cc": [
                            { "name": "Carol", "email": "carol@team.dev" }
                        ],
                        "subject": "Project Update",
                        "receivedAt": "2026-08-30T10:15:00Z",
                        "size": 12890,
                        "preview": "Here is the latest project status..."
                    }
                ],
                "notFound": []
            },
            "g1"
        ]
    ],
    "newState": "1235"
}"#;

#[test]
fn fastmail_session_deserialization() {
    let session: JmapSession = serde_json::from_str(FASTMAIL_SESSION).unwrap();
    assert_eq!(session.api_url, "https://api.fastmail.com/jmap/");
    assert!(session.download_url.contains("storage.fastmail.com"));
    assert!(session.upload_url.contains("storage.fastmail.com"));
    assert_eq!(session.accounts.len(), 1);
    let account = session.accounts.get("u12345678").unwrap();
    assert_eq!(account.name, "User");
    assert!(!account.is_read_only);
    assert_eq!(
        session
            .primary_accounts
            .get("urn:ietf:params:jmap:mail")
            .unwrap(),
        "u12345678"
    );
}

#[test]
fn fastmail_session_mail_capability() {
    let session: JmapSession = serde_json::from_str(FASTMAIL_SESSION).unwrap();
    let account = session.accounts.get("u12345678").unwrap();
    let mail = account.mail.as_ref().unwrap();
    assert_eq!(mail.max_mailbox_name_length, Some(256));
}

#[test]
fn mailbox_get_response_parses_folders() {
    let resp: JmapResponse = serde_json::from_str(MAILBOX_GET_RESPONSE).unwrap();
    assert_eq!(resp.method_responses.len(), 1);
    assert_eq!(resp.new_state.as_deref(), Some("1234"));

    let method_resp = &resp.method_responses[0];
    let arr = method_resp.as_array().unwrap();
    assert_eq!(arr[0].as_str().unwrap(), "Mailbox/get");
    let data = &arr[1];
    let list = data.get("list").unwrap().as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].get("name").unwrap().as_str().unwrap(), "INBOX");
    assert_eq!(list[0].get("role").unwrap().as_str().unwrap(), "inbox");
    assert_eq!(list[0].get("totalEmails").unwrap().as_u64().unwrap(), 42);
    assert_eq!(list[1].get("role").unwrap().as_str().unwrap(), "sent");
    assert_eq!(list[2].get("role").unwrap().as_str().unwrap(), "drafts");
}

#[test]
fn mailbox_get_response_includes_rights() {
    let resp: JmapResponse = serde_json::from_str(MAILBOX_GET_RESPONSE).unwrap();
    let method_resp = &resp.method_responses[0];
    let arr = method_resp.as_array().unwrap();
    let data = &arr[1];
    let list = data.get("list").unwrap().as_array().unwrap();
    let rights = list[0].get("myRights").unwrap();
    assert!(rights.get("mayReadItems").unwrap().as_bool().unwrap());
    assert!(rights.get("mayAddItems").unwrap().as_bool().unwrap());
}

#[test]
fn email_get_response_parses_messages() {
    let resp: JmapResponse = serde_json::from_str(EMAIL_GET_RESPONSE).unwrap();
    assert_eq!(resp.method_responses.len(), 1);
    assert_eq!(resp.new_state.as_deref(), Some("1235"));

    let method_resp = &resp.method_responses[0];
    let arr = method_resp.as_array().unwrap();
    assert_eq!(arr[0].as_str().unwrap(), "Email/get");
    let data = &arr[1];
    let list = data.get("list").unwrap().as_array().unwrap();
    assert_eq!(list.len(), 2);

    let email0 = &list[0];
    assert_eq!(email0.get("id").unwrap().as_str().unwrap(), "em1");
    assert_eq!(
        email0.get("subject").unwrap().as_str().unwrap(),
        "Meeting Tomorrow"
    );
    let from = email0.get("from").unwrap().as_array().unwrap();
    assert_eq!(
        from[0].get("name").unwrap().as_str().unwrap(),
        "Alice Smith"
    );
    assert_eq!(
        from[0].get("email").unwrap().as_str().unwrap(),
        "alice@example.com"
    );
    assert_eq!(email0.get("size").unwrap().as_u64().unwrap(), 4521);
    assert_eq!(
        email0.get("receivedAt").unwrap().as_str().unwrap(),
        "2026-08-30T14:30:00Z"
    );
}

#[test]
fn email_get_response_keywords_and_mailbox_ids() {
    let resp: JmapResponse = serde_json::from_str(EMAIL_GET_RESPONSE).unwrap();
    let method_resp = &resp.method_responses[0];
    let arr = method_resp.as_array().unwrap();
    let data = &arr[1];
    let list = data.get("list").unwrap().as_array().unwrap();

    let email0 = &list[0];
    let keywords = email0.get("keywords").unwrap().as_object().unwrap();
    assert!(keywords.contains_key("$seen"));
    assert!(keywords.contains_key("$flagged"));
    let mailbox_ids = email0.get("mailboxIds").unwrap().as_object().unwrap();
    assert!(mailbox_ids.contains_key("mb1"));

    let email1 = &list[1];
    let keywords = email1.get("keywords").unwrap().as_object().unwrap();
    assert!(keywords.is_empty());
    let cc = email1.get("cc").unwrap().as_array().unwrap();
    assert_eq!(cc.len(), 1);
    assert_eq!(
        cc[0].get("email").unwrap().as_str().unwrap(),
        "carol@team.dev"
    );
}

#[test]
fn error_handling_malformed_json() {
    let result = serde_json::from_str::<JmapResponse>(r#"{"not valid json"#);
    assert!(result.is_err());
}

#[test]
fn error_handling_missing_required_fields() {
    let result = serde_json::from_str::<JmapSession>(
        r#"{
        "apiUrl": "https://example.com/jmap",
        "accounts": {},
        "primaryAccounts": {}
    }"#,
    );
    assert!(result.is_err());
}

#[test]
fn error_handling_wrong_type_for_field() {
    let result = serde_json::from_str::<JmapSession>(
        r#"{
        "apiUrl": 12345,
        "downloadUrl": "https://example.com/download",
        "uploadUrl": "https://example.com/upload",
        "accounts": {},
        "primaryAccounts": {}
    }"#,
    );
    assert!(result.is_err());
}

#[test]
fn state_token_round_trip() {
    let state_token = "12345678";
    let req = JmapRequest {
        using: vec!["urn:ietf:params:jmap:core".into()],
        method_calls: vec![serde_json::json!(["Pong", {}, "c1"])],
        since_state: Some(state_token.into()),
    };
    let serialized = serde_json::to_value(&req).unwrap();
    assert_eq!(serialized["sinceState"].as_str().unwrap(), state_token);

    // Verify the serialized structure is correct.
    assert_eq!(
        serialized["using"][0].as_str().unwrap(),
        "urn:ietf:params:jmap:core"
    );
    let calls = serialized["methodCalls"].as_array().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][0].as_str().unwrap(), "Pong");
}

#[test]
fn state_token_none_omitted_in_serialization() {
    let req = JmapRequest {
        using: vec![],
        method_calls: vec![],
        since_state: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("sinceState").is_none());
}

#[test]
fn response_new_state_preserved() {
    let resp: JmapResponse = serde_json::from_str(MAILBOX_GET_RESPONSE).unwrap();
    assert_eq!(resp.new_state.as_deref(), Some("1234"));
}

#[test]
fn response_without_new_state() {
    let json = r#"{
        "methodResponses": [["Pong", {}, "c1"]]
    }"#;
    let resp: JmapResponse = serde_json::from_str(json).unwrap();
    assert!(resp.new_state.is_none());
}

#[test]
fn empty_method_responses() {
    let json = r#"{
        "methodResponses": []
    }"#;
    let resp: JmapResponse = serde_json::from_str(json).unwrap();
    assert!(resp.method_responses.is_empty());
}
