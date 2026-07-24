//! Thin `reqwest` wrapper that logs every outbound request and its response
//! in full (no redaction — this is a debugging tool, see the design doc
//! section 6) to the wallet's event log before returning.

use crate::error::WalletResult;
use crate::storage::{event_log, now_rfc3339};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LoggingHttpClient {
    client: reqwest::Client,
    data_dir: PathBuf,
}

impl LoggingHttpClient {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            client: reqwest::Client::new(),
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn log_request(
        &self,
        method: &str,
        url: &str,
        headers: &Value,
        body: &str,
    ) -> WalletResult<()> {
        event_log::append_event(
            &self.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "http_request", "direction": "out",
                "method": method, "url": url, "headers": headers, "body": body,
            }),
        )
    }

    fn log_response(&self, status: u16, body: &str) -> WalletResult<()> {
        event_log::append_event(
            &self.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "http_response", "status": status, "body": body,
            }),
        )
    }

    async fn finish(&self, resp: reqwest::Response) -> WalletResult<(u16, String)> {
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        self.log_response(status, &text)?;
        Ok((status, text))
    }

    pub async fn get(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)> {
        let mut req = self.client.get(url);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let headers = if let Some(token) = bearer {
            serde_json::json!({"authorization": format!("Bearer {token}")})
        } else {
            serde_json::json!({})
        };
        self.log_request("GET", url, &headers, "")?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_json(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &Value,
    ) -> WalletResult<(u16, String)> {
        let mut req = self.client.post(url).json(body);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let mut headers = serde_json::json!({"content-type": "application/json"});
        if let Some(token) = bearer {
            headers["authorization"] = serde_json::json!(format!("Bearer {token}"));
        }
        self.log_request("POST", url, &headers, &serde_json::to_string(body)?)?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_form(
        &self,
        url: &str,
        bearer: Option<&str>,
        form_body: &str,
    ) -> WalletResult<(u16, String)> {
        let mut req = self
            .client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body.to_string());
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        self.log_request(
            "POST",
            url,
            &serde_json::json!({"content-type": "application/x-www-form-urlencoded"}),
            form_body,
        )?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_text(&self, url: &str, text_body: &str) -> WalletResult<(u16, String)> {
        self.log_request(
            "POST",
            url,
            &serde_json::json!({"content-type": "text/plain"}),
            text_body,
        )?;
        let resp = self
            .client
            .post(url)
            .header("content-type", "text/plain")
            .body(text_body.to_string())
            .send()
            .await?;
        self.finish(resp).await
    }

    pub async fn post_empty(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)> {
        let mut req = self.client.post(url);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let headers = if let Some(token) = bearer {
            serde_json::json!({"authorization": format!("Bearer {token}")})
        } else {
            serde_json::json!({})
        };
        self.log_request("POST", url, &headers, "")?;
        let resp = req.send().await?;
        self.finish(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    async fn spawn_echo_server() -> String {
        let app = Router::new()
            .route("/echo-get", get(|| async { "hello-get" }))
            .route(
                "/echo-post",
                post(|Json(body): Json<serde_json::Value>| async move { Json(body) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn post_json_returns_body_and_logs_request_and_response() {
        let base = spawn_echo_server().await;
        let dir = tempfile::tempdir().unwrap();
        let client = LoggingHttpClient::new(dir.path());

        let (status, body) = client
            .post_json(
                &format!("{base}/echo-post"),
                Some("secret-token"),
                &serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"hello":"world"}"#);

        let events = event_log::read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "http_request");
        assert_eq!(events[0]["method"], "POST");
        // No redaction: the bearer token appears in full in the logged headers.
        assert!(events[0]["headers"]["authorization"]
            .as_str()
            .unwrap()
            .contains("secret-token"));
        assert_eq!(events[1]["kind"], "http_response");
        assert_eq!(events[1]["status"], 200);
    }

    #[tokio::test]
    async fn get_without_bearer_logs_empty_auth_header() {
        let base = spawn_echo_server().await;
        let dir = tempfile::tempdir().unwrap();
        let client = LoggingHttpClient::new(dir.path());

        let (status, body) = client.get(&format!("{base}/echo-get"), None).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "hello-get");

        let events = event_log::read_events(dir.path()).unwrap();
        assert_eq!(events[0]["headers"], serde_json::json!({}));
    }
}
