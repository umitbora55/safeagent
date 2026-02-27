use async_trait::async_trait;
use safeagent_bridge_common::*;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct TelegramBridge {
    bot_token: String,
    allowed_chats: Vec<String>,
}

impl TelegramBridge {
    pub fn new(bot_token: String, allowed_chats: Vec<String>) -> Self {
        Self {
            bot_token,
            allowed_chats,
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }
}

#[async_trait]
impl Bridge for TelegramBridge {
    fn platform(&self) -> Platform {
        Platform::Telegram
    }

    async fn start(
        self,
        inbox: mpsc::Sender<IncomingMessage>,
        mut outbox: mpsc::Receiver<OutgoingMessage>,
    ) -> Result<(), BridgeError> {
        let client = reqwest::Client::new();

        // Verify token
        let me_url = self.api_url("getMe");
        let resp: TgResponse<TgUser> = client
            .get(&me_url)
            .send()
            .await
            .map_err(|e| BridgeError::ConnectionFailed(e.to_string()))?
            .json()
            .await
            .map_err(|e| BridgeError::ConnectionFailed(e.to_string()))?;

        if !resp.ok {
            return Err(BridgeError::AuthFailed("Invalid bot token".into()));
        }

        let bot_name = resp.result.map(|u| u.first_name).unwrap_or_default();
        info!("✅ Telegram connected as: {}", bot_name);

        // Spawn outbox handler
        let send_client = client.clone();
        let send_token = self.bot_token.clone();
        tokio::spawn(async move {
            while let Some(msg) = outbox.recv().await {
                let url = format!("https://api.telegram.org/bot{}/sendMessage", send_token);

                // Try Markdown first, fallback to plain text
                let body = serde_json::json!({
                    "chat_id": msg.chat_id.0,
                    "text": msg.text,
                    "parse_mode": "Markdown",
                });

                let result = send_client.post(&url).json(&body).send().await;

                match result {
                    Ok(resp) => {
                        let data: serde_json::Value = resp.json().await.unwrap_or_default();
                        if data["ok"].as_bool() != Some(true) {
                            // Markdown failed, retry without parse_mode
                            let plain_body = serde_json::json!({
                                "chat_id": msg.chat_id.0,
                                "text": msg.text,
                            });
                            if let Err(e) = send_client.post(&url).json(&plain_body).send().await {
                                error!("Telegram send error (plain): {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Telegram send error: {}", e);
                    }
                }
            }
        });

        // Poll loop
        let mut offset: Option<i64> = None;

        loop {
            let url = self.api_url("getUpdates");
            let mut params = serde_json::json!({
                "timeout": 30,
                "allowed_updates": ["message"],
            });
            if let Some(off) = offset {
                params["offset"] = serde_json::json!(off);
            }

            match client.post(&url).json(&params).send().await {
                Ok(resp) => {
                    if let Ok(updates) = resp.json::<TgResponse<Vec<TgUpdate>>>().await {
                        if let Some(items) = updates.result {
                            for update in items {
                                offset = Some(update.update_id + 1);

                                if let Some(msg) = update.message {
                                    let chat_id_str = msg.chat.id.to_string();

                                    if !self.allowed_chats.is_empty()
                                        && !self.allowed_chats.contains(&chat_id_str)
                                    {
                                        warn!("⚠️ Ignoring chat: {}", chat_id_str);
                                        continue;
                                    }

                                    let content = if let Some(text) = msg.text {
                                        MessageContent::Text { text }
                                    } else {
                                        MessageContent::Unknown {
                                            raw: serde_json::json!({"type": "unsupported"}),
                                        }
                                    };

                                    // Send typing indicator
                                    let typing_url = self.api_url("sendChatAction");
                                    let typing_body = serde_json::json!({
                                        "chat_id": chat_id_str,
                                        "action": "typing",
                                    });
                                    let _ =
                                        client.post(&typing_url).json(&typing_body).send().await;

                                    let incoming = IncomingMessage {
                                        id: MessageId(msg.message_id.to_string()),
                                        platform: Platform::Telegram,
                                        chat_id: ChatId(chat_id_str),
                                        sender_id: UserId(
                                            msg.from
                                                .as_ref()
                                                .map(|u| u.id.to_string())
                                                .unwrap_or_default(),
                                        ),
                                        sender_name: msg
                                            .from
                                            .as_ref()
                                            .map(|u| u.first_name.clone()),
                                        content,
                                        timestamp: chrono::Utc::now(),
                                        is_group: msg.chat.r#type != "private",
                                        metadata: serde_json::Value::Null,
                                    };

                                    if inbox.send(incoming).await.is_err() {
                                        error!("Inbox closed");
                                        return Err(BridgeError::SendFailed("Inbox closed".into()));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Telegram poll error: {}, retrying in 5s", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Telegram API types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
struct TgResponse<T> {
    ok: bool,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TgUpdate {
    update_id: i64,
    message: Option<TgMessage>,
}

#[derive(Debug, Deserialize)]
struct TgMessage {
    message_id: i64,
    from: Option<TgUser>,
    chat: TgChat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgUser {
    id: i64,
    first_name: String,
}

#[derive(Debug, Deserialize)]
struct TgChat {
    id: i64,
    r#type: String,
}
