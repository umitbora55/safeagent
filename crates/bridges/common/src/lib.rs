use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Newtype wrappers — derleme zamanında tip güvenliği
//  chat_id ile sender_id'yi karıştırmak artık imkansız
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChatId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ChatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Platform & Status
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Telegram,
    WhatsApp,
    Discord,
    Signal,
    Cli,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::Telegram => write!(f, "telegram"),
            Platform::WhatsApp => write!(f, "whatsapp"),
            Platform::Discord => write!(f, "discord"),
            Platform::Signal => write!(f, "signal"),
            Platform::Cli => write!(f, "cli"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Failed { reason: String },
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Messages
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub id: MessageId,
    pub platform: Platform,
    pub chat_id: ChatId,
    pub sender_id: UserId,
    pub sender_name: Option<String>,
    pub content: MessageContent,
    pub timestamp: DateTime<Utc>,
    pub is_group: bool,
    /// Platform-specific extra data (thread_id, reply_markup, etc.)
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContent {
    Text { text: String },
    Voice { audio_url: String, duration_secs: Option<u32> },
    Image { image_url: String, caption: Option<String> },
    File { file_url: String, filename: String },
    /// Platform-specific content not yet modeled
    Unknown { raw: serde_json::Value },
}

impl MessageContent {
    /// Extract text for LLM processing (language-neutral markers)
    pub fn as_text(&self) -> String {
        match self {
            MessageContent::Text { text } => text.clone(),
            MessageContent::Voice { duration_secs, .. } => {
                format!("[voice_message:{}s]", duration_secs.unwrap_or(0))
            }
            MessageContent::Image { caption, .. } => {
                caption.clone().unwrap_or_else(|| "[image]".to_string())
            }
            MessageContent::File { filename, .. } => format!("[file:{}]", filename),
            MessageContent::Unknown { .. } => "[unsupported_content]".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingMessage {
    pub platform: Platform,
    pub chat_id: ChatId,
    pub text: String,
    pub reply_to: Option<MessageId>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Bridge Trait — ownership-friendly tasarım
//
//  Bridge bir "task" olarak spawn edilir.
//  inbox: gelen mesajları gateway'e iletir
//  outbox: gateway'den gelen yanıtları platforma gönderir
//  İç state tamamen bridge'e ait, borrow checker sorunu yok.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Bridge shut down")]
    Shutdown,
}

#[async_trait]
pub trait Bridge: Send + Sync + 'static {
    fn platform(&self) -> Platform;

    /// Bridge'i başlat. Gelen mesajları inbox'a gönder,
    /// outbox'tan gelen yanıtları platforma ilet.
    /// Bu fonksiyon bridge kapanana kadar bloklar (task olarak spawn edilir).
    async fn start(
        self,
        inbox: tokio::sync::mpsc::Sender<IncomingMessage>,
        outbox: tokio::sync::mpsc::Receiver<OutgoingMessage>,
    ) -> Result<(), BridgeError>;
}
