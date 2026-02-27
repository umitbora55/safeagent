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
    Text {
        text: String,
    },
    Voice {
        audio_url: String,
        duration_secs: Option<u32>,
    },
    Image {
        image_url: String,
        caption: Option<String>,
    },
    File {
        file_url: String,
        filename: String,
    },
    /// Platform-specific content not yet modeled
    Unknown {
        raw: serde_json::Value,
    },
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

#[derive(Debug, Clone)]
pub struct BridgeCapabilities {
    pub max_message_length: usize,
    pub supports_threads: bool,
    pub supports_reactions: bool,
    pub supports_attachments: bool,
    pub supports_typing_indicator: bool,
}

impl Default for BridgeCapabilities {
    fn default() -> Self {
        Self {
            max_message_length: 4096,
            supports_threads: false,
            supports_reactions: false,
            supports_attachments: false,
            supports_typing_indicator: false,
        }
    }
}

/// Split a message into chunks that fit within the platform's max message length.
/// Splits at newline boundaries when possible, falls back to character boundary.
pub fn chunk_message(text: &str, max_len: usize) -> Vec<String> {
    if max_len == 0 {
        return vec![text.to_string()];
    }
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut remaining = text;

    while !remaining.is_empty() {
        if remaining.len() <= max_len {
            chunks.push(remaining.to_string());
            break;
        }

        // Try to split at last newline within max_len
        let slice = &remaining[..max_len];
        let split_at = slice
            .rfind('\n')
            .map(|i| i + 1)
            .or_else(|| slice.rfind(' ').map(|i| i + 1))
            .unwrap_or(max_len);

        chunks.push(remaining[..split_at].to_string());
        remaining = &remaining[split_at..];
    }

    chunks
}

#[async_trait]
pub trait Bridge: Send + Sync + 'static {
    fn platform(&self) -> Platform;

    fn capabilities(&self) -> BridgeCapabilities {
        BridgeCapabilities::default()
    }

    /// Bridge'i başlat. Gelen mesajları inbox'a gönder,
    /// outbox'tan gelen yanıtları platforma ilet.
    /// Bu fonksiyon bridge kapanana kadar bloklar (task olarak spawn edilir).
    async fn start(
        self,
        inbox: tokio::sync::mpsc::Sender<IncomingMessage>,
        outbox: tokio::sync::mpsc::Receiver<OutgoingMessage>,
    ) -> Result<(), BridgeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_short_message() {
        let chunks = chunk_message("hello", 100);
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn test_chunk_exact_limit() {
        let msg = "a".repeat(100);
        let chunks = chunk_message(&msg, 100);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_chunk_splits_at_newline() {
        let msg = "line1\nline2\nline3\nline4";
        let chunks = chunk_message(msg, 12);
        assert!(chunks.len() >= 2);
        for c in &chunks {
            assert!(c.len() <= 12);
        }
    }

    #[test]
    fn test_chunk_splits_at_space() {
        let msg = "word1 word2 word3 word4 word5";
        let chunks = chunk_message(msg, 12);
        assert!(chunks.len() >= 2);
        for c in &chunks {
            assert!(c.len() <= 12);
        }
    }

    #[test]
    fn test_chunk_no_delimiter() {
        let msg = "a".repeat(250);
        let chunks = chunk_message(&msg, 100);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 100);
        assert_eq!(chunks[1].len(), 100);
        assert_eq!(chunks[2].len(), 50);
    }

    #[test]
    fn test_chunk_empty() {
        let chunks = chunk_message("", 100);
        assert_eq!(chunks, vec![""]);
    }

    #[test]
    fn test_capabilities_default() {
        let caps = BridgeCapabilities::default();
        assert_eq!(caps.max_message_length, 4096);
        assert!(!caps.supports_threads);
    }
}
