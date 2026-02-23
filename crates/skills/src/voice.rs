use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;

/// Speech-to-text using OpenAI Whisper API.
pub struct WhisperSTT {
    client: reqwest::Client,
    api_key: Option<String>,
    config: SkillConfig,
}

impl WhisperSTT {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            api_key,
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    /// Transcribe audio bytes to text.
    pub async fn transcribe(&self, audio_data: &[u8], filename: &str) -> Result<String, String> {
        let api_key = self.api_key.as_ref()
            .ok_or("OpenAI API key not configured for Whisper STT")?;

        let part = reqwest::multipart::Part::bytes(audio_data.to_vec())
            .file_name(filename.to_string())
            .mime_str("audio/ogg")
            .map_err(|e| format!("Failed to create multipart: {}", e))?;

        let form = reqwest::multipart::Form::new()
            .text("model", "whisper-1")
            .text("response_format", "text")
            .part("file", part);

        let resp = self.client
            .post("https://api.openai.com/v1/audio/transcriptions")
            .header("Authorization", format!("Bearer {}", api_key))
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Whisper API request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Whisper API error {}: {}", status, body));
        }

        let text = resp.text().await
            .map_err(|e| format!("Failed to read Whisper response: {}", e))?;

        Ok(text.trim().to_string())
    }
}

#[async_trait]
impl Skill for WhisperSTT {
    fn id(&self) -> &str { "whisper_stt" }
    fn name(&self) -> &str { "Whisper Speech-to-Text" }
    fn description(&self) -> &str {
        "Transcribe audio to text using OpenAI Whisper. Input: path to audio file."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::read_web()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("Whisper STT is disabled".into());
        }

        let path = input.trim();
        if path.is_empty() {
            return SkillResult::err("Empty audio file path".into());
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => return SkillResult::err(format!("Failed to read audio file: {}", e)),
        };

        match self.transcribe(&data, path).await {
            Ok(text) => SkillResult::ok(text).with_meta("source", path),
            Err(e) => SkillResult::err(e),
        }
    }
}

/// Text-to-speech using OpenAI TTS API.
pub struct OpenAITTS {
    client: reqwest::Client,
    api_key: Option<String>,
    voice: String,
}

impl OpenAITTS {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            api_key,
            voice: "alloy".into(),
        }
    }

    pub fn with_voice(mut self, voice: &str) -> Self {
        self.voice = voice.into();
        self
    }

    /// Convert text to speech, return audio bytes (mp3).
    pub async fn synthesize(&self, text: &str) -> Result<Vec<u8>, String> {
        let api_key = self.api_key.as_ref()
            .ok_or("OpenAI API key not configured for TTS")?;

        let body = serde_json::json!({
            "model": "tts-1",
            "input": text,
            "voice": self.voice,
            "response_format": "mp3"
        });

        let resp = self.client
            .post("https://api.openai.com/v1/audio/speech")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("TTS API request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TTS API error {}: {}", status, body));
        }

        let bytes = resp.bytes().await
            .map_err(|e| format!("Failed to read TTS response: {}", e))?;

        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whisper_no_api_key() {
        let stt = WhisperSTT::new(None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(stt.transcribe(b"fake audio", "test.ogg"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not configured"));
    }

    #[test]
    fn test_tts_no_api_key() {
        let tts = OpenAITTS::new(None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(tts.synthesize("hello"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not configured"));
    }

    #[test]
    fn test_whisper_disabled() {
        let config = SkillConfig { enabled: false, ..Default::default() };
        let stt = WhisperSTT::new(Some("key".into())).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(stt.execute("test.ogg"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_whisper_empty_path() {
        let stt = WhisperSTT::new(Some("key".into()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(stt.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_tts_voice_config() {
        let tts = OpenAITTS::new(None).with_voice("nova");
        assert_eq!(tts.voice, "nova");
    }
}
