use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;
use std::path::PathBuf;

/// Image upload and processing skill.
/// Supports: info, resize metadata, format detection.
/// Vision API integration for image understanding.
pub struct ImageProcessorSkill {
    client: reqwest::Client,
    openai_api_key: Option<String>,
    allowed_dirs: Vec<PathBuf>,
    max_file_size: usize,
    config: SkillConfig,
}

const ALLOWED_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"];
#[allow(dead_code)]
const ALLOWED_MIME_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/svg+xml",
];

impl ImageProcessorSkill {
    pub fn new(allowed_dirs: Vec<PathBuf>, openai_api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            openai_api_key,
            allowed_dirs,
            max_file_size: 20 * 1024 * 1024, // 20MB
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    fn validate_image_path(&self, path_str: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(path_str);

        if path.to_string_lossy().contains("..") {
            return Err("Path traversal (..) not allowed".into());
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            return Err(format!(
                "Unsupported image format '.{}'. Allowed: {:?}",
                ext, ALLOWED_EXTENSIONS
            ));
        }

        let canonical = path
            .canonicalize()
            .map_err(|e| format!("Cannot resolve path: {}", e))?;

        if !self.allowed_dirs.is_empty() {
            let in_allowlist = self.allowed_dirs.iter().any(|dir| {
                if let Ok(dir_c) = dir.canonicalize() {
                    canonical.starts_with(&dir_c)
                } else {
                    canonical.starts_with(dir)
                }
            });
            if !in_allowlist {
                return Err(format!(
                    "Path outside allowed directories: {:?}",
                    self.allowed_dirs
                ));
            }
        }

        Ok(canonical)
    }
}

/// Supported image actions
enum ImageAction {
    Info { path: String },
    Describe { path: String },
    DetectFormat { path: String },
}

fn parse_image_input(input: &str) -> Result<ImageAction, String> {
    let trimmed = input.trim();
    let lower = trimmed.to_lowercase();

    if lower.starts_with("info ") {
        Ok(ImageAction::Info {
            path: trimmed[5..].trim().into(),
        })
    } else if lower.starts_with("describe ") {
        Ok(ImageAction::Describe {
            path: trimmed[9..].trim().into(),
        })
    } else if lower.starts_with("format ") {
        Ok(ImageAction::DetectFormat {
            path: trimmed[7..].trim().into(),
        })
    } else {
        // Default: info
        Ok(ImageAction::Info {
            path: trimmed.into(),
        })
    }
}

fn detect_format(data: &[u8]) -> &'static str {
    if data.len() < 4 {
        return "unknown";
    }
    match &data[..4] {
        [0x89, 0x50, 0x4E, 0x47] => "PNG",
        [0xFF, 0xD8, 0xFF, _] => "JPEG",
        [0x47, 0x49, 0x46, 0x38] => "GIF",
        [0x52, 0x49, 0x46, 0x46] => "WebP",
        [0x42, 0x4D, _, _] => "BMP",
        _ => {
            if data.starts_with(b"<svg") || data.starts_with(b"<?xml") {
                "SVG"
            } else {
                "unknown"
            }
        }
    }
}

fn image_dimensions_hint(data: &[u8], format: &str) -> Option<(u32, u32)> {
    match format {
        "PNG" if data.len() >= 24 => {
            let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
            Some((w, h))
        }
        _ => None,
    }
}

#[async_trait]
impl Skill for ImageProcessorSkill {
    fn id(&self) -> &str {
        "image_processor"
    }
    fn name(&self) -> &str {
        "Image Processor"
    }
    fn description(&self) -> &str {
        "Process images. Actions: info <path>, describe <path> (uses Vision API), format <path>. Supports PNG, JPEG, GIF, WebP, BMP, SVG."
    }
    fn permissions(&self) -> Vec<Permission> {
        vec![Permission::read_fs(), Permission::read_web()]
    }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("Image processor is disabled".into());
        }

        let action = match parse_image_input(input) {
            Ok(a) => a,
            Err(e) => return SkillResult::err(e),
        };

        match action {
            ImageAction::Info { path } | ImageAction::DetectFormat { path } => {
                let resolved = match self.validate_image_path(&path) {
                    Ok(p) => p,
                    Err(e) => return SkillResult::err(e),
                };

                let metadata = match std::fs::metadata(&resolved) {
                    Ok(m) => m,
                    Err(e) => return SkillResult::err(format!("Cannot read file: {}", e)),
                };

                if metadata.len() as usize > self.max_file_size {
                    return SkillResult::err(format!(
                        "File too large: {} bytes (max: {})",
                        metadata.len(),
                        self.max_file_size
                    ));
                }

                let data = match std::fs::read(&resolved) {
                    Ok(d) => d,
                    Err(e) => return SkillResult::err(format!("Cannot read file: {}", e)),
                };

                let format = detect_format(&data);
                let dims = image_dimensions_hint(&data, format);

                let mut info = format!(
                    "🖼️ Image Info\n  Path: {}\n  Format: {}\n  Size: {} bytes",
                    resolved.display(),
                    format,
                    metadata.len()
                );

                if let Some((w, h)) = dims {
                    info.push_str(&format!("\n  Dimensions: {}x{}", w, h));
                }

                let ext = resolved.extension().and_then(|e| e.to_str()).unwrap_or("?");
                SkillResult::ok(info)
                    .with_meta("format", format)
                    .with_meta("size_bytes", &metadata.len().to_string())
                    .with_meta("extension", ext)
            }

            ImageAction::Describe { path } => {
                let api_key = match &self.openai_api_key {
                    Some(k) => k.clone(),
                    None => {
                        return SkillResult::err("OpenAI API key not configured for Vision".into())
                    }
                };

                let resolved = match self.validate_image_path(&path) {
                    Ok(p) => p,
                    Err(e) => return SkillResult::err(e),
                };

                let data = match std::fs::read(&resolved) {
                    Ok(d) => d,
                    Err(e) => return SkillResult::err(format!("Cannot read file: {}", e)),
                };

                if data.len() > self.max_file_size {
                    return SkillResult::err("File too large for Vision API".into());
                }

                let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
                let format = detect_format(&data);
                let mime = match format {
                    "PNG" => "image/png",
                    "JPEG" => "image/jpeg",
                    "GIF" => "image/gif",
                    "WebP" => "image/webp",
                    _ => "image/png",
                };

                let body = serde_json::json!({
                    "model": "gpt-4o-mini",
                    "messages": [{
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image in detail."},
                            {"type": "image_url", "image_url": {"url": format!("data:{};base64,{}", mime, b64)}}
                        ]
                    }],
                    "max_tokens": 500
                });

                let resp = match self
                    .client
                    .post("https://api.openai.com/v1/chat/completions")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return SkillResult::err(format!("Vision API request failed: {}", e)),
                };

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return SkillResult::err(format!("Vision API error {}: {}", status, body));
                }

                let data: serde_json::Value = match resp.json().await {
                    Ok(d) => d,
                    Err(e) => {
                        return SkillResult::err(format!("Failed to parse Vision response: {}", e))
                    }
                };

                let description = data["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("No description generated");

                SkillResult::ok(format!("🖼️ Image Description:\n{}", description))
                    .with_meta("path", &path)
                    .with_meta("model", "gpt-4o-mini")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_png() {
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_format(&png_header), "PNG");
    }

    #[test]
    fn test_detect_format_jpeg() {
        let jpg_header = [0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(detect_format(&jpg_header), "JPEG");
    }

    #[test]
    fn test_detect_format_gif() {
        let gif_header = [0x47, 0x49, 0x46, 0x38];
        assert_eq!(detect_format(&gif_header), "GIF");
    }

    #[test]
    fn test_detect_format_unknown() {
        assert_eq!(detect_format(&[0x00, 0x01, 0x02, 0x03]), "unknown");
        assert_eq!(detect_format(&[0x00]), "unknown");
    }

    #[test]
    fn test_disallowed_extension() {
        let skill = ImageProcessorSkill::new(vec![], None);
        let result = skill.validate_image_path("/tmp/test.exe");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported"));
    }

    #[test]
    fn test_path_traversal() {
        let skill = ImageProcessorSkill::new(vec![PathBuf::from("/tmp")], None);
        let result = skill.validate_image_path("/tmp/../etc/passwd.png");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("traversal"));
    }

    #[test]
    fn test_disabled() {
        let config = SkillConfig {
            enabled: false,
            ..Default::default()
        };
        let skill = ImageProcessorSkill::new(vec![], None).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("info /tmp/test.png"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_no_vision_key() {
        let config = SkillConfig {
            enabled: true,
            ..Default::default()
        };
        let skill = ImageProcessorSkill::new(vec![], None).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("describe /tmp/test.png"));
        assert!(!result.success);
        assert!(result.output.contains("not configured"));
    }

    #[test]
    fn test_png_dimensions() {
        // Minimal PNG IHDR
        let mut data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&100u32.to_be_bytes()); // width
        data.extend_from_slice(&200u32.to_be_bytes()); // height
        let dims = image_dimensions_hint(&data, "PNG");
        assert_eq!(dims, Some((100, 200)));
    }
}
