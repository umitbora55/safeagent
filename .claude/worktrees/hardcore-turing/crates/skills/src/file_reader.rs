use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;
use std::path::PathBuf;

/// Read files from allowlisted directories only.
pub struct FileReaderSkill {
    allowed_dirs: Vec<PathBuf>,
    config: SkillConfig,
}

impl FileReaderSkill {
    pub fn new(allowed_dirs: Vec<PathBuf>) -> Self {
        Self {
            allowed_dirs,
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    /// Validate that a path is safe to read.
    fn validate_path(&self, input_path: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(input_path);

        // Block .. sequences before resolving
        let path_str = path.to_string_lossy();
        if path_str.contains("..") {
            return Err("Path traversal (..) is not allowed".into());
        }

        // Resolve to absolute path
        let resolved = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("Cannot resolve path: {}", e))?
                .join(&path)
        };

        let canonical = resolved
            .canonicalize()
            .map_err(|e| format!("Cannot resolve path '{}': {}", input_path, e))?;

        // Check if it's a symlink pointing outside allowed dirs
        if resolved != canonical {
            // Symlink detected — validate target
            let target_ok = self.allowed_dirs.iter().any(|dir| {
                if let Ok(dir_canonical) = dir.canonicalize() {
                    canonical.starts_with(&dir_canonical)
                } else {
                    false
                }
            });
            if !target_ok {
                return Err("Symlink target is outside allowed directories".into());
            }
        }

        // Check allowlist
        let in_allowlist = self.allowed_dirs.iter().any(|dir| {
            if let Ok(dir_canonical) = dir.canonicalize() {
                canonical.starts_with(&dir_canonical)
            } else {
                canonical.starts_with(dir)
            }
        });

        if !in_allowlist {
            return Err(format!(
                "Path '{}' is outside allowed directories. Allowed: {:?}",
                input_path, self.allowed_dirs
            ));
        }

        // Check it's a file, not a directory
        if canonical.is_dir() {
            return Err("Path is a directory, not a file".into());
        }

        Ok(canonical)
    }
}

#[async_trait]
impl Skill for FileReaderSkill {
    fn id(&self) -> &str {
        "file_reader"
    }
    fn name(&self) -> &str {
        "File Reader"
    }
    fn description(&self) -> &str {
        "Read a file from an allowlisted directory. Input: file path. Returns: file contents (text only)."
    }
    fn permissions(&self) -> Vec<Permission> {
        vec![Permission::read_fs()]
    }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("File reader skill is disabled".into());
        }

        let path_str = input.trim();
        if path_str.is_empty() {
            return SkillResult::err("Empty file path".into());
        }

        if self.allowed_dirs.is_empty() {
            return SkillResult::err(
                "No directories are allowlisted. Configure [skills.file_reader] allowed_dirs in safeagent.toml".into()
            );
        }

        let path = match self.validate_path(path_str) {
            Ok(p) => p,
            Err(e) => return SkillResult::err(e),
        };

        // Check file size
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => return SkillResult::err(format!("Cannot read file metadata: {}", e)),
        };

        if metadata.len() as usize > self.config.max_response_bytes {
            return SkillResult::err(format!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                self.config.max_response_bytes
            ));
        }

        // Read content
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                // Might be binary — try reading bytes and report
                return SkillResult::err(
                    "File is not valid UTF-8 text. Only text files are supported.".into(),
                );
            }
        };

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown");

        SkillResult::ok(content)
            .with_meta("path", &path.to_string_lossy())
            .with_meta("size_bytes", &metadata.len().to_string())
            .with_meta("extension", ext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "safeagent_filereader_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.txt");
        fs::write(&file, "hello world").unwrap();
        (dir, file)
    }

    #[test]
    fn test_read_allowed_file() {
        let (dir, file) = setup_test_dir();
        let skill = FileReaderSkill::new(vec![dir.clone()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(file.to_str().unwrap()));
        assert!(result.success);
        assert_eq!(result.output, "hello world");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_outside_allowlist() {
        let (dir, _file) = setup_test_dir();
        let skill = FileReaderSkill::new(vec![dir.join("nonexistent_subdir")]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("/etc/passwd"));
        assert!(!result.success);
        assert!(result.output.contains("outside allowed"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_path_traversal_blocked() {
        let (dir, _file) = setup_test_dir();
        let skill = FileReaderSkill::new(vec![dir.clone()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(&format!("{}/../../../etc/passwd", dir.display())));
        assert!(!result.success);
        assert!(result.output.contains("traversal"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_empty_path() {
        let skill = FileReaderSkill::new(vec![PathBuf::from("/tmp")]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_no_allowed_dirs() {
        let skill = FileReaderSkill::new(vec![]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("/tmp/test.txt"));
        assert!(!result.success);
        assert!(result.output.contains("No directories"));
    }

    #[test]
    fn test_disabled() {
        let config = SkillConfig {
            enabled: false,
            ..Default::default()
        };
        let skill = FileReaderSkill::new(vec![PathBuf::from("/tmp")]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("/tmp/test.txt"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_directory_rejected() {
        let (dir, _file) = setup_test_dir();
        let skill = FileReaderSkill::new(vec![dir.clone()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(dir.to_str().unwrap()));
        assert!(!result.success);
        assert!(result.output.contains("directory"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_too_large() {
        let (dir, file) = setup_test_dir();
        let config = SkillConfig {
            max_response_bytes: 5,
            ..Default::default()
        };
        let skill = FileReaderSkill::new(vec![dir.clone()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(file.to_str().unwrap()));
        assert!(!result.success);
        assert!(result.output.contains("too large"));
        fs::remove_dir_all(&dir).ok();
    }
}
