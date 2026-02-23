use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;
use std::path::PathBuf;

/// Write files to allowlisted directories only.
/// Default mode: create-only (no overwrite, no delete).
pub struct FileWriterSkill {
    allowed_dirs: Vec<PathBuf>,
    allow_overwrite: bool,
    config: SkillConfig,
}

impl FileWriterSkill {
    pub fn new(allowed_dirs: Vec<PathBuf>) -> Self {
        Self {
            allowed_dirs,
            allow_overwrite: false, // deny-all default
            config: SkillConfig { enabled: false, ..Default::default() }, // disabled by default
        }
    }

    pub fn with_overwrite(mut self, allow: bool) -> Self {
        self.allow_overwrite = allow;
        self
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    fn validate_path(&self, input_path: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(input_path);

        if path.to_string_lossy().contains("..") {
            return Err("Path traversal (..) is not allowed".into());
        }

        let resolved = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("Cannot resolve path: {}", e))?
                .join(&path)
        };

        // For new files, parent must exist and be in allowlist
        let parent = resolved.parent()
            .ok_or("Invalid path: no parent directory")?;

        let parent_canonical = parent.canonicalize()
            .map_err(|e| format!("Parent directory does not exist: {}", e))?;

        let in_allowlist = self.allowed_dirs.iter().any(|dir| {
            if let Ok(dir_canonical) = dir.canonicalize() {
                parent_canonical.starts_with(&dir_canonical)
            } else {
                parent_canonical.starts_with(dir)
            }
        });

        if !in_allowlist {
            return Err(format!(
                "Path '{}' is outside allowed directories. Allowed: {:?}",
                input_path, self.allowed_dirs
            ));
        }

        Ok(resolved)
    }
}

#[async_trait]
impl Skill for FileWriterSkill {
    fn id(&self) -> &str { "file_writer" }
    fn name(&self) -> &str { "File Writer" }
    fn description(&self) -> &str {
        "Write content to a file in an allowlisted directory. Input format: 'path/to/file.txt\\n---\\ncontent here'. First line is the path, separator is ---, rest is content."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::write_fs()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "File writer skill is disabled by default. Enable in safeagent.toml:\n\
                 [skills.file_writer]\n\
                 enabled = true\n\
                 allowed_dirs = [\"/path/to/dir\"]".into()
            );
        }

        if self.allowed_dirs.is_empty() {
            return SkillResult::err(
                "No directories allowlisted. Configure [skills.file_writer] allowed_dirs in safeagent.toml".into()
            );
        }

        // Parse input: path\n---\ncontent
        let parts: Vec<&str> = input.splitn(2, "\n---\n").collect();
        if parts.len() != 2 {
            return SkillResult::err(
                "Invalid format. Expected: path/to/file.txt\\n---\\ncontent here".into()
            );
        }

        let path_str = parts[0].trim();
        let content = parts[1];

        if path_str.is_empty() {
            return SkillResult::err("Empty file path".into());
        }

        let path = match self.validate_path(path_str) {
            Ok(p) => p,
            Err(e) => return SkillResult::err(e),
        };

        // Check overwrite
        if path.exists() && !self.allow_overwrite {
            return SkillResult::err(format!(
                "File '{}' already exists. Overwrite is disabled (create-only mode).\n\
                 Enable with: allow_overwrite = true in config.",
                path_str
            ));
        }

        // Check content size
        if content.len() > self.config.max_response_bytes {
            return SkillResult::err(format!(
                "Content too large: {} bytes (max: {} bytes)",
                content.len(), self.config.max_response_bytes
            ));
        }

        // Write file
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return SkillResult::err(format!("Cannot create directory: {}", e));
            }
        }

        match std::fs::write(&path, content) {
            Ok(_) => {
                let action = if path.exists() { "overwritten" } else { "created" };
                SkillResult::ok(format!("✅ File {} ({} bytes)", action, content.len()))
                    .with_meta("path", &path.to_string_lossy())
                    .with_meta("size_bytes", &content.len().to_string())
            }
            Err(e) => SkillResult::err(format!("Failed to write file: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("safeagent_filewriter_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_disabled_by_default() {
        let skill = FileWriterSkill::new(vec![PathBuf::from("/tmp")]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("test.txt\n---\nhello"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_create_file() {
        let dir = setup_test_dir();
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![dir.clone()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let input = format!("{}/new_file.txt\n---\nhello world", dir.display());
        let result = rt.block_on(skill.execute(&input));
        assert!(result.success, "Error: {}", result.output);

        let content = fs::read_to_string(dir.join("new_file.txt")).unwrap();
        assert_eq!(content, "hello world");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_no_overwrite_by_default() {
        let dir = setup_test_dir();
        let existing = dir.join("existing.txt");
        fs::write(&existing, "old content").unwrap();

        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![dir.clone()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let input = format!("{}/existing.txt\n---\nnew content", dir.display());
        let result = rt.block_on(skill.execute(&input));
        assert!(!result.success);
        assert!(result.output.contains("already exists"));

        // Content unchanged
        let content = fs::read_to_string(&existing).unwrap();
        assert_eq!(content, "old content");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_overwrite_enabled() {
        let dir = setup_test_dir();
        let existing = dir.join("overwrite.txt");
        fs::write(&existing, "old").unwrap();

        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![dir.clone()])
            .with_overwrite(true)
            .with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let input = format!("{}/overwrite.txt\n---\nnew", dir.display());
        let result = rt.block_on(skill.execute(&input));
        assert!(result.success);

        let content = fs::read_to_string(&existing).unwrap();
        assert_eq!(content, "new");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_outside_allowlist() {
        let dir = setup_test_dir();
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![dir.clone()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(skill.execute("/etc/test.txt\n---\nhello"));
        assert!(!result.success);
        assert!(result.output.contains("outside allowed"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_path_traversal() {
        let dir = setup_test_dir();
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![dir.clone()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let input = format!("{}/../../../etc/passwd\n---\nhacked", dir.display());
        let result = rt.block_on(skill.execute(&input));
        assert!(!result.success);
        assert!(result.output.contains("traversal"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_invalid_format() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![PathBuf::from("/tmp")]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(skill.execute("just some text without separator"));
        assert!(!result.success);
        assert!(result.output.contains("Invalid format"));
    }

    #[test]
    fn test_no_allowed_dirs() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = FileWriterSkill::new(vec![]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(skill.execute("/tmp/test.txt\n---\nhello"));
        assert!(!result.success);
        assert!(result.output.contains("No directories"));
    }
}
