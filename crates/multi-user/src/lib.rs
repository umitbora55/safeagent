//! Multi-user support for SafeAgent.
//! Each user gets isolated vault, memory, and spending limits.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A user profile with isolated resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub display_name: String,
    pub role: UserRole,
    pub daily_spend_limit_microdollars: Option<u64>,
    pub monthly_spend_limit_microdollars: Option<u64>,
    pub allowed_skills: Vec<String>,
    pub created_at: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    Member,
    ReadOnly,
}

/// Team configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub shared_skills: Vec<String>,
    pub team_daily_limit_microdollars: Option<u64>,
    pub team_monthly_limit_microdollars: Option<u64>,
    pub members: Vec<String>, // user IDs
}

/// Manages multiple users and teams.
pub struct UserManager {
    data_dir: PathBuf,
    users: Mutex<HashMap<String, UserProfile>>,
    teams: Mutex<HashMap<String, Team>>,
}

impl UserManager {
    pub fn new(data_dir: PathBuf) -> anyhow::Result<Self> {
        let manager = Self {
            data_dir: data_dir.clone(),
            users: Mutex::new(HashMap::new()),
            teams: Mutex::new(HashMap::new()),
        };

        // Load existing users
        let users_file = data_dir.join("users.json");
        if users_file.exists() {
            let content = std::fs::read_to_string(&users_file)?;
            let users: HashMap<String, UserProfile> = serde_json::from_str(&content)?;
            *manager.users.lock().unwrap() = users;
        }

        let teams_file = data_dir.join("teams.json");
        if teams_file.exists() {
            let content = std::fs::read_to_string(&teams_file)?;
            let teams: HashMap<String, Team> = serde_json::from_str(&content)?;
            *manager.teams.lock().unwrap() = teams;
        }

        Ok(manager)
    }

    /// Get the data directory for a specific user (isolated storage).
    pub fn user_data_dir(&self, user_id: &str) -> PathBuf {
        self.data_dir.join("users").join(user_id)
    }

    /// Create a new user.
    pub fn create_user(&self, display_name: &str, role: UserRole) -> anyhow::Result<UserProfile> {
        let id = uuid::Uuid::new_v4().to_string();
        let user = UserProfile {
            id: id.clone(),
            display_name: display_name.to_string(),
            role,
            daily_spend_limit_microdollars: None,
            monthly_spend_limit_microdollars: None,
            allowed_skills: vec![],
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
        };

        // Create user data directory
        let user_dir = self.user_data_dir(&id);
        std::fs::create_dir_all(&user_dir)?;

        let mut users = self.users.lock().unwrap();
        users.insert(id.clone(), user.clone());
        self.save_users(&users)?;

        Ok(user)
    }

    /// Get a user by ID.
    pub fn get_user(&self, user_id: &str) -> Option<UserProfile> {
        self.users.lock().unwrap().get(user_id).cloned()
    }

    /// List all users.
    pub fn list_users(&self) -> Vec<UserProfile> {
        self.users.lock().unwrap().values().cloned().collect()
    }

    /// Update a user's spending limits.
    pub fn set_user_limits(&self, user_id: &str, daily: Option<u64>, monthly: Option<u64>) -> anyhow::Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(user_id) {
            user.daily_spend_limit_microdollars = daily;
            user.monthly_spend_limit_microdollars = monthly;
            self.save_users(&users)?;
            Ok(())
        } else {
            anyhow::bail!("User not found: {}", user_id)
        }
    }

    /// Set allowed skills for a user.
    pub fn set_user_skills(&self, user_id: &str, skills: Vec<String>) -> anyhow::Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(user_id) {
            user.allowed_skills = skills;
            self.save_users(&users)?;
            Ok(())
        } else {
            anyhow::bail!("User not found: {}", user_id)
        }
    }

    /// Deactivate a user.
    pub fn deactivate_user(&self, user_id: &str) -> anyhow::Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(user_id) {
            user.active = false;
            self.save_users(&users)?;
            Ok(())
        } else {
            anyhow::bail!("User not found: {}", user_id)
        }
    }

    /// Check if a user can use a specific skill.
    pub fn can_use_skill(&self, user_id: &str, skill_id: &str) -> bool {
        let users = self.users.lock().unwrap();
        if let Some(user) = users.get(user_id) {
            if !user.active { return false; }
            if user.role == UserRole::Admin { return true; }
            if user.role == UserRole::ReadOnly { return skill_id.starts_with("read") || skill_id.contains("_reader"); }
            user.allowed_skills.is_empty() || user.allowed_skills.contains(&skill_id.to_string())
        } else {
            false
        }
    }

    // ─── Teams ──────────────────────────────────

    /// Create a team.
    pub fn create_team(&self, name: &str) -> anyhow::Result<Team> {
        let id = uuid::Uuid::new_v4().to_string();
        let team = Team {
            id: id.clone(),
            name: name.to_string(),
            shared_skills: vec![],
            team_daily_limit_microdollars: None,
            team_monthly_limit_microdollars: None,
            members: vec![],
        };

        let mut teams = self.teams.lock().unwrap();
        teams.insert(id, team.clone());
        self.save_teams(&teams)?;

        Ok(team)
    }

    /// Add a user to a team.
    pub fn add_to_team(&self, team_id: &str, user_id: &str) -> anyhow::Result<()> {
        let mut teams = self.teams.lock().unwrap();
        if let Some(team) = teams.get_mut(team_id) {
            if !team.members.contains(&user_id.to_string()) {
                team.members.push(user_id.to_string());
            }
            self.save_teams(&teams)?;
            Ok(())
        } else {
            anyhow::bail!("Team not found: {}", team_id)
        }
    }

    /// List all teams.
    pub fn list_teams(&self) -> Vec<Team> {
        self.teams.lock().unwrap().values().cloned().collect()
    }

    // ─── Persistence ────────────────────────────

    fn save_users(&self, users: &HashMap<String, UserProfile>) -> anyhow::Result<()> {
        let path = self.data_dir.join("users.json");
        let content = serde_json::to_string_pretty(users)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    fn save_teams(&self, teams: &HashMap<String, Team>) -> anyhow::Result<()> {
        let path = self.data_dir.join("teams.json");
        let content = serde_json::to_string_pretty(teams)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_manager() -> UserManager {
        let dir = std::env::temp_dir().join(format!("safeagent_multiuser_test_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        UserManager::new(dir).unwrap()
    }

    #[test]
    fn test_create_user() {
        let mgr = temp_manager();
        let user = mgr.create_user("Alice", UserRole::Admin).unwrap();
        assert_eq!(user.display_name, "Alice");
        assert_eq!(user.role, UserRole::Admin);
        assert!(user.active);
    }

    #[test]
    fn test_get_user() {
        let mgr = temp_manager();
        let user = mgr.create_user("Bob", UserRole::Member).unwrap();
        let fetched = mgr.get_user(&user.id).unwrap();
        assert_eq!(fetched.display_name, "Bob");
    }

    #[test]
    fn test_list_users() {
        let mgr = temp_manager();
        mgr.create_user("A", UserRole::Admin).unwrap();
        mgr.create_user("B", UserRole::Member).unwrap();
        assert_eq!(mgr.list_users().len(), 2);
    }

    #[test]
    fn test_set_limits() {
        let mgr = temp_manager();
        let user = mgr.create_user("C", UserRole::Member).unwrap();
        mgr.set_user_limits(&user.id, Some(5_000_000), Some(50_000_000)).unwrap();
        let fetched = mgr.get_user(&user.id).unwrap();
        assert_eq!(fetched.daily_spend_limit_microdollars, Some(5_000_000));
    }

    #[test]
    fn test_deactivate() {
        let mgr = temp_manager();
        let user = mgr.create_user("D", UserRole::Member).unwrap();
        mgr.deactivate_user(&user.id).unwrap();
        let fetched = mgr.get_user(&user.id).unwrap();
        assert!(!fetched.active);
    }

    #[test]
    fn test_skill_access_admin() {
        let mgr = temp_manager();
        let user = mgr.create_user("Admin", UserRole::Admin).unwrap();
        assert!(mgr.can_use_skill(&user.id, "web_search"));
        assert!(mgr.can_use_skill(&user.id, "email_sender"));
    }

    #[test]
    fn test_skill_access_readonly() {
        let mgr = temp_manager();
        let user = mgr.create_user("RO", UserRole::ReadOnly).unwrap();
        assert!(mgr.can_use_skill(&user.id, "file_reader"));
        assert!(mgr.can_use_skill(&user.id, "calendar_reader"));
        assert!(!mgr.can_use_skill(&user.id, "email_sender"));
    }

    #[test]
    fn test_skill_access_member_allowlist() {
        let mgr = temp_manager();
        let user = mgr.create_user("M", UserRole::Member).unwrap();
        mgr.set_user_skills(&user.id, vec!["web_search".into()]).unwrap();
        assert!(mgr.can_use_skill(&user.id, "web_search"));
        assert!(!mgr.can_use_skill(&user.id, "email_sender"));
    }

    #[test]
    fn test_inactive_user_denied() {
        let mgr = temp_manager();
        let user = mgr.create_user("X", UserRole::Admin).unwrap();
        mgr.deactivate_user(&user.id).unwrap();
        assert!(!mgr.can_use_skill(&user.id, "web_search"));
    }

    #[test]
    fn test_create_team() {
        let mgr = temp_manager();
        let team = mgr.create_team("Engineering").unwrap();
        assert_eq!(team.name, "Engineering");
    }

    #[test]
    fn test_add_to_team() {
        let mgr = temp_manager();
        let user = mgr.create_user("E", UserRole::Member).unwrap();
        let team = mgr.create_team("Eng").unwrap();
        mgr.add_to_team(&team.id, &user.id).unwrap();
        let teams = mgr.list_teams();
        assert!(teams[0].members.contains(&user.id));
    }
}
