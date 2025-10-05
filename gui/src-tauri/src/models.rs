use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export the models from the server to maintain consistency
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub domain: String,
    pub os: String,
    pub arch: String,
    pub process_id: u32,
    pub process_name: String,
    pub integrity_level: String,
    pub remote_ip: String,
    pub internal_ip: String,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub sleep_interval: u64,
    pub jitter: f32,
    pub is_active: bool,
    pub encryption_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Task {
    pub id: String,
    pub agent_id: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub task_type: TaskType,
    pub created_at: DateTime<Utc>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub status: TaskStatus,
    pub priority: TaskPriority,
    pub timeout: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    Shell,
    PowerShell,
    Download,
    Upload,
    Screenshot,
    Keylog,
    ProcessList,
    SystemInfo,
    NetworkInfo,
    FileList,
    Registry,
    Sleep,
    Jitter,
    Exit,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
    Timeout,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TaskResult {
    pub id: String,
    pub task_id: String,
    pub agent_id: String,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub execution_time: f64,
    pub completed_at: DateTime<Utc>,
    pub file_data: Option<Vec<u8>>,
}

// GUI-specific models
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConnection {
    pub url: String,
    pub is_connected: bool,
    pub last_connected: Option<DateTime<Utc>>,
    pub auth_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GuiSettings {
    pub server_url: String,
    pub auto_refresh: bool,
    pub refresh_interval: u64, // seconds
    pub theme: String,
    pub log_level: String,
    pub window_state: Option<WindowState>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WindowState {
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub maximized: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommandTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub task_type: TaskType,
    pub category: String,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            auto_refresh: true,
            refresh_interval: 30,
            theme: "dark".to_string(),
            log_level: "info".to_string(),
            window_state: None,
        }
    }
}

impl Default for ServerConnection {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".to_string(),
            is_connected: false,
            last_connected: None,
            auth_token: None,
        }
    }
}

// Utility functions for display
impl Agent {
    pub fn get_status_display(&self) -> String {
        if self.is_active {
            let now = Utc::now();
            let duration = now.signed_duration_since(self.last_seen);

            if duration.num_seconds() < 60 {
                "Active".to_string()
            } else if duration.num_seconds() < 300 {
                "Idle".to_string()
            } else {
                "Stale".to_string()
            }
        } else {
            "Inactive".to_string()
        }
    }

    pub fn get_last_seen_display(&self) -> String {
        self.last_seen.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    pub fn get_uptime_display(&self) -> String {
        let duration = self.last_seen.signed_duration_since(self.first_seen);

        if duration.num_days() > 0 {
            format!("{}d {}h", duration.num_days(), duration.num_hours() % 24)
        } else if duration.num_hours() > 0 {
            format!("{}h {}m", duration.num_hours(), duration.num_minutes() % 60)
        } else {
            format!(
                "{}m {}s",
                duration.num_minutes(),
                duration.num_seconds() % 60
            )
        }
    }
}

impl Task {
    pub fn get_status_display(&self) -> String {
        match self.status {
            TaskStatus::Pending => "Pending".to_string(),
            TaskStatus::Assigned => "Assigned".to_string(),
            TaskStatus::Running => "Running".to_string(),
            TaskStatus::Completed => "Completed".to_string(),
            TaskStatus::Failed => "Failed".to_string(),
            TaskStatus::Timeout => "Timeout".to_string(),
        }
    }

    pub fn get_priority_display(&self) -> String {
        match self.priority {
            TaskPriority::Low => "Low".to_string(),
            TaskPriority::Normal => "Normal".to_string(),
            TaskPriority::High => "High".to_string(),
            TaskPriority::Critical => "Critical".to_string(),
        }
    }

    pub fn get_type_display(&self) -> String {
        match self.task_type {
            TaskType::Shell => "Shell".to_string(),
            TaskType::PowerShell => "PowerShell".to_string(),
            TaskType::Download => "Download".to_string(),
            TaskType::Upload => "Upload".to_string(),
            TaskType::Screenshot => "Screenshot".to_string(),
            TaskType::Keylog => "Keylog".to_string(),
            TaskType::ProcessList => "Process List".to_string(),
            TaskType::SystemInfo => "System Info".to_string(),
            TaskType::NetworkInfo => "Network Info".to_string(),
            TaskType::FileList => "File List".to_string(),
            TaskType::Registry => "Registry".to_string(),
            TaskType::Sleep => "Sleep".to_string(),
            TaskType::Jitter => "Jitter".to_string(),
            TaskType::Exit => "Exit".to_string(),
        }
    }
}

impl TaskResult {
    pub fn get_execution_time_display(&self) -> String {
        if self.execution_time < 1000.0 {
            format!("{:.0}ms", self.execution_time)
        } else {
            format!("{:.2}s", self.execution_time / 1000.0)
        }
    }

    pub fn is_success(&self) -> bool {
        self.error.is_none() && (self.exit_code.is_none() || self.exit_code == Some(0))
    }
}
