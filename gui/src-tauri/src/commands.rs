use crate::api_client::{ApiClient, ApiError};
use crate::models::*;
use crate::AppState;
use chrono::Utc;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tauri::{command, AppHandle, Manager};
use tokio::time::{sleep, Duration};

// Server connection commands
#[command]
pub async fn connect_to_server(
    app_handle: AppHandle,
    state: AppState,
    url: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<ServerConnection, String> {
    let mut api_client = state.lock().map_err(|e| e.to_string())?;

    // Update the API client with new URL
    *api_client = ApiClient::new(url.clone());

    // Test connection
    match api_client.test_connection().await {
        Ok(_) => {
            // If credentials provided, authenticate
            if let (Some(user), Some(pass)) = (username, password) {
                // This would need to be implemented in the server API
                // For now, we'll just mark as connected
                api_client.set_auth_token("dummy_token".to_string());
            }

            let connection = ServerConnection {
                url: url.clone(),
                is_connected: true,
                last_connected: Some(chrono::Utc::now()),
                auth_token: api_client.auth_token.clone(),
            };

            // Start auto-refresh if enabled
            start_auto_refresh(app_handle, state.clone()).await;

            Ok(connection)
        }
        Err(e) => Err(format!("Failed to connect to server: {}", e)),
    }
}

#[command]
pub async fn disconnect_from_server(state: AppState) -> Result<(), String> {
    let mut api_client = state.lock().map_err(|e| e.to_string())?;
    api_client.clear_auth();
    Ok(())
}

#[command]
pub async fn get_server_status(state: AppState) -> Result<ServerConnection, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;

    match api_client.test_connection().await {
        Ok(_) => Ok(ServerConnection {
            url: api_client.base_url.clone(),
            is_connected: true,
            last_connected: Some(chrono::Utc::now()),
            auth_token: api_client.auth_token.clone(),
        }),
        Err(_) => Ok(ServerConnection {
            url: api_client.base_url.clone(),
            is_connected: false,
            last_connected: None,
            auth_token: None,
        }),
    }
}

// Agent management commands
#[command]
pub async fn get_agents(state: AppState) -> Result<Vec<Agent>, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client.get_agents().await.map_err(|e| e.to_string())
}

#[command]
pub async fn get_agent_details(state: AppState, agent_id: String) -> Result<Agent, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .get_agent(&agent_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn update_agent(state: AppState, agent_id: String, agent: Agent) -> Result<(), String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .update_agent(&agent_id, &agent)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn delete_agent(state: AppState, agent_id: String) -> Result<(), String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .delete_agent(&agent_id)
        .await
        .map_err(|e| e.to_string())
}

// Task management commands
#[command]
pub async fn create_task(
    state: AppState,
    agent_id: String,
    command: String,
    arguments: Vec<String>,
    task_type: TaskType,
) -> Result<Task, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .create_task(&agent_id, &command, arguments, task_type)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_agent_tasks(state: AppState, agent_id: String) -> Result<Vec<Task>, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .get_agent_tasks(&agent_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_task_results(
    state: AppState,
    agent_id: String,
) -> Result<Vec<TaskResult>, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;
    api_client
        .get_task_results(&agent_id)
        .await
        .map_err(|e| e.to_string())
}

// File operations
#[command]
pub async fn download_file(
    state: AppState,
    agent_id: String,
    file_path: String,
    save_path: String,
) -> Result<String, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;

    match api_client.download_file(&agent_id, &file_path).await {
        Ok(file_data) => {
            // Save file to specified path
            match fs::write(&save_path, file_data) {
                Ok(_) => Ok(format!("File saved to: {}", save_path)),
                Err(e) => Err(format!("Failed to save file: {}", e)),
            }
        }
        Err(e) => Err(format!("Failed to download file: {}", e)),
    }
}

#[command]
pub async fn upload_file(
    state: AppState,
    agent_id: String,
    local_path: String,
    remote_path: String,
) -> Result<String, String> {
    let api_client = state.lock().map_err(|e| e.to_string())?;

    // Read local file
    match fs::read(&local_path) {
        Ok(file_data) => {
            api_client
                .upload_file(&agent_id, &remote_path, file_data)
                .await
                .map_err(|e| e.to_string())?;
            Ok(format!("File uploaded successfully to: {}", remote_path))
        }
        Err(e) => Err(format!("Failed to read local file: {}", e)),
    }
}

// Settings commands
#[command]
pub async fn save_settings(settings: GuiSettings) -> Result<(), String> {
    // Get app data directory
    let app_dir = tauri::api::path::app_data_dir(&tauri::Config::default())
        .ok_or("Failed to get app data directory")?;

    let settings_dir = app_dir.join("scythe-gui");
    fs::create_dir_all(&settings_dir).map_err(|e| e.to_string())?;

    let settings_file = settings_dir.join("settings.json");
    let settings_json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;

    fs::write(settings_file, settings_json).map_err(|e| e.to_string())?;
    Ok(())
}

#[command]
pub async fn load_settings() -> Result<GuiSettings, String> {
    // Get app data directory
    let app_dir = tauri::api::path::app_data_dir(&tauri::Config::default())
        .ok_or("Failed to get app data directory")?;

    let settings_file = app_dir.join("scythe-gui").join("settings.json");

    if !settings_file.exists() {
        return Ok(GuiSettings::default());
    }

    let settings_content = fs::read_to_string(settings_file).map_err(|e| e.to_string())?;
    let settings: GuiSettings =
        serde_json::from_str(&settings_content).map_err(|e| e.to_string())?;

    Ok(settings)
}

// Utility commands
#[command]
pub async fn get_command_templates() -> Result<Vec<CommandTemplate>, String> {
    let templates = vec![
        CommandTemplate {
            id: "sysinfo".to_string(),
            name: "System Information".to_string(),
            description: "Get detailed system information".to_string(),
            command: "systeminfo".to_string(),
            arguments: vec![],
            task_type: TaskType::SystemInfo,
            category: "Reconnaissance".to_string(),
        },
        CommandTemplate {
            id: "process_list".to_string(),
            name: "Process List".to_string(),
            description: "List all running processes".to_string(),
            command: "tasklist".to_string(),
            arguments: vec!["/v".to_string()],
            task_type: TaskType::ProcessList,
            category: "Reconnaissance".to_string(),
        },
        CommandTemplate {
            id: "network_info".to_string(),
            name: "Network Information".to_string(),
            description: "Get network configuration".to_string(),
            command: "ipconfig".to_string(),
            arguments: vec!["/all".to_string()],
            task_type: TaskType::NetworkInfo,
            category: "Reconnaissance".to_string(),
        },
        CommandTemplate {
            id: "screenshot".to_string(),
            name: "Screenshot".to_string(),
            description: "Capture desktop screenshot".to_string(),
            command: "screenshot".to_string(),
            arguments: vec![],
            task_type: TaskType::Screenshot,
            category: "Collection".to_string(),
        },
        CommandTemplate {
            id: "powershell_whoami".to_string(),
            name: "PowerShell Whoami".to_string(),
            description: "Get current user context via PowerShell".to_string(),
            command: "whoami".to_string(),
            arguments: vec!["/all".to_string()],
            task_type: TaskType::PowerShell,
            category: "Reconnaissance".to_string(),
        },
        CommandTemplate {
            id: "download_file".to_string(),
            name: "Download File".to_string(),
            description: "Download a file from the target".to_string(),
            command: "download".to_string(),
            arguments: vec!["<file_path>".to_string()],
            task_type: TaskType::Download,
            category: "Exfiltration".to_string(),
        },
        CommandTemplate {
            id: "upload_file".to_string(),
            name: "Upload File".to_string(),
            description: "Upload a file to the target".to_string(),
            command: "upload".to_string(),
            arguments: vec!["<local_path>".to_string(), "<remote_path>".to_string()],
            task_type: TaskType::Upload,
            category: "Infiltration".to_string(),
        },
        CommandTemplate {
            id: "sleep".to_string(),
            name: "Set Sleep Interval".to_string(),
            description: "Configure agent sleep time".to_string(),
            command: "sleep".to_string(),
            arguments: vec!["<seconds>".to_string()],
            task_type: TaskType::Sleep,
            category: "Configuration".to_string(),
        },
        CommandTemplate {
            id: "exit".to_string(),
            name: "Exit Agent".to_string(),
            description: "Terminate the agent process".to_string(),
            command: "exit".to_string(),
            arguments: vec![],
            task_type: TaskType::Exit,
            category: "Control".to_string(),
        },
    ];

    Ok(templates)
}

// Helper function for auto-refresh
async fn start_auto_refresh(app_handle: AppHandle, state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            // Check if still connected
            let api_client = match state.lock() {
                Ok(client) => client,
                Err(_) => break,
            };

            if api_client.test_connection().await.is_ok() {
                // Emit refresh event to frontend
                let _ = app_handle.emit_all("refresh-data", ());
            } else {
                // Connection lost, stop refreshing
                break;
            }
        }
    });
}

// Additional utility commands
#[command]
pub async fn show_file_dialog(
    app_handle: AppHandle,
    dialog_type: String,
    title: String,
    default_path: Option<String>,
    filters: Option<Vec<Value>>,
) -> Result<Option<String>, String> {
    use tauri::api::dialog::{blocking::FileDialogBuilder, MessageDialogKind};

    let mut dialog = FileDialogBuilder::new();

    if let Some(path) = default_path {
        dialog = dialog.set_path(path);
    }

    let result = match dialog_type.as_str() {
        "open_file" => dialog.pick_file(),
        "save_file" => dialog.save_file(),
        "open_folder" => dialog.pick_folder(),
        _ => return Err("Invalid dialog type".to_string()),
    };

    Ok(result.map(|p| p.to_string_lossy().to_string()))
}

#[command]
pub async fn show_message_dialog(
    app_handle: AppHandle,
    title: String,
    message: String,
    kind: String,
) -> Result<bool, String> {
    use tauri::api::dialog::{blocking::MessageDialogBuilder, MessageDialogKind};

    let dialog_kind = match kind.as_str() {
        "info" => MessageDialogKind::Info,
        "warning" => MessageDialogKind::Warning,
        "error" => MessageDialogKind::Error,
        _ => MessageDialogKind::Info,
    };

    let _ = MessageDialogBuilder::new(title, message)
        .kind(dialog_kind)
        .show();

    Ok(true)
}

#[command]
pub async fn open_url(url: String) -> Result<(), String> {
    match webbrowser::open(&url) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to open URL: {}", e)),
    }
}
