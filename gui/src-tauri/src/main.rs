#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod api_client;
mod commands;
mod models;

use commands::*;
use std::sync::{Arc, Mutex};
use tauri::{Manager, WindowEvent};

pub type AppState = Arc<Mutex<api_client::ApiClient>>;

fn main() {
    // Initialize logger
    env_logger::init();

    // Create API client state
    let api_client = Arc::new(Mutex::new(api_client::ApiClient::new(
        "http://127.0.0.1:8080".to_string(),
    )));

    tauri::Builder::default()
        .manage(api_client)
        .setup(|app| {
            // Initialize the main window
            let window = app.get_window("main").unwrap();

            // Set up window event handlers
            window.on_window_event(|event| match event {
                WindowEvent::CloseRequested { api, .. } => {
                    // Handle window close event
                    api.prevent_close();
                }
                _ => {}
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Server connection
            connect_to_server,
            disconnect_from_server,
            get_server_status,
            // Agent management
            get_agents,
            get_agent_details,
            update_agent,
            delete_agent,
            // Task management
            create_task,
            get_agent_tasks,
            get_task_results,
            // File operations
            download_file,
            upload_file,
            // Settings
            save_settings,
            load_settings,
            // Utility commands
            get_command_templates,
            show_file_dialog,
            show_message_dialog,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
