use chrono::{DateTime, Utc};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {0}")]
    Api(String),
    #[error("Authentication error")]
    Auth,
    #[error("Not connected to server")]
    NotConnected,
}

// Import models from the server
use crate::models::{Agent, Task, TaskPriority, TaskResult, TaskStatus, TaskType};

#[derive(Clone, Debug)]
pub struct ApiClient {
    pub client: Client,
    pub base_url: String,
    pub auth_token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: None,
        }
    }

    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    pub fn clear_auth(&mut self) {
        self.auth_token = None;
    }

    fn get_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        if let Some(token) = &self.auth_token {
            headers.insert("Authorization".to_string(), format!("Bearer {}", token));
        }

        headers
    }

    pub async fn test_connection(&self) -> Result<(), ApiError> {
        let response = self
            .client
            .get(&format!("{}/api/v1/agents", self.base_url))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError::Api(format!(
                "Server returned status: {}",
                response.status()
            )))
        }
    }

    // Agent management
    pub async fn get_agents(&self) -> Result<Vec<Agent>, ApiError> {
        let response = self
            .client
            .get(&format!("{}/api/v1/agents", self.base_url))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            let agents: Vec<Agent> = serde_json::from_value(data["agents"].clone())?;
            Ok(agents)
        } else {
            Err(ApiError::Api(format!(
                "Failed to get agents: {}",
                response.status()
            )))
        }
    }

    pub async fn get_agent(&self, agent_id: &str) -> Result<Agent, ApiError> {
        let response = self
            .client
            .get(&format!("{}/api/v1/agents/{}", self.base_url, agent_id))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            let agent: Agent = serde_json::from_value(data["agent"].clone())?;
            Ok(agent)
        } else if response.status() == 404 {
            Err(ApiError::Api("Agent not found".to_string()))
        } else {
            Err(ApiError::Api(format!(
                "Failed to get agent: {}",
                response.status()
            )))
        }
    }

    pub async fn update_agent(&self, agent_id: &str, agent: &Agent) -> Result<(), ApiError> {
        let response = self
            .client
            .put(&format!("{}/api/v1/agents/{}", self.base_url, agent_id))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .json(agent)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == 404 {
            Err(ApiError::Api("Agent not found".to_string()))
        } else {
            Err(ApiError::Api(format!(
                "Failed to update agent: {}",
                response.status()
            )))
        }
    }

    pub async fn delete_agent(&self, agent_id: &str) -> Result<(), ApiError> {
        let response = self
            .client
            .delete(&format!("{}/api/v1/agents/{}", self.base_url, agent_id))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == 404 {
            Err(ApiError::Api("Agent not found".to_string()))
        } else {
            Err(ApiError::Api(format!(
                "Failed to delete agent: {}",
                response.status()
            )))
        }
    }

    // Task management (these would need to be implemented in the server API)
    pub async fn create_task(
        &self,
        agent_id: &str,
        command: &str,
        arguments: Vec<String>,
        task_type: TaskType,
    ) -> Result<Task, ApiError> {
        let task_data = serde_json::json!({
            "agent_id": agent_id,
            "command": command,
            "arguments": arguments,
            "task_type": task_type
        });

        let response = self
            .client
            .post(&format!("{}/api/v1/tasks", self.base_url))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .json(&task_data)
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            let task: Task = serde_json::from_value(data["task"].clone())?;
            Ok(task)
        } else {
            Err(ApiError::Api(format!(
                "Failed to create task: {}",
                response.status()
            )))
        }
    }

    pub async fn get_agent_tasks(&self, agent_id: &str) -> Result<Vec<Task>, ApiError> {
        let response = self
            .client
            .get(&format!(
                "{}/api/v1/agents/{}/tasks",
                self.base_url, agent_id
            ))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            let tasks: Vec<Task> = serde_json::from_value(data["tasks"].clone())?;
            Ok(tasks)
        } else {
            Err(ApiError::Api(format!(
                "Failed to get tasks: {}",
                response.status()
            )))
        }
    }

    pub async fn get_task_results(&self, agent_id: &str) -> Result<Vec<TaskResult>, ApiError> {
        let response = self
            .client
            .get(&format!(
                "{}/api/v1/agents/{}/results",
                self.base_url, agent_id
            ))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            let results: Vec<TaskResult> = serde_json::from_value(data["results"].clone())?;
            Ok(results)
        } else {
            Err(ApiError::Api(format!(
                "Failed to get results: {}",
                response.status()
            )))
        }
    }

    // File operations
    pub async fn download_file(
        &self,
        agent_id: &str,
        file_path: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let request_data = serde_json::json!({
            "agent_id": agent_id,
            "file_path": file_path
        });

        let response = self
            .client
            .post(&format!("{}/api/v1/files/download", self.base_url))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .json(&request_data)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.bytes().await?.to_vec())
        } else {
            Err(ApiError::Api(format!(
                "Failed to download file: {}",
                response.status()
            )))
        }
    }

    pub async fn upload_file(
        &self,
        agent_id: &str,
        file_path: &str,
        file_data: Vec<u8>,
    ) -> Result<(), ApiError> {
        let form = reqwest::multipart::Form::new()
            .part(
                "agent_id",
                reqwest::multipart::Part::text(agent_id.to_string()),
            )
            .part(
                "file_path",
                reqwest::multipart::Part::text(file_path.to_string()),
            )
            .part("file_data", reqwest::multipart::Part::bytes(file_data));

        let response = self
            .client
            .post(&format!("{}/api/v1/files/upload", self.base_url))
            .headers(self.get_headers().try_into().unwrap_or_default())
            .multipart(form)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError::Api(format!(
                "Failed to upload file: {}",
                response.status()
            )))
        }
    }
}
