use crate::features::data_structs::{Agent, C2Registry};
use actix_web::{HttpResponse, Responder, Result, delete, get, post, put, web};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[post("/agents")]
pub async fn register_agent(
    agent: web::Json<Agent>,
    registry: web::Data<Arc<Mutex<C2Registry>>>,
) -> Result<impl Responder> {
    let mut registry = registry.lock().unwrap();
    let agent = agent.into_inner();
    registry.add_agent(agent.clone());

    Ok(HttpResponse::Created().json(json!({
        "status": "success",
        "message": "Agent registered successfully",
        "agent": agent
    })))
}

#[get("/agents")]
pub async fn list_agents(registry: web::Data<Arc<Mutex<C2Registry>>>) -> Result<impl Responder> {
    let registry = registry.lock().unwrap();
    let agents = registry.list_agents();

    Ok(HttpResponse::Ok().json(json!({
        "status": "success",
        "agents": agents
    })))
}

#[get("/agents/{id}")]
pub async fn get_agent(
    path: web::Path<String>,
    registry: web::Data<Arc<Mutex<C2Registry>>>,
) -> Result<impl Responder> {
    let agent_id = path.into_inner();
    let registry = registry.lock().unwrap();

    match registry.get_agent(&agent_id) {
        Some(agent) => Ok(HttpResponse::Ok().json(json!({
            "status": "success",
            "agent": agent
        }))),
        None => Ok(HttpResponse::NotFound().json(json!({
            "status": "error",
            "message": "Agent not found"
        }))),
    }
}

#[put("/agents/{id}")]
pub async fn update_agent(
    path: web::Path<String>,
    agent: web::Json<Agent>,
    registry: web::Data<Arc<Mutex<C2Registry>>>,
) -> Result<impl Responder> {
    let agent_id = path.into_inner();
    let mut registry = registry.lock().unwrap();
    let agent = agent.into_inner();

    // Check if agent exists first
    if registry.get_agent(&agent_id).is_some() {
        registry.update_agent(&agent_id, agent.clone());
        Ok(HttpResponse::Ok().json(json!({
            "status": "success",
            "message": "Agent updated successfully",
            "agent": agent
        })))
    } else {
        Ok(HttpResponse::NotFound().json(json!({
            "status": "error",
            "message": "Agent not found"
        })))
    }
}

#[delete("/agents/{id}")]
pub async fn delete_agent(
    path: web::Path<String>,
    registry: web::Data<Arc<Mutex<C2Registry>>>,
) -> Result<impl Responder> {
    let agent_id = path.into_inner();
    let mut registry = registry.lock().unwrap();

    // Check if agent exists first
    if registry.get_agent(&agent_id).is_some() {
        registry.remove_agent(&agent_id);
        Ok(HttpResponse::Ok().json(json!({
            "status": "success",
            "message": "Agent deleted successfully"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(json!({
            "status": "error",
            "message": "Agent not found"
        })))
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(register_agent)
        .service(list_agents)
        .service(get_agent)
        .service(update_agent)
        .service(delete_agent);
}
