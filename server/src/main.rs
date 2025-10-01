use actix_web::{App, HttpServer, web};
use std::sync::{Arc, Mutex};

mod api;
mod auth;
mod crypto;
mod features;

use features::data_structs::C2Registry;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Create shared agent registry
    let agent_registry = Arc::new(Mutex::new(C2Registry::new()));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(agent_registry.clone()))
            .service(web::scope("/api/v1").configure(api::routes::configure_routes))
    })
    .bind("127.0.0.1:8080")?
    .workers(4)
    .run()
    .await
}
