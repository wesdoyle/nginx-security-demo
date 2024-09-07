use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use sqlx::postgres::PgPoolOptions;
use sqlx::FromRow;
use serde::{Deserialize, Serialize};

#[derive(Serialize, FromRow)]
struct Course {
    id: i32,
    title: String,
    description: Option<String>,
    instructor: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    prefix: String,
}

async fn search_courses(
    query: web::Query<SearchQuery>,
    db_pool: web::Data<sqlx::PgPool>,
) -> impl Responder {

    let courses = sqlx::query_as!(
        Course,
        "SELECT id, title, description, instructor FROM courses WHERE title LIKE $1",
        format!("{}%", query.prefix)
    )
    .fetch_all(db_pool.get_ref())
    .await;
    match courses {
        Ok(courses) => HttpResponse::Ok().json(courses),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@db/coursedb".to_string());
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .route("/search", web::get().to(search_courses))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}