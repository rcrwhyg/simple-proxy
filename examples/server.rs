use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU64},
};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: u64,
    email: String,
    #[serde(skip_serializing)]
    password: String,
    name: String,
    create_at: DateTime<Utc>,
    update_at: DateTime<Utc>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    next_id: AtomicU64,
    users: DashMap<u64, User>,
    argon2: Argon2<'static>,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    email: String,
    password: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    email: Option<String>,
    password: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: DateTime<Utc>,
}

impl AppState {
    fn new() -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                next_id: AtomicU64::new(1),
                users: DashMap::new(),
                argon2: Argon2::default(),
            }),
        }
    }

    fn get_user(&self, id: u64) -> Option<User> {
        self.inner.users.get(&id).map(|user| user.clone())
    }

    fn create_user(&self, req: CreateUserRequest) -> Result<User, anyhow::Error> {
        // 生成密码哈希
        let password_hash = hash_password(&self.inner.argon2, &req.password)?;

        let id = self
            .inner
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = Utc::now();

        let user = User {
            id,
            email: req.email,
            password: password_hash,
            name: req.name,
            create_at: now,
            update_at: now,
        };

        self.inner.users.insert(id, user.clone());
        Ok(user)
    }

    fn update_user(&self, id: u64, req: UpdateUserRequest) -> Option<User> {
        let mut user_ref = self.get_user(id)?;

        if let Some(email) = req.email {
            user_ref.email = email;
        }

        if let Some(password) = req.password {
            let password_hash = hash_password(&self.inner.argon2, &password).ok()?;
            user_ref.password = password_hash;
        }

        if let Some(name) = req.name {
            user_ref.name = name;
        }

        user_ref.update_at = Utc::now();
        let updated_user = user_ref.clone();
        Some(updated_user)
    }

    fn delete_user(&self, id: u64) -> Option<User> {
        self.inner.users.remove(&id).map(|(_, user)| user)
    }

    fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "healthy".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn list_users(&self) -> Vec<User> {
        self.inner
            .users
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

fn hash_password(argon2: &Argon2<'static>, password: &str) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("Failed to hash password"))?
        .to_string();
    Ok(password_hash)
}

// 处理函数
async fn get_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state.get_user(id).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn list_users(State(state): State<AppState>) -> Json<Vec<User>> {
    Json(state.list_users())
}

async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<User>), (StatusCode, String)> {
    match state.create_user(req) {
        Ok(user) => Ok((StatusCode::CREATED, Json(user))),
        Err(err) => Err((StatusCode::BAD_REQUEST, err.to_string())),
    }
}

async fn update_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    state
        .update_user(id, req)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn delete_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state.delete_user(id).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(state.health())
}

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 创建应用状态
    let app_state = AppState::new();

    // 构建路由
    let app = Router::new()
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // 启动服务器
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    info!("服务器已启动，监听地址: {}", listener.local_addr().unwrap());
    info!("API 端点:");
    info!("  GET    /users       - 获取用户列表");
    info!("  POST   /users       - 创建新用户");
    info!("  GET    /users/{{id}}  - 获取指定用户");
    info!("  PUT    /users/{{id}}  - 更新指定用户");
    info!("  DELETE /users/{{id}}  - 删除指定用户");
    info!("  GET    /health      - 健康检查");

    axum::serve(listener, app).await.unwrap();
}
