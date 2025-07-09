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

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{PasswordVerifier, password_hash::PasswordHash};
    use chrono::Utc;

    fn create_test_app_state() -> AppState {
        AppState::new()
    }

    fn create_test_user_request() -> CreateUserRequest {
        CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "test123".to_string(),
            name: "测试用户".to_string(),
        }
    }

    #[test]
    fn test_app_state_new() {
        let app_state = AppState::new();

        // 验证初始状态
        assert_eq!(
            app_state
                .inner
                .next_id
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(app_state.inner.users.is_empty());
        assert_eq!(app_state.list_users().len(), 0);
    }

    #[test]
    fn test_create_user_success() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let result = app_state.create_user(request);

        assert!(result.is_ok());
        let user = result.unwrap();

        // 验证用户属性
        assert_eq!(user.id, 1);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, "测试用户");
        assert!(!user.password.is_empty());

        // 验证密码已被哈希
        assert_ne!(user.password, "test123");
        assert!(user.password.starts_with("$argon2id$"));

        // 验证时间戳
        let now = Utc::now();
        assert!((now - user.create_at).num_seconds() < 5);
        assert!((now - user.update_at).num_seconds() < 5);
        assert_eq!(user.create_at, user.update_at);
    }

    #[test]
    fn test_create_user_password_hashing() {
        let app_state = create_test_app_state();
        let mut request = create_test_user_request();
        request.password = "plaintext_password".to_string();

        let result = app_state.create_user(request);
        assert!(result.is_ok());

        let user = result.unwrap();

        // 验证密码可以被验证
        let parsed_hash = PasswordHash::new(&user.password).unwrap();
        assert!(
            app_state
                .inner
                .argon2
                .verify_password(b"plaintext_password", &parsed_hash)
                .is_ok()
        );

        // 验证错误密码会失败
        assert!(
            app_state
                .inner
                .argon2
                .verify_password(b"wrong_password", &parsed_hash)
                .is_err()
        );
    }

    #[test]
    fn test_create_multiple_users() {
        let app_state = create_test_app_state();

        // 创建第一个用户
        let mut request1 = create_test_user_request();
        request1.email = "user1@example.com".to_string();
        let user1 = app_state.create_user(request1).unwrap();

        // 创建第二个用户
        let mut request2 = create_test_user_request();
        request2.email = "user2@example.com".to_string();
        let user2 = app_state.create_user(request2).unwrap();

        // 验证ID递增
        assert_eq!(user1.id, 1);
        assert_eq!(user2.id, 2);

        // 验证用户数量
        assert_eq!(app_state.list_users().len(), 2);
    }

    #[test]
    fn test_get_user_success() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let created_user = app_state.create_user(request).unwrap();
        let retrieved_user = app_state.get_user(created_user.id);

        assert!(retrieved_user.is_some());
        let retrieved_user = retrieved_user.unwrap();

        assert_eq!(retrieved_user.id, created_user.id);
        assert_eq!(retrieved_user.email, created_user.email);
        assert_eq!(retrieved_user.name, created_user.name);
        assert_eq!(retrieved_user.password, created_user.password);
    }

    #[test]
    fn test_get_user_not_found() {
        let app_state = create_test_app_state();

        let result = app_state.get_user(999);
        assert!(result.is_none());
    }

    #[test]
    fn test_update_user_success() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let created_user = app_state.create_user(request).unwrap();
        let original_create_time = created_user.create_at;

        // 稍等一下以确保时间戳不同
        std::thread::sleep(std::time::Duration::from_millis(10));

        let update_request = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            password: Some("new_password".to_string()),
            name: Some("更新用户".to_string()),
        };

        let updated_user = app_state.update_user(created_user.id, update_request);

        assert!(updated_user.is_some());
        let updated_user = updated_user.unwrap();

        // 验证更新的字段
        assert_eq!(updated_user.email, "updated@example.com");
        assert_eq!(updated_user.name, "更新用户");
        assert_ne!(updated_user.password, created_user.password);

        // 验证时间戳
        assert_eq!(updated_user.create_at, original_create_time); // 创建时间不变
        assert!(updated_user.update_at > original_create_time); // 更新时间改变

        // 验证新密码可以被验证
        let parsed_hash = PasswordHash::new(&updated_user.password).unwrap();
        assert!(
            app_state
                .inner
                .argon2
                .verify_password(b"new_password", &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_update_user_partial() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let created_user = app_state.create_user(request).unwrap();
        let original_password = created_user.password.clone();

        // 只更新邮箱
        let update_request = UpdateUserRequest {
            email: Some("partial@example.com".to_string()),
            password: None,
            name: None,
        };

        let updated_user = app_state.update_user(created_user.id, update_request);

        assert!(updated_user.is_some());
        let updated_user = updated_user.unwrap();

        // 验证只有邮箱被更新
        assert_eq!(updated_user.email, "partial@example.com");
        assert_eq!(updated_user.name, created_user.name); // 未更新
        assert_eq!(updated_user.password, original_password); // 未更新
    }

    #[test]
    fn test_update_user_not_found() {
        let app_state = create_test_app_state();

        let update_request = UpdateUserRequest {
            email: Some("test@example.com".to_string()),
            password: None,
            name: None,
        };

        let result = app_state.update_user(999, update_request);
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_user_success() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let created_user = app_state.create_user(request).unwrap();

        // 验证用户存在
        assert!(app_state.get_user(created_user.id).is_some());
        assert_eq!(app_state.list_users().len(), 1);

        // 删除用户
        let deleted_user = app_state.delete_user(created_user.id);

        assert!(deleted_user.is_some());
        let deleted_user = deleted_user.unwrap();

        // 验证返回的用户信息正确
        assert_eq!(deleted_user.id, created_user.id);
        assert_eq!(deleted_user.email, created_user.email);

        // 验证用户已被删除
        assert!(app_state.get_user(created_user.id).is_none());
        assert_eq!(app_state.list_users().len(), 0);
    }

    #[test]
    fn test_delete_user_not_found() {
        let app_state = create_test_app_state();

        let result = app_state.delete_user(999);
        assert!(result.is_none());
    }

    #[test]
    fn test_list_users_empty() {
        let app_state = create_test_app_state();

        let users = app_state.list_users();
        assert!(users.is_empty());
    }

    #[test]
    fn test_list_users_multiple() {
        let app_state = create_test_app_state();

        // 创建多个用户
        let mut request1 = create_test_user_request();
        request1.email = "user1@example.com".to_string();
        request1.name = "用户1".to_string();

        let mut request2 = create_test_user_request();
        request2.email = "user2@example.com".to_string();
        request2.name = "用户2".to_string();

        let mut request3 = create_test_user_request();
        request3.email = "user3@example.com".to_string();
        request3.name = "用户3".to_string();

        app_state.create_user(request1).unwrap();
        app_state.create_user(request2).unwrap();
        app_state.create_user(request3).unwrap();

        let users = app_state.list_users();
        assert_eq!(users.len(), 3);

        // 验证用户ID是递增的
        let mut user_ids: Vec<u64> = users.iter().map(|u| u.id).collect();
        user_ids.sort();
        assert_eq!(user_ids, vec![1, 2, 3]);
    }

    #[test]
    fn test_health_check() {
        let app_state = create_test_app_state();

        let health = app_state.health();

        assert_eq!(health.status, "healthy");

        // 验证时间戳是最近的
        let now = Utc::now();
        assert!((now - health.timestamp).num_seconds() < 5);
    }

    #[test]
    fn test_concurrent_user_creation() {
        let app_state = create_test_app_state();
        let app_state = Arc::new(app_state);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let app_state = Arc::clone(&app_state);
                std::thread::spawn(move || {
                    let request = CreateUserRequest {
                        email: format!("user{}@example.com", i),
                        password: "password".to_string(),
                        name: format!("用户{}", i),
                    };
                    app_state.create_user(request)
                })
            })
            .collect();

        // 等待所有线程完成
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // 验证所有用户都创建成功
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.is_ok()));

        // 验证用户数量
        assert_eq!(app_state.list_users().len(), 10);

        // 验证ID是唯一的
        let user_ids: Vec<u64> = app_state.list_users().iter().map(|u| u.id).collect();
        let mut sorted_ids = user_ids.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        assert_eq!(user_ids.len(), sorted_ids.len()); // 没有重复ID
    }

    #[test]
    fn test_password_hashing_helper() {
        let argon2 = Argon2::default();
        let password = "test_password_123";

        let result = hash_password(&argon2, password);
        assert!(result.is_ok());

        let hashed = result.unwrap();
        assert!(!hashed.is_empty());
        assert!(hashed.starts_with("$argon2id$"));

        // 验证密码可以被验证
        let parsed_hash = PasswordHash::new(&hashed).unwrap();
        assert!(
            argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        );
    }

    #[test]
    fn test_user_serialization_excludes_password() {
        let app_state = create_test_app_state();
        let request = create_test_user_request();

        let user = app_state.create_user(request).unwrap();

        // 序列化用户
        let serialized = serde_json::to_string(&user).unwrap();

        // 验证密码字段不在序列化结果中
        assert!(!serialized.contains("password"));
        assert!(serialized.contains("email"));
        assert!(serialized.contains("name"));
        assert!(serialized.contains("id"));
    }
}
