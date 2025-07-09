# Simple Proxy

一个基于 Pingora 的高性能反向代理服务器，专为现代 Rust 应用设计。

## 🚀 项目概述

Simple Proxy 是一个使用 Cloudflare 的 [Pingora](https://github.com/cloudflare/pingora) 框架构建的反向代理服务器。它提供了高性能的 HTTP 代理功能，并包含一个完整的示例用户管理服务器作为代理目标。

### 主要特性

- **高性能反向代理**: 基于 Pingora 框架，提供企业级性能
- **用户管理 API**: 完整的 CRUD 操作示例服务器
- **安全密码处理**: 使用 Argon2 进行密码哈希
- **并发安全**: 使用 DashMap 实现无锁并发数据结构
- **全面测试覆盖**: 包含 17 个单元测试，覆盖所有核心功能
- **结构化日志**: 集成 tracing 和请求/响应日志
- **健康检查**: 内置健康检查端点

## 📋 系统要求

- Rust 1.75+ (使用 Rust 2024 Edition)
- Linux/macOS/WSL2
- 8MB+ 可用内存

## 🛠️ 安装和设置

### 1. 克隆项目

```bash
git clone https://github.com/rcrwhyg/simple-proxy.git
cd simple-proxy
```

### 2. 构建项目

```bash
# 构建反向代理服务器
cargo build --release

# 构建示例用户管理服务器
cargo build --release --example server
```

### 3. 运行测试

```bash
# 运行所有测试
make test

# 运行示例服务器测试
cargo test --example server
```

## 🚦 快速开始

### 启动示例服务器

```bash
# 在端口 3000 启动用户管理服务器
cargo run --example server
```

服务器启动后，你将看到以下输出：

```
服务器已启动，监听地址: 127.0.0.1:3000
API 端点:
  GET    /users       - 获取用户列表
  POST   /users       - 创建新用户
  GET    /users/{id}  - 获取指定用户
  PUT    /users/{id}  - 更新指定用户
  DELETE /users/{id}  - 删除指定用户
  GET    /health      - 健康检查
```

### 启动反向代理

```bash
# 启动反向代理服务器（代理到示例服务器）
cargo run
```

## 📚 API 文档

### 用户管理端点

#### 获取所有用户
```http
GET /users
```

**响应示例:**
```json
[
  {
    "id": 1,
    "email": "user@example.com",
    "name": "用户名",
    "create_at": "2024-01-15T10:30:00Z",
    "update_at": "2024-01-15T10:30:00Z"
  }
]
```

#### 创建新用户
```http
POST /users
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "securepassword123",
  "name": "新用户"
}
```

**响应示例:**
```json
{
  "id": 2,
  "email": "newuser@example.com",
  "name": "新用户",
  "create_at": "2024-01-15T10:35:00Z",
  "update_at": "2024-01-15T10:35:00Z"
}
```

#### 获取指定用户
```http
GET /users/{id}
```

#### 更新用户信息
```http
PUT /users/{id}
Content-Type: application/json

{
  "email": "updated@example.com",
  "name": "更新后的用户名"
}
```

#### 删除用户
```http
DELETE /users/{id}
```

#### 健康检查
```http
GET /health
```

**响应示例:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:40:00Z"
}
```

## 🔧 开发指南

### 项目结构

```
simple-proxy/
├── src/                    # 反向代理核心代码
├── examples/
│   └── server.rs          # 示例用户管理服务器
├── specs/
│   └── 001-example-server.md  # 服务器规范文档
├── Cargo.toml             # 项目依赖配置
└── README.md              # 项目文档
```

### 核心依赖

- **axum 0.8**: 现代异步 Web 框架
- **tokio 1.46**: 异步运行时
- **dashmap 6.1**: 并发哈希映射
- **argon2 0.5**: 密码哈希算法
- **serde 1.0**: 序列化/反序列化
- **chrono 0.4**: 日期时间处理
- **tracing**: 结构化日志

### 开发工作流

1. **编码**:
   ```bash
   # 检查代码质量
   cargo clippy
   ```

2. **测试**:
   ```bash
   # 运行所有测试
   cargo test

   # 运行特定模块测试
   cargo test --example server tests::test_create_user
   ```

3. **构建**:
   ```bash
   # 开发构建
   cargo build

   # 发布构建
   cargo build --release
   ```

### 添加新功能

1. **创建功能分支**:
   ```bash
   git checkout -b feature/new-feature
   ```

2. **编写测试**:
   ```rust
   #[test]
   fn test_new_feature() {
       // 测试代码
   }
   ```

3. **实现功能**:
   ```rust
   // 功能实现
   ```

4. **验证**:
   ```bash
   cargo test && cargo clippy
   ```

## 🧪 测试

项目包含全面的测试套件：

### 单元测试覆盖

- ✅ AppState 初始化
- ✅ 用户创建和 ID 生成
- ✅ 密码哈希和验证
- ✅ 用户查询、更新和删除
- ✅ 用户列表获取
- ✅ 健康检查
- ✅ 并发安全性
- ✅ 序列化行为（密码排除）

### 运行测试

```bash
# 运行所有测试
make test

# 运行特定测试文件
cargo test --example server

# 运行特定测试
cargo test test_create_user

# 显示测试输出
cargo test -- --nocapture
```

### 测试覆盖率

```bash
# 安装 cargo-tarpaulin
cargo install cargo-tarpaulin

# 生成测试覆盖率报告
cargo tarpaulin --example server
```

## 🏗️ 架构设计

### 系统架构

```
客户端请求 → 反向代理 (Pingora) → 示例服务器 (Axum)
                 ↓
            负载均衡、缓存、日志
```

### 数据流

1. **请求处理**: 客户端发送 HTTP 请求到反向代理
2. **代理转发**: Pingora 将请求转发到后端服务器
3. **业务逻辑**: Axum 服务器处理业务逻辑
4. **数据存储**: DashMap 提供内存数据存储
5. **响应返回**: 响应通过代理返回给客户端

### 安全特性

- **密码安全**: 使用 Argon2 进行密码哈希
- **数据保护**: 序列化时自动排除敏感字段
- **并发安全**: 使用无锁数据结构避免竞态条件
- **输入验证**: 严格的请求数据验证

## 📊 性能特性

- **零拷贝**: Pingora 提供高效的内存使用
- **异步处理**: 全异步架构支持高并发
- **无锁设计**: DashMap 避免锁竞争
- **内存高效**: 最小化内存分配和复制

## 🔍 监控和日志

### 结构化日志

项目使用 `tracing` 提供结构化日志：

```rust
// 请求日志
info!("on_request: {:?}", request);

// 响应日志
info!("on_response: {:?}", response);
```

### 健康检查

内置健康检查端点：

```bash
curl http://localhost:3000/health
```

## 🤝 贡献指南

1. **Fork 项目**
2. **创建功能分支**: `git checkout -b feature/amazing-feature`
3. **提交更改**: `git commit -m 'Add amazing feature'`
4. **推送分支**: `git push origin feature/amazing-feature`
5. **创建 Pull Request**

### 代码规范

- 遵循 Rust 2024 Edition 标准
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 进行代码检查
- 为新功能编写测试
- 更新相关文档

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE.md](LICENSE.md) 文件了解详情。

## 🙏 致谢

- [Pingora](https://github.com/cloudflare/pingora) - 高性能代理框架
- [Axum](https://github.com/tokio-rs/axum) - 现代 Rust Web 框架
- [Tokio](https://tokio.rs/) - 异步运行时

## 📞 联系方式

- **作者**: rcrwhyg
- **邮箱**: rcrwhyg@sina.com
- **GitHub**: [https://github.com/rcrwhyg/simple-proxy](https://github.com/rcrwhyg/simple-proxy)

---

**注意**: 这是一个示例项目，用于演示反向代理和 Web 服务器集成。在生产环境中使用前，请确保进行适当的安全审查和性能测试。
