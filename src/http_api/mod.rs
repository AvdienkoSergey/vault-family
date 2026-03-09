mod auth_handlers;
mod dto;
mod handlers;
mod invite_handlers;
mod shared_vault_handlers;
mod transfer_handlers;
mod vault_handlers;

#[cfg(test)]
mod tests;

use axum::Router;
use axum::http::header::AUTHORIZATION;
use axum::routing::{delete, get, patch, post, put};
use tokio::net::TcpListener;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth;
use crate::auth::{
    DeviceTrustStore, FailedLoginTracker, JwtSecret, SecurityLockStore, SessionStore,
};
use crate::crypto_operations::{CryptoProvider, RealCrypto};
use crate::shared;
use crate::transfer::{TransferRateLimiter, TransferStore};
use crate::ws::{ConnectionRegistry, TicketStore};

use auth_handlers::{
    api_change_password_handler, api_login_handler, api_register_handler,
    api_security_lock_handler, login_handler, logout_handler, refresh_handler, register_handler,
};
use handlers::{generate_handler, health_handler};
use invite_handlers::{
    accept_invite_handler, complete_invite_handler, get_accepted_invites_handler,
    list_my_invites_handler, send_invite_handler,
};
use shared_vault_handlers::{
    api_create_vault_handler,
    api_delete_vault_handler,
    api_get_my_key_handler,
    api_list_members_handler,
    api_list_vaults_handler,
    api_pull_entries_handler,
    api_push_entries_handler,
    api_revoke_member_handler,
    api_update_keys_handler,
    // Legacy handlers
    create_shared_vault_handler,
    delete_shared_vault_handler,
    list_members_handler,
    list_shared_vaults_handler,
    revoke_member_handler,
    update_permission_handler,
};
use transfer_handlers::{transfer_download_handler, transfer_upload_handler};
use vault_handlers::{add_handler, delete_handler, list_handler, view_handler};

// ════════════════════════════════════════════════════════════════════
// Swagger / OpenAPI (feature = "swagger")
// ════════════════════════════════════════════════════════════════════

#[cfg(feature = "swagger")]
mod swagger {
    use super::dto;
    use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
    use utoipa::{Modify, OpenApi};

    pub struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "bearer_jwt",
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .bearer_format("JWT")
                            .build(),
                    ),
                );
            }
        }
    }

    #[derive(OpenApi)]
    #[openapi(
        info(
            title = "Vault Family API",
            description = "Password manager API",
            version = "0.1.7"
        ),
        paths(
            // System
            super::handlers::health_handler,
            super::handlers::generate_handler,
            // Auth
            super::auth_handlers::register_handler,
            super::auth_handlers::login_handler,
            super::auth_handlers::refresh_handler,
            super::auth_handlers::logout_handler,
            // Personal Vault
            super::vault_handlers::add_handler,
            super::vault_handlers::list_handler,
            super::vault_handlers::view_handler,
            super::vault_handlers::delete_handler,
            // API — Shared Vaults (zero-knowledge)
            super::shared_vault_handlers::api_create_vault_handler,
            super::shared_vault_handlers::api_list_vaults_handler,
            super::shared_vault_handlers::api_delete_vault_handler,
            // API — Members
            super::shared_vault_handlers::api_list_members_handler,
            super::shared_vault_handlers::api_revoke_member_handler,
            super::shared_vault_handlers::api_update_keys_handler,
            // API — Entries
            super::shared_vault_handlers::api_push_entries_handler,
            super::shared_vault_handlers::api_pull_entries_handler,
            // API — Invites
            super::invite_handlers::send_invite_handler,
            super::invite_handlers::list_my_invites_handler,
            super::invite_handlers::accept_invite_handler,
            super::invite_handlers::get_accepted_invites_handler,
            super::invite_handlers::complete_invite_handler,
            // Transfer (anonymous relay)
            super::transfer_handlers::transfer_upload_handler,
            super::transfer_handlers::transfer_download_handler,
        ),
        components(schemas(
            dto::RegisterRequest,
            dto::RegisterResponse,
            dto::LoginRequest,
            dto::LoginResponse,
            dto::RefreshRequest,
            dto::LogoutResponse,
            dto::AddRequest,
            dto::AddResponse,
            dto::ListEntry,
            dto::ViewResponse,
            dto::DeleteResponse,
            dto::CreateSharedVaultRequest,
            dto::CreateSharedVaultResponse,
            dto::SharedVaultListItem,
            dto::UpdatePermissionRequest,
            dto::MemberListItem,
            dto::GenerateParams,
            dto::GenerateResponse,
            // New API DTOs
            dto::ApiSharedVaultItem,
            dto::SendInviteRequest,
            dto::SendInviteResponse,
            dto::AcceptInviteRequest,
            dto::CompleteInviteRequest,
            dto::ApiInviteItem,
            dto::ApiAcceptedInviteItem,
            dto::ApiMemberItem,
            dto::MemberKeyUpdateItem,
            dto::UpdateMemberKeysRequest,
            dto::ApiEncryptedEntryItem,
            dto::PushEntriesRequest,
            dto::PullEntriesQuery,
            // Transfer DTOs
            dto::TransferUploadRequest,
            dto::TransferUploadResponse,
            dto::TransferDownloadResponse,
        )),
        modifiers(&SecurityAddon),
        tags(
            (name = "System", description = "Health check and utilities"),
            (name = "Auth", description = "Authentication and session management"),
            (name = "Vault", description = "Personal vault entries"),
            (name = "Shared Vaults", description = "Shared vault management (zero-knowledge)"),
            (name = "Invites", description = "4-step invitation flow"),
            (name = "Members", description = "Shared vault member management"),
            (name = "Entries", description = "Encrypted entry storage (zero-knowledge)"),
            (name = "Transfer", description = "Anonymous encrypted archive relay (in-memory)"),
        )
    )]
    pub struct ApiDoc;
}

// ════════════════════════════════════════════════════════════════════
// Ошибки сервера
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum ServerError {
    Connection(String),
}

impl std::error::Error for ServerError {}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Connection(msg) => write!(f, "connection error: {msg}"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Shared state
// ════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub(crate) struct AppState<C: CryptoProvider + Clone> {
    /// Путь к vault.db (пользователи + записи)
    pub(crate) db_path: String,
    /// Путь к auth.db (refresh-токены)
    pub(crate) auth_db_path: String,
    /// Путь к shared.db (shared vaults)
    pub(crate) shared_db_path: String,
    /// JWT-секрет для подписи токенов
    pub(crate) jwt_secret: Arc<JwtSecret>,
    /// Серверное хранилище сессий (EncryptionKey в памяти, не в JWT)
    pub(crate) session_store: SessionStore,
    /// Трекер неудачных попыток входа (brute-force защита)
    pub(crate) failed_login_tracker: FailedLoginTracker,
    /// Криптопровайдер
    pub(crate) crypto: C,
    /// In-memory хранилище трансферов (зашифрованные архивы, TTL ≤ 15 мин)
    pub(crate) transfer_store: TransferStore,
    /// Per-IP rate limiter для GET /transfer/{code}
    pub(crate) transfer_rate_limiter: TransferRateLimiter,
    /// WebSocket connection registry (user_id → senders)
    pub(crate) ws_registry: ConnectionRegistry,
    /// One-time tickets for secure WS handshake
    pub(crate) ticket_store: TicketStore,
    /// Permanent security lock triggered by legitimate user
    pub(crate) security_lock: SecurityLockStore,
    /// Trusted devices per email (exempt from brute-force/security lock)
    pub(crate) device_trust: DeviceTrustStore,
}

// ════════════════════════════════════════════════════════════════════
// Server
// ════════════════════════════════════════════════════════════════════

pub async fn run_server(host: &str, port: u16, db_path: String) -> Result<(), ServerError> {
    let socket_address = format!("{}:{}", &host, &port);

    let jwt_secret = auth::jwt_secret::load_or_create_jwt_secret(&db_path)
        .map_err(|e| ServerError::Connection(format!("Failed to load JWT secret: {e}")))?;

    let auth_db_path = auth::auth_db_path(&db_path);
    let shared_db_path = shared::shared_db_path(&db_path);

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("vault_family=info,tower_http=info")),
        )
        .compact()
        .init();

    // Transfer: in-memory store + rate limiter + background cleanup
    let transfer_store = TransferStore::new();
    let transfer_rate_limiter = TransferRateLimiter::new();
    {
        let store_clone = transfer_store.clone();
        let limiter_clone = transfer_rate_limiter.clone();
        tokio::spawn(async move {
            crate::transfer::cleanup_loop(store_clone, limiter_clone).await;
        });
    }

    // WebSocket: connection registry + ticket store + background cleanup
    let ws_registry = ConnectionRegistry::new();
    let ticket_store = TicketStore::new();
    {
        let registry_clone = ws_registry.clone();
        let ticket_clone = ticket_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                ticket_clone.cleanup_expired_public();
                registry_clone.cleanup_dead();
            }
        });
    }

    // New /api/* routes (zero-knowledge relay for mobile frontend)
    let api_routes: Router<AppState<RealCrypto>> = Router::new()
        // Auth
        .route("/auth/register", post(api_register_handler::<RealCrypto>))
        .route("/auth/login", post(api_login_handler::<RealCrypto>))
        // Vaults
        .route(
            "/vaults",
            post(api_create_vault_handler::<RealCrypto>).get(api_list_vaults_handler::<RealCrypto>),
        )
        .route(
            "/vaults/{vault_id}",
            delete(api_delete_vault_handler::<RealCrypto>),
        )
        // Invites (vault-scoped)
        .route(
            "/vaults/{vault_id}/invites",
            post(send_invite_handler::<RealCrypto>),
        )
        .route(
            "/vaults/{vault_id}/invites/accepted",
            get(get_accepted_invites_handler::<RealCrypto>),
        )
        // Invites (user-scoped)
        .route("/invites", get(list_my_invites_handler::<RealCrypto>))
        .route(
            "/invites/{invite_id}/accept",
            post(accept_invite_handler::<RealCrypto>),
        )
        .route(
            "/invites/{invite_id}/complete",
            post(complete_invite_handler::<RealCrypto>),
        )
        // Members
        .route(
            "/vaults/{vault_id}/members",
            get(api_list_members_handler::<RealCrypto>),
        )
        .route(
            "/vaults/{vault_id}/members/{user_id}",
            delete(api_revoke_member_handler::<RealCrypto>),
        )
        // Re-keying
        .route(
            "/vaults/{vault_id}/keys",
            put(api_update_keys_handler::<RealCrypto>),
        )
        // Member vault key
        .route(
            "/vaults/{vault_id}/my-key",
            get(api_get_my_key_handler::<RealCrypto>),
        )
        // Entries (zero-knowledge)
        .route(
            "/vaults/{vault_id}/entries",
            post(api_push_entries_handler::<RealCrypto>)
                .get(api_pull_entries_handler::<RealCrypto>),
        )
        // Security
        .route(
            "/auth/security-lock",
            post(api_security_lock_handler::<RealCrypto>),
        )
        .route(
            "/auth/change-password",
            post(api_change_password_handler::<RealCrypto>),
        )
        // WebSocket ticket
        .route(
            "/ws/ticket",
            post(crate::ws::ws_ticket_handler::<RealCrypto>),
        );

    let app: Router = Router::new()
        .route("/ws", get(crate::ws::ws_upgrade_handler::<RealCrypto>))
        .route("/health", get(health_handler))
        // Legacy auth routes
        .route("/login", post(login_handler::<RealCrypto>))
        .route("/logout", post(logout_handler::<RealCrypto>))
        .route("/refresh", post(refresh_handler::<RealCrypto>))
        .route("/register", post(register_handler::<RealCrypto>))
        // Personal vault
        .route("/add", post(add_handler::<RealCrypto>))
        .route("/list", get(list_handler::<RealCrypto>))
        .route("/view/{id}", get(view_handler::<RealCrypto>))
        .route("/delete/{id}", delete(delete_handler::<RealCrypto>))
        .route("/generate", get(generate_handler))
        // Legacy shared vault routes (backward compatibility)
        .route(
            "/shared-vaults",
            post(create_shared_vault_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults",
            get(list_shared_vaults_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}",
            delete(delete_shared_vault_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/members",
            get(list_members_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/members/{user_id}",
            delete(revoke_member_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/members/{user_id}",
            patch(update_permission_handler::<RealCrypto>),
        )
        // Transfer (anonymous, no auth)
        .route("/transfer", post(transfer_upload_handler::<RealCrypto>))
        .route(
            "/transfer/{code}",
            get(transfer_download_handler::<RealCrypto>),
        )
        // Mount new API routes
        .nest("/api", api_routes)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new([AUTHORIZATION]))
        .with_state(AppState {
            db_path,
            auth_db_path,
            shared_db_path,
            jwt_secret: Arc::new(jwt_secret),
            session_store: SessionStore::new(),
            failed_login_tracker: FailedLoginTracker::new(),
            crypto: RealCrypto,
            transfer_store,
            transfer_rate_limiter,
            ws_registry,
            ticket_store,
            security_lock: SecurityLockStore::new(),
            device_trust: DeviceTrustStore::new(),
        });

    #[cfg(feature = "swagger")]
    let app = {
        if std::env::var("SWAGGER_ENABLED").unwrap_or_default() == "true" {
            tracing::warn!("Swagger UI is ENABLED at /swagger-ui — do NOT use in production!");
            use swagger::ApiDoc;
            use utoipa::OpenApi;
            use utoipa_swagger_ui::SwaggerUi;
            app.merge(
                SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
        } else {
            app
        }
    };

    let listener = TcpListener::bind(socket_address)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to open remote address: {}", e)))?;

    println!("Server started at http://{}:{}", host, port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| ServerError::Connection(format!("Unable to start server: {}", e)))?;

    Ok(())
}
