mod auth_handlers;
mod dto;
mod handlers;
mod shared_vault_handlers;
mod vault_handlers;

#[cfg(test)]
mod tests;

use axum::Router;
use axum::http::header::AUTHORIZATION;
use axum::routing::{delete, get, patch, post};
use tokio::net::TcpListener;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use crate::auth;
use crate::auth::{FailedLoginTracker, JwtSecret, SessionStore};
use crate::crypto_operations::{CryptoProvider, RealCrypto};
use crate::shared;

use auth_handlers::{login_handler, logout_handler, refresh_handler, register_handler};
use handlers::{generate_handler, health_handler};
use shared_vault_handlers::{
    add_shared_entry_handler, create_shared_vault_handler, delete_shared_entry_handler,
    delete_shared_vault_handler, invite_member_handler, list_members_handler,
    list_shared_entries_handler, list_shared_vaults_handler, revoke_member_handler,
    update_permission_handler, view_shared_entry_handler,
};
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
            // Vault
            super::vault_handlers::add_handler,
            super::vault_handlers::list_handler,
            super::vault_handlers::view_handler,
            super::vault_handlers::delete_handler,
            // Shared Vaults
            super::shared_vault_handlers::create_shared_vault_handler,
            super::shared_vault_handlers::list_shared_vaults_handler,
            super::shared_vault_handlers::delete_shared_vault_handler,
            // Shared Vaults - Members
            super::shared_vault_handlers::invite_member_handler,
            super::shared_vault_handlers::list_members_handler,
            super::shared_vault_handlers::revoke_member_handler,
            super::shared_vault_handlers::update_permission_handler,
            // Shared Vaults - Entries
            super::shared_vault_handlers::add_shared_entry_handler,
            super::shared_vault_handlers::list_shared_entries_handler,
            super::shared_vault_handlers::view_shared_entry_handler,
            super::shared_vault_handlers::delete_shared_entry_handler,
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
            dto::InviteMemberRequest,
            dto::InviteMemberResponse,
            dto::UpdatePermissionRequest,
            dto::SharedEntryListItem,
            dto::MemberListItem,
            dto::GenerateParams,
            dto::GenerateResponse,
        )),
        modifiers(&SecurityAddon),
        tags(
            (name = "System", description = "Health check and utilities"),
            (name = "Auth", description = "Authentication and session management"),
            (name = "Vault", description = "Personal vault entries"),
            (name = "Shared Vaults", description = "Shared vault management"),
            (name = "Shared Vaults - Members", description = "Shared vault member management"),
            (name = "Shared Vaults - Entries", description = "Shared vault entry management"),
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

    let app: Router = Router::new()
        .route("/health", get(health_handler))
        .route("/login", post(login_handler::<RealCrypto>))
        .route("/logout", post(logout_handler::<RealCrypto>))
        .route("/refresh", post(refresh_handler::<RealCrypto>))
        .route("/register", post(register_handler::<RealCrypto>))
        .route("/add", post(add_handler::<RealCrypto>))
        .route("/list", get(list_handler::<RealCrypto>))
        .route("/view/{id}", get(view_handler::<RealCrypto>))
        .route("/delete/{id}", delete(delete_handler::<RealCrypto>))
        .route("/generate", get(generate_handler))
        // Shared vaults
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
            "/shared-vaults/{vault_id}/invite",
            post(invite_member_handler::<RealCrypto>),
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
        .route(
            "/shared-vaults/{vault_id}/entries",
            post(add_shared_entry_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/entries",
            get(list_shared_entries_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/entries/{entry_id}",
            get(view_shared_entry_handler::<RealCrypto>),
        )
        .route(
            "/shared-vaults/{vault_id}/entries/{entry_id}",
            delete(delete_shared_entry_handler::<RealCrypto>),
        )
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

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to start server: {}", e)))?;

    Ok(())
}
