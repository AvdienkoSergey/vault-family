//! Branded types для JWT/auth-домена.
//!
//! Живут в auth/, потому что это типы Вахтера,
//! а не Хранилища (vault/) или общего домена (types.rs).

use crate::branded_secret;
use std::fmt;

// JWT
branded_secret!(JwtSecret); // ключ подписи (живёт в AppState)

// Refresh tokens
branded_secret!(RefreshTokenHash); // SHA-256 хэш, хранится в auth.db
