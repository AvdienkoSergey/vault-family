use crate::types::JwtSecret;
use rand::RngExt;
use std::fs;
use std::path::Path;
use tracing::info;

pub fn load_or_create_jwt_secret(db_path: &str) -> Result<JwtSecret, std::io::Error> {
    // 1. Проверяем переменную окружения
    if let Ok(secret) = std::env::var("JWT_SECRET") {
        info!("JWT secret loaded from JWT_SECRET env var");
        return Ok(JwtSecret::new(secret));
    }

    // 2. Читаем файл рядом с БД
    let secret_path = Path::new(db_path)
        .parent()
        .expect("db_path must have a parent directory")
        .join(".jwt_secret");

    if let Ok(secret) = fs::read_to_string(&secret_path) {
        let trimmed = secret.trim();
        if !trimmed.is_empty() {
            info!("JWT secret loaded from file: {}", secret_path.display());
            return Ok(JwtSecret::new(trimmed.to_string()));
        }
    }

    // 3. Генерируем 64 random bytes → hex → записываем в файл
    let mut bytes = [0u8; 64];
    rand::rng().fill(&mut bytes);
    let hex_secret = hex::encode(bytes);

    fs::write(&secret_path, &hex_secret)?;
    info!(
        "JWT secret generated and saved to: {}",
        secret_path.display()
    );

    Ok(JwtSecret::new(hex_secret))
}
