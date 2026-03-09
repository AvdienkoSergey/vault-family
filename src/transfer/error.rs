use std::fmt;

#[derive(Debug)]
pub enum TransferError {
    /// Payload превышает MAX_PAYLOAD_BYTES.
    PayloadTooLarge,
    /// Хранилище заполнено (MAX_CONCURRENT_SLOTS).
    StoreFull,
    /// Не удалось сгенерировать уникальный код за MAX_CODE_RETRIES попыток.
    CodeCollision,
    /// Код не найден (не существовал или уже использован).
    NotFound,
    /// Код найден, но TTL истёк.
    Expired,
    /// IP превысил лимит запросов (RATE_LIMIT_MAX_ATTEMPTS за окно).
    RateLimited,
    /// Невалидный формат кода (ожидается NNN-NNN).
    InvalidCode,
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferError::PayloadTooLarge => write!(f, "payload too large"),
            TransferError::StoreFull => write!(f, "transfer store full, try later"),
            TransferError::CodeCollision => write!(f, "failed to generate unique code"),
            TransferError::NotFound => write!(f, "transfer code not found"),
            TransferError::Expired => write!(f, "transfer expired"),
            TransferError::RateLimited => write!(f, "too many attempts, try later"),
            TransferError::InvalidCode => write!(f, "invalid transfer code format"),
        }
    }
}

impl std::error::Error for TransferError {}
