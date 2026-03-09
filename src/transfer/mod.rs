//! Transfer — анонимный in-memory relay для зашифрованных архивов.
//!
//! # Цель
//!
//! Перенос зашифрованного vault-архива между устройствами одного пользователя.
//! Device A: upload(archive) → { code: "847-291" }
//! Device B: download("847-291") → archive (one-time, auto-deleted)
//!
//! # Zero-knowledge
//!
//! Сервер хранит непрозрачный blob (AES-256-GCM от мастер-пароля).
//! Никогда не видит содержимое, не может расшифровать.
//!
//! # In-memory
//!
//! Данные живут только в оперативной памяти. Перезапуск = потеря.
//! Для one-time трансфера (TTL ≤ 15 мин) — это feature, не баг.
//!
//! # Безопасность
//!
//! - Пространство кодов: 1 000 000 (NNN-NNN)
//! - Rate limit: 10 GET-попыток за 5 мин на IP → brute-force ≈ 347 дней
//! - TTL ≤ 15 мин — окно атаки крошечное
//! - copies ≤ 3 — после скачивания слот удаляется
//! - Лимит размера: 15 MB на payload
//! - Лимит слотов: 20 одновременно (worst-case RAM ≈ 300 MB)

pub mod error;

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::types::TransferCode;
pub use error::TransferError;

// ════════════════════════════════════════════════════════════════════
// Константы
// ════════════════════════════════════════════════════════════════════

/// Максимальный TTL, даже если клиент запросит больше.
pub const MAX_TTL_MINUTES: u64 = 15;

/// Максимальное количество скачиваний одного слота.
pub const MAX_COPIES: u32 = 3;

/// Максимальный размер payload в байтах (15 MB).
///
/// Обоснование:
/// - 1000 записей ≈ 3 MB в transport-формате (base64 + hex + AES + JSON).
/// - 15 MB — запас для роста (заметки, вложения, несколько vault-DB).
/// - 20 слотов × 15 MB = 300 MB worst-case RAM.
pub const MAX_PAYLOAD_BYTES: usize = 15 * 1024 * 1024;

/// Максимум одновременных слотов в хранилище.
///
/// 20 слотов — семейный менеджер, 1–5 пользователей, трансфер раз в неделю.
pub const MAX_CONCURRENT_SLOTS: usize = 20;

/// Rate limiter: максимум GET /transfer/{code} попыток с одного IP за окно.
pub const RATE_LIMIT_MAX_ATTEMPTS: u32 = 10;

/// Rate limiter: скользящее окно (секунды).
pub const RATE_LIMIT_WINDOW_SECS: i64 = 300; // 5 минут

/// Интервал фоновой очистки (секунды).
pub const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Максимум попыток генерации уникального кода (коллизии в HashMap).
const MAX_CODE_RETRIES: u32 = 10;

// ════════════════════════════════════════════════════════════════════
// TransferSlot — одна запись в хранилище
// ════════════════════════════════════════════════════════════════════

struct TransferSlot {
    /// Непрозрачный зашифрованный payload (VFARCHIVE1:... строка).
    payload: String,
    /// Оставшееся количество скачиваний. При 0 — слот удаляется.
    copies_remaining: u32,
    /// Когда слот протухает (server-enforced).
    expires_at: DateTime<Utc>,
    /// Размер payload в байтах (кэшируется при вставке).
    payload_bytes: usize,
}

// ════════════════════════════════════════════════════════════════════
// TransferStoreInner — данные за одним RwLock
// ════════════════════════════════════════════════════════════════════

struct TransferStoreInner {
    slots: HashMap<String, TransferSlot>,
    total_bytes: usize,
}

// ════════════════════════════════════════════════════════════════════
// TransferStore
// ════════════════════════════════════════════════════════════════════

/// Потокобезопасное in-memory хранилище трансферов.
///
/// `Clone` через `Arc` — все handler'ы работают с одним HashMap.
/// `RwLock` — много читателей (claim), редкие писатели (insert).
#[derive(Clone)]
pub struct TransferStore {
    inner: Arc<RwLock<TransferStoreInner>>,
}

impl Default for TransferStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TransferStoreInner {
                slots: HashMap::new(),
                total_bytes: 0,
            })),
        }
    }

    /// Вставить новый трансфер-слот.
    ///
    /// Возвращает (TransferCode, expires_at) при успехе.
    /// Ошибки: PayloadTooLarge, StoreFull, CodeCollision.
    pub fn insert(
        &self,
        payload: String,
        ttl_minutes: u64,
        copies: u32,
    ) -> Result<(TransferCode, DateTime<Utc>), TransferError> {
        let payload_bytes = payload.len();
        if payload_bytes > MAX_PAYLOAD_BYTES {
            return Err(TransferError::PayloadTooLarge);
        }

        let ttl = ttl_minutes.min(MAX_TTL_MINUTES);
        let copies = copies.clamp(1, MAX_COPIES);
        let expires_at = Utc::now() + Duration::minutes(ttl as i64);

        let mut store = self.inner.write().expect("TransferStore lock poisoned");

        // Очистка протухших перед вставкой (как SessionStore)
        Self::cleanup_expired_inner(&mut store);

        if store.slots.len() >= MAX_CONCURRENT_SLOTS {
            return Err(TransferError::StoreFull);
        }

        // Генерация уникального кода (retry при коллизии)
        let mut code = TransferCode::generate();
        let mut retries = 0;
        while store.slots.contains_key(code.as_str()) {
            if retries >= MAX_CODE_RETRIES {
                return Err(TransferError::CodeCollision);
            }
            code = TransferCode::generate();
            retries += 1;
        }

        store.slots.insert(
            code.as_str().to_string(),
            TransferSlot {
                payload,
                copies_remaining: copies,
                expires_at,
                payload_bytes,
            },
        );
        store.total_bytes += payload_bytes;

        Ok((code, expires_at))
    }

    /// Забрать payload по коду: декрементирует copies, удаляет при 0.
    ///
    /// Ошибки: NotFound, Expired.
    pub fn claim(&self, code: &TransferCode) -> Result<String, TransferError> {
        let mut store = self.inner.write().expect("TransferStore lock poisoned");
        let now = Utc::now();

        let slot = store
            .slots
            .get_mut(code.as_str())
            .ok_or(TransferError::NotFound)?;

        if slot.expires_at < now {
            let bytes = slot.payload_bytes;
            store.slots.remove(code.as_str());
            store.total_bytes = store.total_bytes.saturating_sub(bytes);
            return Err(TransferError::Expired);
        }

        let payload = slot.payload.clone();
        slot.copies_remaining -= 1;

        if slot.copies_remaining == 0 {
            let bytes = slot.payload_bytes;
            store.slots.remove(code.as_str());
            store.total_bytes = store.total_bytes.saturating_sub(bytes);
        }

        Ok(payload)
    }

    /// Очистить все протухшие слоты. Вызывается фоновым таском.
    pub fn cleanup_expired(&self) {
        let mut store = self.inner.write().expect("TransferStore lock poisoned");
        Self::cleanup_expired_inner(&mut store);
    }

    /// Количество активных слотов (для диагностики).
    pub fn slot_count(&self) -> usize {
        let store = self.inner.read().expect("TransferStore lock poisoned");
        store.slots.len()
    }

    fn cleanup_expired_inner(store: &mut TransferStoreInner) {
        let now = Utc::now();
        let mut freed = 0usize;
        store.slots.retain(|_, slot| {
            if slot.expires_at > now {
                true
            } else {
                freed += slot.payload_bytes;
                false
            }
        });
        store.total_bytes = store.total_bytes.saturating_sub(freed);
    }
}

// ════════════════════════════════════════════════════════════════════
// TransferRateLimiter — per-IP защита от brute-force кодов
// ════════════════════════════════════════════════════════════════════

/// Потокобезопасный rate limiter для GET /transfer/{code}.
///
/// Предотвращает перебор 6-цифровых кодов.
/// Пространство кодов: 1 000 000. При 10 попытках за 5 мин:
/// ожидаемое время угадывания ≈ 347 дней.
///
/// `Clone` через `Arc` — все handler'ы работают с одним HashMap.
#[derive(Clone)]
pub struct TransferRateLimiter {
    inner: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl Default for TransferRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Зафиксировать GET-попытку с данного IP.
    pub fn record_attempt(&self, ip: &str) {
        let mut map = self
            .inner
            .write()
            .expect("TransferRateLimiter lock poisoned");
        let attempts = map.entry(ip.to_string()).or_default();
        Self::cleanup_old(attempts);
        attempts.push(Utc::now());
    }

    /// Превышен ли лимит для данного IP?
    pub fn is_limited(&self, ip: &str) -> bool {
        let map = self
            .inner
            .read()
            .expect("TransferRateLimiter lock poisoned");
        let Some(attempts) = map.get(ip) else {
            return false;
        };
        let cutoff = Utc::now() - Duration::seconds(RATE_LIMIT_WINDOW_SECS);
        let recent = attempts.iter().filter(|t| **t > cutoff).count();
        recent >= RATE_LIMIT_MAX_ATTEMPTS as usize
    }

    /// Очистить все протухшие записи. Вызывается фоновым таском.
    pub fn cleanup_all(&self) {
        let mut map = self
            .inner
            .write()
            .expect("TransferRateLimiter lock poisoned");
        let cutoff = Utc::now() - Duration::seconds(RATE_LIMIT_WINDOW_SECS);
        map.retain(|_, attempts| {
            attempts.retain(|t| *t > cutoff);
            !attempts.is_empty()
        });
    }

    fn cleanup_old(attempts: &mut Vec<DateTime<Utc>>) {
        let cutoff = Utc::now() - Duration::seconds(RATE_LIMIT_WINDOW_SECS);
        attempts.retain(|t| *t > cutoff);
    }
}

// ════════════════════════════════════════════════════════════════════
// Фоновая очистка
// ════════════════════════════════════════════════════════════════════

/// Фоновый цикл очистки протухших слотов и rate limiter записей.
///
/// Запускается один раз через `tokio::spawn` при старте сервера.
/// Интервал: CLEANUP_INTERVAL_SECS (60 сек).
pub async fn cleanup_loop(store: TransferStore, rate_limiter: TransferRateLimiter) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
    loop {
        interval.tick().await;
        store.cleanup_expired();
        rate_limiter.cleanup_all();
        tracing::debug!("transfer cleanup: {} active slots", store.slot_count());
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── TransferCode ──────────────────────────────────────────────

    #[test]
    fn code_generate_format() {
        let code = TransferCode::generate();
        let s = code.as_str();
        assert_eq!(s.len(), 7);
        assert_eq!(&s[3..4], "-");
        assert!(s[..3].chars().all(|c| c.is_ascii_digit()));
        assert!(s[4..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn code_parse_valid() {
        assert!(TransferCode::parse("000-000").is_some());
        assert!(TransferCode::parse("999-999").is_some());
        assert!(TransferCode::parse("847-291").is_some());
        assert!(TransferCode::parse(" 123-456 ").is_some()); // trim
    }

    #[test]
    fn code_parse_invalid() {
        assert!(TransferCode::parse("").is_none());
        assert!(TransferCode::parse("1234567").is_none()); // no dash
        assert!(TransferCode::parse("12-3456").is_none()); // wrong split
        assert!(TransferCode::parse("abc-def").is_none()); // letters
        assert!(TransferCode::parse("12-34-56").is_none()); // too many dashes
        assert!(TransferCode::parse("1234-567").is_none()); // 4-3
    }

    // ── TransferStore ─────────────────────────────────────────────

    #[test]
    fn insert_and_claim() {
        let store = TransferStore::new();
        let (code, _) = store.insert("test-payload".into(), 10, 1).unwrap();

        let payload = store.claim(&code).unwrap();
        assert_eq!(payload, "test-payload");
    }

    #[test]
    fn claim_nonexistent_returns_not_found() {
        let store = TransferStore::new();
        let code = TransferCode::parse("000-000").unwrap();

        let err = store.claim(&code).unwrap_err();
        assert!(matches!(err, TransferError::NotFound));
    }

    #[test]
    fn claim_expired_returns_expired() {
        let store = TransferStore::new();

        // Вставляем слот с expires_at в прошлом
        {
            let mut inner = store.inner.write().unwrap();
            inner.slots.insert(
                "111-222".to_string(),
                TransferSlot {
                    payload: "old".into(),
                    copies_remaining: 1,
                    expires_at: Utc::now() - Duration::seconds(1),
                    payload_bytes: 3,
                },
            );
            inner.total_bytes += 3;
        }

        let code = TransferCode::parse("111-222").unwrap();
        let err = store.claim(&code).unwrap_err();
        assert!(matches!(err, TransferError::Expired));

        // Слот должен быть удалён
        assert_eq!(store.slot_count(), 0);
    }

    #[test]
    fn copies_decrement_and_delete() {
        let store = TransferStore::new();
        let (code, _) = store.insert("payload".into(), 10, 2).unwrap();

        // Первый claim — ОК, слот остаётся (copies=1)
        let p1 = store.claim(&code).unwrap();
        assert_eq!(p1, "payload");
        assert_eq!(store.slot_count(), 1);

        // Второй claim — ОК, слот удаляется (copies=0)
        let p2 = store.claim(&code).unwrap();
        assert_eq!(p2, "payload");
        assert_eq!(store.slot_count(), 0);

        // Третий claim — NotFound
        let err = store.claim(&code).unwrap_err();
        assert!(matches!(err, TransferError::NotFound));
    }

    #[test]
    fn payload_too_large_rejected() {
        let store = TransferStore::new();
        let big = "x".repeat(MAX_PAYLOAD_BYTES + 1);

        let err = store.insert(big, 10, 1).unwrap_err();
        assert!(matches!(err, TransferError::PayloadTooLarge));
    }

    #[test]
    fn store_full_rejected() {
        let store = TransferStore::new();

        for _ in 0..MAX_CONCURRENT_SLOTS {
            store.insert("small".into(), 10, 1).unwrap();
        }

        let err = store.insert("one-too-many".into(), 10, 1).unwrap_err();
        assert!(matches!(err, TransferError::StoreFull));
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = TransferStore::new();

        // Вставляем протухший слот напрямую
        {
            let mut inner = store.inner.write().unwrap();
            inner.slots.insert(
                "expired-code".to_string(),
                TransferSlot {
                    payload: "gone".into(),
                    copies_remaining: 1,
                    expires_at: Utc::now() - Duration::seconds(1),
                    payload_bytes: 4,
                },
            );
            inner.total_bytes += 4;
        }

        // Вставка нового триггерит cleanup
        store.insert("fresh".into(), 10, 1).unwrap();

        let inner = store.inner.read().unwrap();
        assert!(!inner.slots.contains_key("expired-code"));
        assert_eq!(inner.slots.len(), 1);
    }

    #[test]
    fn ttl_clamped_to_max() {
        let store = TransferStore::new();
        let (_, expires_at) = store.insert("data".into(), 999, 1).unwrap();

        let max_expected = Utc::now() + Duration::minutes(MAX_TTL_MINUTES as i64);
        // expires_at должен быть ≤ MAX_TTL_MINUTES от now (с запасом 1 сек)
        assert!(expires_at <= max_expected + Duration::seconds(1));
    }

    #[test]
    fn copies_clamped_to_max() {
        let store = TransferStore::new();
        let (code, _) = store.insert("data".into(), 10, 999).unwrap();

        // Должно быть MAX_COPIES, не 999
        let inner = store.inner.read().unwrap();
        let slot = inner.slots.get(code.as_str()).unwrap();
        assert_eq!(slot.copies_remaining, MAX_COPIES);
    }

    #[test]
    fn clone_shares_state() {
        let store1 = TransferStore::new();
        let store2 = store1.clone();

        let (code, _) = store1.insert("shared".into(), 10, 1).unwrap();
        let payload = store2.claim(&code).unwrap();
        assert_eq!(payload, "shared");
    }

    // ── TransferRateLimiter ───────────────────────────────────────

    #[test]
    fn not_limited_under_threshold() {
        let limiter = TransferRateLimiter::new();
        limiter.record_attempt("1.2.3.4");

        assert!(!limiter.is_limited("1.2.3.4"));
    }

    #[test]
    fn limited_after_max_attempts() {
        let limiter = TransferRateLimiter::new();

        for _ in 0..RATE_LIMIT_MAX_ATTEMPTS {
            limiter.record_attempt("1.2.3.4");
        }

        assert!(limiter.is_limited("1.2.3.4"));
    }

    #[test]
    fn old_attempts_expire() {
        let limiter = TransferRateLimiter::new();

        // Вставляем MAX попыток с временем в прошлом (за окном)
        {
            let mut map = limiter.inner.write().unwrap();
            let old_time = Utc::now() - Duration::seconds(RATE_LIMIT_WINDOW_SECS + 1);
            let attempts: Vec<DateTime<Utc>> =
                (0..RATE_LIMIT_MAX_ATTEMPTS).map(|_| old_time).collect();
            map.insert("1.2.3.4".to_string(), attempts);
        }

        assert!(!limiter.is_limited("1.2.3.4"));
    }

    #[test]
    fn different_ips_isolated() {
        let limiter = TransferRateLimiter::new();

        for _ in 0..RATE_LIMIT_MAX_ATTEMPTS {
            limiter.record_attempt("1.2.3.4");
        }

        assert!(limiter.is_limited("1.2.3.4"));
        assert!(!limiter.is_limited("5.6.7.8"));
    }

    #[test]
    fn clone_shares_limiter_state() {
        let limiter1 = TransferRateLimiter::new();
        let limiter2 = limiter1.clone();

        for _ in 0..RATE_LIMIT_MAX_ATTEMPTS {
            limiter1.record_attempt("1.2.3.4");
        }

        assert!(limiter2.is_limited("1.2.3.4"));
    }
}
