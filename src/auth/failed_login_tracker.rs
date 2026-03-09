//! Защита от brute-force: отслеживание неудачных попыток входа.
//!
//! # Цель
//!
//! Атакующий может бесконечно перебирать мастер-пароль через POST /login
//! или Basic Auth на любом защищённом эндпоинте. Нужно ограничение.
//!
//! # Как работает
//!
//! Счётчик неудачных попыток **по email** в in-memory HashMap.
//! Если за `FAILED_ATTEMPTS_WINDOW_SECS` секунд набралось
//! `MAX_FAILED_ATTEMPTS` попыток — аккаунт блокируется (403 Forbidden).
//!
//! Блокировка **временная**: старые попытки протухают, и доступ
//! восстанавливается автоматически. Сброс при успешном логине не нужен.
//!
//! # Почему email, а не IP?
//!
//! В Axum без reverse proxy IP = 127.0.0.1.
//! Email — реальный идентификатор цели атаки.
//! Если атакуют конкретный аккаунт — блокируем именно его.
//!
//! # Ограничения
//!
//! - **In-memory**: при перезапуске сервера счётчики сбрасываются.
//!   Для персонального менеджера (1–5 пользователей) — ОК.
//! - **Не спасает от distributed brute-force** (разные email).
//!   Для этого нужен rate limiter по IP (tower middleware).

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Максимум неудачных попыток до блокировки.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Окно наблюдения (секунды). Попытки старше этого — не считаются.
pub const FAILED_ATTEMPTS_WINDOW_SECS: i64 = 300; // 5 минут

// ════════════════════════════════════════════════════════════════════
// FailedLoginTracker
// ════════════════════════════════════════════════════════════════════

/// Потокобезопасный трекер неудачных попыток входа.
///
/// `Clone` через `Arc` — все handler'ы работают с одним HashMap.
/// `RwLock` — много читателей (is_locked), редкие писатели (record).
#[derive(Clone)]
pub struct FailedLoginTracker {
    inner: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl Default for FailedLoginTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FailedLoginTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Зафиксировать неудачную попытку входа.
    ///
    /// Вызывается при:
    /// - POST /login с неверным паролем
    /// - Basic Auth с неверным паролем (через guard)
    pub fn record_failed_attempt(&self, email: &str) {
        let mut map = self
            .inner
            .write()
            .expect("FailedLoginTracker lock poisoned");
        let attempts = map.entry(email.to_string()).or_default();
        Self::cleanup_old(attempts);
        attempts.push(Utc::now());
    }

    /// Заблокирован ли аккаунт?
    ///
    /// `true` если количество попыток за окно >= MAX_FAILED_ATTEMPTS.
    pub fn is_locked(&self, email: &str) -> bool {
        let map = self.inner.read().expect("FailedLoginTracker lock poisoned");
        let Some(attempts) = map.get(email) else {
            return false;
        };
        let cutoff = Utc::now() - Duration::seconds(FAILED_ATTEMPTS_WINDOW_SECS);
        let recent = attempts.iter().filter(|t| **t > cutoff).count();
        recent >= MAX_FAILED_ATTEMPTS as usize
    }

    /// Сбросить счётчик при успешном логине.
    ///
    /// Легитимный пользователь с правильным паролем не должен быть
    /// заблокирован из-за чужих неудачных попыток.
    pub fn clear_attempts(&self, email: &str) {
        let mut map = self
            .inner
            .write()
            .expect("FailedLoginTracker lock poisoned");
        map.remove(email);
    }

    /// Удалить попытки старше окна наблюдения.
    fn cleanup_old(attempts: &mut Vec<DateTime<Utc>>) {
        let cutoff = Utc::now() - Duration::seconds(FAILED_ATTEMPTS_WINDOW_SECS);
        attempts.retain(|t| *t > cutoff);
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_check_not_locked() {
        let tracker = FailedLoginTracker::new();
        tracker.record_failed_attempt("alice@example.com");

        assert!(!tracker.is_locked("alice@example.com"));
    }

    #[test]
    fn locked_after_max_attempts() {
        let tracker = FailedLoginTracker::new();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            tracker.record_failed_attempt("alice@example.com");
        }

        assert!(tracker.is_locked("alice@example.com"));
    }

    #[test]
    fn old_attempts_expire() {
        let tracker = FailedLoginTracker::new();

        // Вставляем MAX попыток с временем в прошлом (за окном)
        {
            let mut map = tracker.inner.write().unwrap();
            let old_time = Utc::now() - Duration::seconds(FAILED_ATTEMPTS_WINDOW_SECS + 1);
            let attempts: Vec<DateTime<Utc>> = (0..MAX_FAILED_ATTEMPTS).map(|_| old_time).collect();
            map.insert("alice@example.com".to_string(), attempts);
        }

        assert!(!tracker.is_locked("alice@example.com"));
    }

    #[test]
    fn different_emails_isolated() {
        let tracker = FailedLoginTracker::new();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            tracker.record_failed_attempt("alice@example.com");
        }

        assert!(tracker.is_locked("alice@example.com"));
        assert!(!tracker.is_locked("bob@example.com"));
    }

    #[test]
    fn clear_attempts_unlocks() {
        let tracker = FailedLoginTracker::new();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            tracker.record_failed_attempt("alice@example.com");
        }
        assert!(tracker.is_locked("alice@example.com"));

        tracker.clear_attempts("alice@example.com");
        assert!(!tracker.is_locked("alice@example.com"));
    }

    #[test]
    fn clone_shares_state() {
        let tracker1 = FailedLoginTracker::new();
        let tracker2 = tracker1.clone();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            tracker1.record_failed_attempt("alice@example.com");
        }

        assert!(tracker2.is_locked("alice@example.com"));
    }
}
