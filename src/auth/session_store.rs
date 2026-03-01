//! Серверное хранилище сессий — EncryptionKey в памяти сервера.
//!
//! # Цель
//!
//! Убрать EncryptionKey из JWT payload.
//! Раньше каждый access_token содержал `ek` (ключ шифрования) — перехват
//! одного токена означал утечку ключа **навсегда** (ключ не меняется пока
//! жив мастер-пароль).
//!
//! Теперь JWT содержит только идентификацию (`sub` + `email`),
//! а ключ шифрования живёт только в оперативной памяти сервера.
//!
//! # Почему не в JWT?
//!
//! JWT путешествует по сети: клиент → сервер → клиент.
//! Каждый hop — потенциальная точка перехвата (логи, прокси, MITM).
//! Серверная память — один процесс, одна машина, нужен root-доступ.
//!
//! # TTL = refresh_token (7 дней), НЕ access_token (15 мин)
//!
//! Почему не 15 минут (как у access_token)?
//! Потому что POST /refresh вызывается **после** истечения access_token.
//! Если запись в мапе живёт 15 мин — к моменту refresh она уже удалена,
//! и ek не найти → refresh сломан → пользователь перелогинивается каждые 15 мин.
//!
//! 7 дней — это время жизни refresh_token. Пока можно обновить токен,
//! ek должен быть доступен.
//!
//! # Ограничения
//!
//! - **In-memory**: при перезапуске сервера все сессии теряются.
//!   Пользователи перелогиниваются. Для персонального менеджера — ОК.
//! - **Один процесс**: HashMap не шарится между инстансами.
//!   Горизонтальное масштабирование потребует Redis/shared store.
//! - **1–5 пользователей**: cleanup O(n) при каждом insert — незаметно.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

use crate::types::EncryptionKey;

use super::jwt_provider::REFRESH_TOKEN_TTL_DAYS;

// ════════════════════════════════════════════════════════════════════
// SessionEntry — одна запись в мапе
// ════════════════════════════════════════════════════════════════════

struct SessionEntry {
    /// Hex-строка ключа шифрования.
    /// `Zeroizing<String>` — зануляется в RAM при удалении из HashMap.
    encryption_key_hex: Zeroizing<String>,
    /// Когда запись протухает (привязана к refresh_token TTL).
    expires_at: DateTime<Utc>,
}

// ════════════════════════════════════════════════════════════════════
// SessionStore
// ════════════════════════════════════════════════════════════════════

/// Потокобезопасное хранилище сессий.
///
/// `Clone` через `Arc` — все handler'ы работают с одним и тем же HashMap.
/// `RwLock` — много читателей (guard → get), редкие писатели (login → insert).
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Сохранить EncryptionKey для пользователя.
    ///
    /// Вызывается при:
    /// - POST /login  — после успешного create_pass()
    /// - POST /refresh — обновить TTL существующей записи
    /// - Basic Auth    — кэшировать ek для будущих JWT-запросов
    ///
    /// Если запись уже существует — перезаписывает (обновляет TTL).
    pub fn insert(&self, user_id: &str, encryption_key: &EncryptionKey) {
        let mut map = self.inner.write().expect("SessionStore lock poisoned");
        self.cleanup_expired(&mut map);
        map.insert(
            user_id.to_string(),
            SessionEntry {
                encryption_key_hex: Zeroizing::new(encryption_key.as_str().to_string()),
                expires_at: Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS),
            },
        );
    }

    /// Достать EncryptionKey по user_id.
    ///
    /// Возвращает `None` если:
    /// - Пользователь не логинился (нет записи)
    /// - Запись протухла (> 7 дней без refresh)
    /// - Сервер перезапускался (HashMap пуст)
    pub fn get(&self, user_id: &str) -> Option<EncryptionKey> {
        let map = self.inner.read().expect("SessionStore lock poisoned");
        let entry = map.get(user_id)?;
        if entry.expires_at < Utc::now() {
            return None;
        }
        Some(EncryptionKey::new((*entry.encryption_key_hex).clone()))
    }

    /// Удалить сессию пользователя.
    ///
    /// Для будущего эндпоинта «выйти везде».
    pub fn remove(&self, user_id: &str) {
        let mut map = self.inner.write().expect("SessionStore lock poisoned");
        map.remove(user_id);
    }

    /// Удалить все протухшие записи.
    ///
    /// Вызывается при каждом `insert()`.
    /// Для 1–5 пользователей — O(n) ≈ мгновенно.
    fn cleanup_expired(&self, map: &mut HashMap<String, SessionEntry>) {
        let now = Utc::now();
        map.retain(|_, entry| entry.expires_at > now);
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ek(hex: &str) -> EncryptionKey {
        EncryptionKey::new(hex.to_string())
    }

    #[test]
    fn insert_and_get() {
        let store = SessionStore::new();
        store.insert("user-1", &make_ek("deadbeef"));

        let ek = store.get("user-1").unwrap();
        assert_eq!(ek.as_str(), "deadbeef");
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = SessionStore::new();
        assert!(store.get("nobody").is_none());
    }

    #[test]
    fn insert_overwrites() {
        let store = SessionStore::new();
        store.insert("user-1", &make_ek("old-key"));
        store.insert("user-1", &make_ek("new-key"));

        let ek = store.get("user-1").unwrap();
        assert_eq!(ek.as_str(), "new-key");
    }

    #[test]
    fn remove_deletes_entry() {
        let store = SessionStore::new();
        store.insert("user-1", &make_ek("deadbeef"));
        store.remove("user-1");

        assert!(store.get("user-1").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let store = SessionStore::new();

        // Вставляем запись с expires_at в прошлом
        {
            let mut map = store.inner.write().unwrap();
            map.insert(
                "user-1".to_string(),
                SessionEntry {
                    encryption_key_hex: Zeroizing::new("deadbeef".to_string()),
                    expires_at: Utc::now() - Duration::seconds(1),
                },
            );
        }

        assert!(store.get("user-1").is_none());
    }

    #[test]
    fn cleanup_removes_expired_on_insert() {
        let store = SessionStore::new();

        // Вставляем протухшую запись напрямую
        {
            let mut map = store.inner.write().unwrap();
            map.insert(
                "expired-user".to_string(),
                SessionEntry {
                    encryption_key_hex: Zeroizing::new("old".to_string()),
                    expires_at: Utc::now() - Duration::seconds(1),
                },
            );
        }

        // insert() триггерит cleanup
        store.insert("fresh-user", &make_ek("new"));

        let map = store.inner.read().unwrap();
        assert!(!map.contains_key("expired-user"));
        assert!(map.contains_key("fresh-user"));
    }

    #[test]
    fn clone_shares_state() {
        let store1 = SessionStore::new();
        let store2 = store1.clone();

        store1.insert("user-1", &make_ek("shared-key"));
        let ek = store2.get("user-1").unwrap();
        assert_eq!(ek.as_str(), "shared-key");
    }
}
