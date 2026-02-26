# 🔐 Vault Family — Type-Safe Password Manager

Персональный менеджер паролей с E2E шифрованием, построенный на принципах type-driven development в Rust.

## Принципы

Компилятор — главный охранник. Система типов гарантирует:

- Незашифрованные пароли не попадут в базу данных
- Зашифрованные blob'ы не покажутся пользователю без расшифровки
- `UserId` нельзя перепутать с `EntryId`
- Секреты не утекут в логи через `Debug` или `Display`
- Секреты занулятся в памяти при уничтожении (`ZeroizeOnDrop`)
- Нельзя читать записи без аутентификации (typestate)

## Архитектура

### Модули

```
vault-family/
├── src/
│   ├── main.rs                 # Точка входа
│   ├── types.rs                # Макросы branded_id! и branded_secret!
│   ├── vault_store.rs          # Branded types, структуры, DB операции
│   ├── crypto_operations.rs    # Хеширование, шифрование, деривация
│   └── password_generator.rs   # Генератор паролей с typestate
```

### Branded Types

Два макроса создают типы-обёртки вокруг `String`:

```
branded_id!       — открытые данные, безопасно логировать
                    Debug показывает значение
                    Есть Serialize (можно отправить по API)

branded_secret!   — секретные данные, нельзя светить
                    Debug показывает (***)
                    Нет Serialize (нельзя случайно отправить)
                    Нет Clone (нельзя размножить секрет)
                    ZeroizeOnDrop (зануляется в RAM при drop)
```

### Все типы системы

```
TABLE users (SQLite)
├── UserId              branded_id      uuid
├── Email               branded_secret  персональные данные
├── MasterPasswordHash  branded_secret  PBKDF2 хеш
├── AuthSalt            branded_secret  соль для аутентификации
├── EncryptionSalt      branded_secret  соль для ключа шифрования
└── created_at          DateTime<Utc>

TABLE entries (SQLite)
├── EntryId             branded_id      uuid
├── UserId              branded_id      ссылка на users
├── EncryptedData       branded_id      зашифрованный blob (уже безопасен)
├── Nonce               branded_id      nonce для AES-GCM (бесполезен без ключа)
├── created_at          DateTime<Utc>
└── updated_at          DateTime<Utc>

Только в памяти (никогда не в БД)
├── MasterPassword      branded_secret  ввод пользователя
├── EncryptionKey       branded_secret  32 байта, деривируется из MasterPassword
└── EntryPassword       branded_secret  расшифрованный пароль записи

Поля записей
├── ServiceName         branded_id      "Hetzner Cloud"
└── ServiceUrl          branded_id      "https://console.hetzner.com"
```

### Доменные структуры

```
User                    строка из TABLE users
PlainEntry              расшифрованная запись (только в памяти)
EncryptedEntry          зашифрованная запись (TABLE entries)
AuthSession             User + EncryptionKey (результат логина)
```

## Криптография

### Две соли — зачем

```
MasterPassword ──┬── + AuthSalt       → MasterPasswordHash
                 │                       хранится в БД
                 │                       используется для проверки пароля
                 │
                 └── + EncryptionSalt  → EncryptionKey
                                         НЕ хранится в БД
                                         живёт только в RAM
                                         используется для AES-GCM
```

Разделение нужно чтобы:
- Можно сменить способ аутентификации (добавить 2FA) не перешифровывая весь vault
- Утечка хеша аутентификации не даёт готовый ключ шифрования

### Регистрация (create_user)

```
Ввод: Email + MasterPassword
                │
                ├─ hash_master_password(&password)
                │    PBKDF2(password, random AuthSalt, 600K итераций)
                │    → (MasterPasswordHash, AuthSalt)
                │
                ├─ generate_salt()
                │    → EncryptionSalt (случайные 16 байт)
                │
                └─ INSERT INTO users (id, email, hash, auth_salt, enc_salt, created_at)

MasterPassword → drop → ZeroizeOnDrop → нули в RAM
```

### Логин (authenticate)

```
Ввод: Email + MasterPassword
                │
                ├─ SELECT FROM users WHERE email = ?
                │    → User (с hash, auth_salt, encryption_salt)
                │
                ├─ verify_master_password(&password, &hash, &auth_salt)
                │    PBKDF2(password, auth_salt) == hash ?
                │    false → Err(AuthError)
                │    true  ↓
                │
                ├─ derive_encryption_key(&password, &encryption_salt)
                │    PBKDF2(password, encryption_salt, 600K итераций)
                │    → EncryptionKey (32 байта)
                │
                └─ AuthSession { user, key }

MasterPassword → drop → ZeroizeOnDrop → нули в RAM
EncryptionKey живёт пока живёт AuthSession
```

### Сохранение пароля

```
PlainEntry (в памяти)
    │
    ├─ encrypt_entry(&plain, &session.key)
    │    JSON(PlainEntry) → AES-256-GCM(key, new Nonce) → base64
    │    → EncryptedEntry { encrypted_data, nonce }
    │
    └─ db.save_entry(&encrypted)
         INSERT INTO entries

Компилятор не даст: db.save_entry(&plain_entry)
    ошибка: expected &EncryptedEntry, found &PlainEntry
```

### Чтение пароля

```
db.list_entries()
    SELECT FROM entries WHERE user_id = ?
    → Vec<EncryptedEntry>
         │
         ├─ decrypt_entry(&encrypted, &session.key)
         │    base64 → AES-256-GCM decrypt(key, nonce) → JSON → PlainEntry
         │
         └─ plain.password.as_str()  ← явный доступ к секрету
            println!("{:?}", plain.password) → "EntryPassword(***)"
```

## Typestate: DB

```
DB<Closed>  →  DB<Open>  →  DB<Authenticated>
   new()         open()        authenticate()
                    │               │
                    │               ├── save_entry()
                    ├── create_user()   list_entries()
                    ├── authenticate()  delete_entry()
                    │
                    │  Нельзя:
                    │  db_open.save_entry()     ← ошибка компиляции
                    │  db_closed.create_user()  ← ошибка компиляции
```

Каждый переход **потребляет** предыдущее состояние (move semantics).
После `authenticate()` нельзя вызвать `create_user()` — `DB<Open>` больше не существует.

### Associated Types вместо Option

```rust
trait ConnectionState {
    type Conn;       // () для Closed, Connection для Open/Authenticated
    type Session;    // () для Closed/Open, AuthSession для Authenticated
}
```

`DB<Closed>` физически не содержит `Connection` — там `()`.
Никакого `Option`, никакого ослабления типов.

## Type Safety чек-лист

```
 ✅  1. Branded newtype обёртки (нельзя передать String)
 ✅  2. Скрытый Debug для секретов
 ✅  3. Нет Display для секретов
 ✅  4. Приватное поле + new() конструктор
 ✅  5. Typestate для DB (Closed → Open → Authenticated)
 ✅  6. PlainEntry vs EncryptedEntry (нельзя сохранить незашифрованное)
 ✅  7. Нельзя перепутать UserId и EntryId
 ✅  8. Секрет нельзя сериализовать (нет Serialize)
 ✅  9. ZeroizeOnDrop (секреты занулятся в RAM)
 ✅ 10. Typestate для DB (нельзя читать без логина)
```

## Крипто-операции

```rust
// Регистрация
hash_master_password(&MasterPassword) → (MasterPasswordHash, AuthSalt)
generate_salt() → EncryptionSalt

// Логин
verify_master_password(&MasterPassword, &MasterPasswordHash, &AuthSalt) → bool
derive_encryption_key(&MasterPassword, &EncryptionSalt) → EncryptionKey

// Работа с записями
encrypt_entry(&PlainEntry, &EncryptionKey) → EncryptedEntry
decrypt_entry(&EncryptedEntry, &EncryptionKey) → PlainEntry
```

## Зависимости

```toml
rusqlite = { version = "0.31", features = ["bundled"] }  # SQLite
uuid = { version = "1.6", features = ["v4"] }            # ID генерация
chrono = { version = "0.4", features = ["serde"] }       # Даты
serde = { version = "1.0", features = ["derive"] }       # Сериализация
serde_json = "1.0"                                        # JSON
zeroize = { version = "1", features = ["derive"] }        # Зануление RAM
ring = "0.17"                                              # PBKDF2
aes-gcm = "0.10"                                           # AES-256-GCM
rand = "0.8"                                               # Генерация случайных данных
```

## Roadmap

- [x] Система типов (branded types, typestate)
- [x] Генератор паролей с typestate
- [x] DB операции (create_user, authenticate, CRUD entries)
- [ ] Реализация крипто-операций (PBKDF2, AES-GCM)
- [ ] CLI интерфейс
- [ ] Web API (axum) для доступа с любого устройства
- [ ] PWA фронтенд с E2E шифрованием в браузере
- [ ] Деплой на Hetzner CX23 Helsinki
- [ ] Браузерное расширение с автозаполнением
