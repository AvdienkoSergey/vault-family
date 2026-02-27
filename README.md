# Vault Family — Type-Safe Password Manager

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
│   ├── lib.rs                  # Library crate: pub mod для всех модулей
│   ├── main.rs                 # Binary crate: тонкая обёртка → cli::run()
│   ├── types.rs                # Макросы branded_no_secret! и branded_secret!
│   ├── crypto_operations.rs    # CryptoProvider trait, RealCrypto, FakeCrypto
│   ├── sqlite.rs               # DB typestate (Closed → Open → Authenticated)
│   ├── password_generator.rs   # Генератор паролей с typestate (Empty → Ready)
│   └── cli.rs                  # CLI интерфейс (clap)
```

Проект разделён на library crate (`lib.rs`) и binary crate (`main.rs`).
Вся логика живёт в библиотеке — бинарник только вызывает `vault_family::cli::run()`.
Это позволяет подключить тот же core через HTTP API без дублирования кода.

### Branded Types

Два макроса создают типы-обёртки вокруг `String`:

```
branded_no_secret!  — открытые данные, безопасно логировать
                      Debug показывает значение
                      Есть Serialize (можно отправить по API)

branded_secret!     — секретные данные, нельзя светить
                      Debug показывает (***)
                      Нет Serialize (нельзя случайно отправить)
                      Нет Clone (нельзя размножить секрет)
                      ZeroizeOnDrop (зануляется в RAM при drop)
```

### Email валидация

```
Email::new(input)    — внутренний конструктор (чтение из БД, тесты)
                       доверяет входным данным

Email::parse(input)  — валидирующий конструктор (CLI, будущий API)
                       trim → пустота? → RFC 5321/5322 → Ok(Email)
                       используется email_address crate
```

CLI всегда вызывает `Email::parse()` — невалидный email отклоняется до запроса пароля.

### Все типы системы

```
TABLE users (SQLite)
├── UserId              branded_no_secret  uuid
├── Email               branded_secret     персональные данные
├── MasterPasswordHash  branded_secret     PBKDF2 хеш
├── AuthSalt            branded_secret     соль для аутентификации
├── EncryptionSalt      branded_secret     соль для ключа шифрования
└── created_at          DateTime<Utc>

TABLE entries (SQLite)
├── EntryId             branded_no_secret  uuid
├── UserId              branded_no_secret  ссылка на users
├── EncryptedData       branded_no_secret  зашифрованный blob (уже безопасен)
├── Nonce               branded_no_secret  nonce для AES-GCM (бесполезен без ключа)
├── created_at          DateTime<Utc>
└── updated_at          DateTime<Utc>

Только в памяти (никогда не в БД)
├── MasterPassword      branded_secret     ввод пользователя
├── EncryptionKey       branded_secret     32 байта, деривируется из MasterPassword
└── EntryPassword       branded_secret     расшифрованный пароль записи

Поля записей
├── ServiceName         branded_no_secret  "Hetzner Cloud"
├── ServiceUrl          branded_no_secret  "https://console.hetzner.com"
└── Login               branded_secret     логин на сервисе (email, username, телефон)
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

## CLI

Мастер-пароль всегда вводится интерактивно (скрытый ввод через rpassword), никогда через аргументы командной строки.

```bash
# Регистрация нового пользователя
vault-family register --email user@example.com

# Добавить запись (пароль вводится интерактивно, --login по умолчанию = email)
vault-family add --email user@example.com --service "GitHub" --url "https://github.com" --login "my-gh-user"

# Добавить запись с автогенерацией пароля (24 символа)
vault-family add --email user@example.com --service "AWS" --url "https://aws.amazon.com" --login "admin" --generate 24

# Список всех записей
vault-family list --email user@example.com

# Просмотр записи (расшифровка)
vault-family view --email user@example.com <entry-id>

# Удалить запись
vault-family delete --email user@example.com <entry-id>

# Сгенерировать пароль (без аутентификации)
vault-family generate --length 20 --lowercase --uppercase --digits --symbols

# Указать путь к БД (по умолчанию ~/Library/Application Support/vault-family/vault.db)
vault-family --db /path/to/vault.db list --email user@example.com
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

## Typestate: PasswordGenerator

```
PasswordGenerator<Empty, N>  →  PasswordGenerator<Ready, N>
       new()                        has_lowercase()
                                    has_uppercase()
                                    has_digits()
                                    has_symbols()
                                    from_flags(...)
                                        │
                                        └── generate() → Password
```

- `N` — минимальная длина пароля (const generic, проверяется в compile-time)
- `generate()` доступен только в состоянии `Ready` (хотя бы один charset включён)
- Builder API: `new().has_lowercase().has_digits().generate()`
- Runtime API: `from_flags(length, lowercase, uppercase, digits, symbols)` — для CLI
- Пресет: `secure()` — 20 символов, все наборы

## Type Safety чек-лист

```
 ✅  1. Branded newtype обёртки (branded_no_secret!, branded_secret!)
 ✅  2. Скрытый Debug для секретов
 ✅  3. Нет Display для секретов
 ✅  4. Приватное поле + new() конструктор
 ✅  5. Typestate для DB (Closed → Open → Authenticated)
 ✅  6. PlainEntry vs EncryptedEntry (нельзя сохранить незашифрованное)
 ✅  7. Нельзя перепутать UserId и EntryId
 ✅  8. Секрет нельзя сериализовать (нет Serialize)
 ✅  9. ZeroizeOnDrop (секреты занулятся в RAM)
 ✅ 10. Typestate для DB (нельзя читать без логина)
 ✅ 11. Email валидация по RFC 5321/5322 (email_address crate)
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

## Тесты

50 unit-тестов покрывают все модули:

```
cargo test

types::tests                      (5 тестов)  — Email::parse()
├── parse_valid_email
├── parse_trims_whitespace
├── parse_empty_fails
├── parse_whitespace_only_fails
└── parse_invalid_rejected

sqlite::tests                     (6 тестов)  — FakeCrypto
├── open_database
├── authenticate
├── wrong_password
├── save_and_read_entry
├── delete_entry
└── user_isolation

crypto_operations::tests          (15 тестов) — RealCrypto
├── generate_salt (hex format, uniqueness)
├── hash_master_password (PHC format, uniqueness)
├── verify_master_password (correct, wrong)
├── derive_encryption_key (hex format, deterministic, salt/password isolation)
└── encrypt/decrypt (roundtrip, different ciphertext, wrong key, invalid key, short key)

password_generator::tests         (24 теста)
├── new (defaults, custom MIN_LENGTH)
├── from_flags (valid, all charsets, no charset panic, length below min panic)
├── length (setter, below min panic)
├── builder chain (has_*, combinations, length + charset)
├── generate (correct length, charset compliance, uniqueness, variety)
└── secure (preset length 20, all charsets)
```

`CryptoProvider` trait позволяет тестировать DB-логику без реальной криптографии:
- `FakeCrypto` (`#[cfg(test)]`) — детерминированный, мгновенный
- `RealCrypto` — PBKDF2 600K итераций, AES-256-GCM (~60с на тест с derive_key)

## Зависимости

```toml
# Core
rusqlite = { version = "0.38", features = ["bundled"] }           # SQLite
uuid = { version = "1.16", features = ["v4"] }                    # ID генерация
chrono = "0.4"                                                     # Даты
serde = { version = "1.0", features = ["derive"] }                # Сериализация
serde_json = "1.0"                                                 # JSON
zeroize = { version = "1.8", features = ["derive"] }              # Зануление RAM

# Криптография
pbkdf2 = { version = "0.12", features = ["password-hash", "simple"] }  # PBKDF2
sha2 = "0.10"                                                           # SHA-256
aes-gcm = "0.10"                                                        # AES-256-GCM
hex = "0.4"                                                              # Hex encode/decode
rand = "0.10"                                                            # Генерация случайных данных

# Валидация
email_address = "0.2"                                              # RFC 5321/5322 email валидация

# CLI
clap = { version = "4.5", features = ["derive"] }                 # Парсинг аргументов
rpassword = "7.4"                                                  # Скрытый ввод пароля
dirs = "6.0"                                                       # Кроссплатформенные пути
```

## CI / CD

### CI

На каждый PR и push в `main` запускаются 4 параллельных job:

```
cargo check    — компиляция
cargo test     — тесты
cargo clippy   — линтер (с -D warnings)
cargo fmt      — форматирование
```

### Релизы (release-please)

Проект использует [release-please](https://github.com/googleapis/release-please) для автоматического семантического версионирования. При push в `main`:

1. Анализируются новые Conventional Commits
2. Создаётся / обновляется Release PR с CHANGELOG
3. При мерже PR — создаётся GitHub Release + git tag
4. Автоматически бампится версия в `Cargo.toml`

### Формат коммитов

```
feat: описание      → bump patch (до v1.0), bump minor (после v1.0)
fix: описание       → bump patch
feat!: описание     → bump minor (до v1.0), bump major (после v1.0)
docs: описание      → в changelog, без bump
chore: описание     → без bump
style: описание     → без bump
```

## Roadmap

- [x] Система типов (branded types, typestate)
- [x] Генератор паролей с typestate
- [x] DB операции (create_user, authenticate, CRUD entries)
- [x] Реализация крипто-операций (PBKDF2, AES-GCM)
- [x] CLI интерфейс (clap + rpassword)
- [x] Library crate (lib.rs) для переиспользования core-логики
- [x] Email валидация по RFC 5321/5322 (email_address crate)
- [x] Unit-тесты (50 тестов: types, sqlite, crypto_operations, password_generator)
- [ ] Web API (axum) для доступа с любого устройства
- [ ] PWA фронтенд с E2E шифрованием в браузере
- [ ] Деплой на Hetzner CX23 Helsinki
- [ ] Браузерное расширение с автозаполнением
