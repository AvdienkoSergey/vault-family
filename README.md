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
- `auth/` и `vault/` не зависят друг от друга — мост между ними `VaultPass`

## Архитектура: Guard → Pass → Storage

```
┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐
│   Guard     │ ───► │   Pass      │ ───► │     Storage         │
│   (auth/)   │      │ (VaultPass) │      │ (vault/)            │
│             │      │             │      │                     │
│ JWT, Basic, │      │ user_id     │      │ users, entries      │
│ OAuth, ...  │      │ email       │      │ encrypt/decrypt     │
│             │      │ enc_key     │      │ CRUD                │
│ auth.db     │      │ scope (fut) │      │ vault.db            │
└─────────────┘      └─────────────┘      └─────────────────────┘
```

**Guard** (`auth/`) проверяет личность, выдаёт **Pass** (`VaultPass`).
С **Pass** входишь в **Storage** (`vault/`) и работаешь с данными.
Storage не знает КАК ты получил пропуск — оно только проверяет что Pass валиден.

### Матрица зависимостей

```
             auth/    types.rs    vault/    http_api/    cli.rs
auth/          -      VaultPass     -          -           -
vault/         -      VaultPass     -          -           -
http_api/    guard()  VaultPass   enter()      -           -
cli.rs         -      VaultPass   create_pass  -           -
                                  + enter()
```

- `auth/` и `vault/` не зависят друг от друга
- Оба зависят только от `types.rs` (VaultPass)
- `http_api/` зависит от обоих через VaultPass
- `cli.rs` зависит только от vault (без auth — пароль вводится напрямую)

### Модули

```
vault-family/
├── src/
│   ├── lib.rs                  # Library crate: pub mod для всех модулей
│   ├── main.rs                 # Binary crate: тонкая обёртка → cli::run()
│   ├── types.rs                # Макросы branded types + VaultPass (Пропуск)
│   ├── crypto_operations.rs    # CryptoProvider trait, RealCrypto, FakeCrypto
│   ├── password_generator.rs   # Генератор паролей с typestate (Empty → Ready)
│   ├── cli.rs                  # CLI интерфейс (clap)
│   ├── auth/                   # Guard — аутентификация и сессии
│   │   ├── mod.rs              #   guard() — единая точка входа, AuthError
│   │   ├── session_store.rs    #   SessionStore — EncryptionKey в памяти сервера
│   │   ├── failed_login_tracker.rs #   Brute-force защита (счётчик неудачных попыток)
│   │   ├── jwt_provider.rs     #   JWT Claims, create/decode access tokens
│   │   ├── jwt_secret.rs       #   Загрузка/генерация JWT secret
│   │   ├── jwt_store.rs        #   AuthStore — refresh_tokens в auth.db
│   │   ├── jwt_types.rs        #   JwtSecret, RefreshTokenHash (branded types)
│   │   └── basic_provider.rs   #   Basic Auth extraction
│   ├── vault/                  # Storage — пользователи и записи
│   │   └── mod.rs              #   DB typestate (Closed → Open → Authenticated)
│   └── http_api/               # Тонкий HTTP слой (axum)
│       ├── mod.rs              #   Router, AppState, run_server
│       └── handlers.rs         #   Handler-функции для всех endpoints
```

Проект разделён на library crate (`lib.rs`) и binary crate (`main.rs`).
Вся логика живёт в библиотеке — бинарник только вызывает `vault_family::cli::run()`.
Это позволяет подключить тот же core через HTTP API без дублирования кода.

### Отдельные базы данных

```
{data_dir}/vault-family/
├── vault.db          ← users + entries (Storage)
├── auth.db           ← refresh_tokens (Guard)
└── .jwt_secret       ← HMAC ключ подписи
```

`vault.db` не знает про JWT и refresh-токены. `auth.db` не знает про записи и шифрование.
EncryptionKey живёт только в `SessionStore` (оперативная память сервера) — не в БД и не в JWT.

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
vault.db — TABLE users
├── UserId              branded_no_secret  uuid
├── Email               branded_secret     персональные данные
├── MasterPasswordHash  branded_secret     PBKDF2 хеш
├── AuthSalt            branded_secret     соль для аутентификации
├── EncryptionSalt      branded_secret     соль для ключа шифрования
└── created_at          DateTime<Utc>

vault.db — TABLE entries
├── EntryId             branded_no_secret  uuid
├── UserId              branded_no_secret  ссылка на users
├── EncryptedData       branded_no_secret  зашифрованный blob (уже безопасен)
├── Nonce               branded_no_secret  nonce для AES-GCM (бесполезен без ключа)
├── created_at          DateTime<Utc>
└── updated_at          DateTime<Utc>

auth.db — TABLE refresh_tokens
├── RefreshTokenHash    branded_secret     SHA-256 хэш токена (PK)  [auth/jwt_types.rs]
├── UserId              branded_no_secret  ссылка на users
└── expires_at          DateTime<Utc>

Только в памяти (никогда не в БД)
├── MasterPassword      branded_secret     ввод пользователя
├── EncryptionKey       branded_secret     32 байта, деривируется из MasterPassword
└── EntryPassword       branded_secret     расшифрованный пароль записи

JWT / Сессии (auth/)
├── JwtSecret           branded_secret     ключ подписи HMAC-SHA256  [auth/jwt_types.rs]
├── RefreshTokenHash    branded_secret     SHA-256 хэш в auth.db    [auth/jwt_types.rs]
└── SessionStore        Arc<RwLock<HashMap>>  EncryptionKey в памяти сервера  [auth/session_store.rs]

VaultPass — Пропуск (types.rs)
├── user_id             UserId
├── email               Email
└── encryption_key      EncryptionKey
    Не Clone, не Serialize, EncryptionKey → ZeroizeOnDrop

Поля записей
├── ServiceName         branded_no_secret  "Hetzner Cloud"
├── ServiceUrl          branded_no_secret  "https://console.hetzner.com"
└── Login               branded_secret     логин на сервисе (email, username, телефон)
```

### Доменные структуры

```
User                    полная строка из TABLE users (используется при регистрации)
SessionUser             id + email (минимум для активной сессии, без хэшей и солей)
PlainEntry              расшифрованная запись (только в памяти)
EncryptedEntry          зашифрованная запись (TABLE entries)
AuthSession             SessionUser + EncryptionKey (результат аутентификации)
VaultPass               Пропуск: user_id + email + encryption_key (мост auth ↔ vault)
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

### Логин (create_pass)

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
                └─ VaultPass { user_id, email, encryption_key }

MasterPassword → drop → ZeroizeOnDrop → нули в RAM
EncryptionKey живёт внутри VaultPass до enter()
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

## Потоки данных

### POST /login (Guard выдаёт пропуск)

```
Request { email, password }
  │
  ▼
vault_db.create_pass(email, password)     ← vault.db: verify password, derive key
  │
  ▼
VaultPass { user_id, email, encryption_key }
  │
  ├─► session_store.insert(user_id, ek)   ← ek в память сервера (TTL = 7 дней)
  ├─► jwt::create_access_token(user_id, email)  ← JWT без ek
  ├─► auth_store.save_refresh_token(...)   ← auth.db: сохранить hash
  │
  ▼
Response { access_token, refresh_token }
```

### GET /list (Пропуск → Хранилище)

```
Request + "Authorization: Bearer {jwt}"
  │
  ▼
auth::guard(headers, jwt_secret, session_store, verify)
  │  JWT path: decode JWT → session_store.get(sub) → ek
  │  Basic path: verify(email, pw) → session_store.insert(user_id, ek)
  │
  ▼
VaultPass { user_id, email, encryption_key }
  │
  ▼
vault_db.enter(pass)                      ← vault.db: verify user exists
  │
  ▼
DB<Authenticated> → list_entries() → decrypt()
  │
  ▼
Response [{ entry_id, service_name }]
```

### POST /refresh (только Guard, Хранилище не трогаем)

```
Request { old_access_token, refresh_token }
  │
  ├─► jwt::decode_allow_expired(old_token) → Claims { sub, email }
  ├─► auth_store.verify_and_delete(hash)   ← auth.db: rotation
  ├─► session_store.get(sub) → ek          ← достать ek из памяти
  │
  ▼
  ├─► session_store.insert(sub, ek)        ← продлить TTL
  ├─► jwt::create_access_token(sub, email) ← новый JWT (без ek)
  ├─► auth_store.save_refresh_token(...)   ← auth.db: новый hash
  │
  ▼
Response { new_access_token, new_refresh_token }
```

Заметь: refresh_handler не открывает vault.db! Он работает с auth.db, JWT и SessionStore.

### CLI (прямой путь, без Guard)

```
$ vault-family list --email alex@icloud.com
  │
  ▼
rpassword::prompt("Master password: ")
  │
  ▼
vault_db.create_pass(email, password)     ← vault.db
  │
  ▼
VaultPass { user_id, email, encryption_key }
  │
  ▼
vault_db.enter(pass)                      ← vault.db
  │
  ▼
DB<Authenticated> → list_entries()
```

## CLI

Мастер-пароль всегда вводится интерактивно (скрытый ввод через rpassword), никогда через аргументы командной строки.
CLI идёт напрямую в Storage (vault/) потому что у него уже есть то что проверяет Guard (auth/) - живой пароль от пользователя

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

# Запустить HTTP-сервер (по умолчанию 127.0.0.1:3000)
vault-family serve
vault-family serve --host 0.0.0.0 --port 8080
```

## HTTP API

HTTP API — полное зеркало CLI. Аутентификация через JWT-сессии (access + refresh токены). Basic Auth сохранён как fallback для CLI-совместимости.

### Аутентификация

```
POST /login  →  {access_token (JWT, 15 мин), refresh_token (opaque, 7 дней)}

Защищённые эндпоинты принимают:
  1. Authorization: Bearer <access_token>     ← PWA/мобильное приложение
  2. Authorization: Basic <base64>            ← CLI fallback

POST /refresh  →  новая пара {access_token, refresh_token}
  Принимает: {refresh_token, access_token (истёкший)}
  Rotation: старый refresh_token удаляется из auth.db
```

#### guard() — единая точка входа

```rust
auth::guard(&headers, &jwt_secret, &session_store, &failed_login_tracker, |email, password| {
    vault_db.create_pass(email, password)
})
```

`guard()` пробует Bearer JWT (быстрый путь: decode JWT → `session_store.get(sub)` → ek), при неудаче — извлекает Basic Auth credentials и вызывает `verify` callback. При Basic Auth кэширует ek в SessionStore для будущих JWT-запросов. Closure-based DI: auth/ не зависит от vault/ напрямую.

**Brute-force защита:** перед проверкой пароля `guard()` проверяет `tracker.is_locked(email)`. При неудачной попытке — `tracker.record_failed_attempt(email)`. После `MAX_FAILED_ATTEMPTS` (5) неудачных попыток за `FAILED_ATTEMPTS_WINDOW_SECS` (300 сек) — возвращает `AuthError::AccountLocked` → 403 Forbidden. Блокировка временная, старые попытки протухают автоматически.

#### JWT Claims (access_token)

```
{ sub: "user-uuid", email: "...", exp: unix_timestamp }
```

JWT содержит только идентификацию — **без секретов**. EncryptionKey хранится в `SessionStore` (серверная память), не путешествует по сети.

#### SessionStore — серверное хранилище сессий

```
SessionStore: Arc<RwLock<HashMap<String, SessionEntry>>>

SessionEntry {
    encryption_key_hex: Zeroizing<String>,   ← зануляется при удалении
    expires_at: DateTime<Utc>,               ← TTL = 7 дней (refresh_token)
}
```

**Почему TTL = 7 дней, а не 15 минут (как access_token)?**
POST /refresh вызывается **после** истечения access_token. Если запись в SessionStore живёт 15 мин — к моменту refresh она уже удалена, ek не найти, refresh сломан. 7 дней — время жизни refresh_token. Пока можно обновить токен, ek должен быть доступен.

**Ограничения:**
- In-memory: при перезапуске сервера все сессии теряются (пользователи перелогиниваются)
- Один процесс: HashMap не шарится между инстансами (горизонтальное масштабирование → Redis)
- 1–5 пользователей: cleanup O(n) при каждом insert — незаметно

#### FailedLoginTracker — brute-force защита

```
FailedLoginTracker: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>

Ключ:     email (String)
Значение: Vec<DateTime<Utc>> — временны́е метки неудачных попыток

Константы:
  MAX_FAILED_ATTEMPTS       = 5       попыток
  FAILED_ATTEMPTS_WINDOW_SECS = 300   секунд (5 минут)
```

**Где проверяется:**
- `guard()` — Basic Auth путь (перед `verify`, после неудачного `verify`)
- `login_handler` — перед `create_pass()`, после неудачного `create_pass()`
- Bearer JWT — **не проверяется** (нет пароля → нет brute-force)

**Поведение:** 5 неудачных попыток за 5 минут → 403 Forbidden. Блокировка временная — старые попытки протухают по TTL. Сброс при успешном логине не нужен.

**Ограничения:**
- In-memory: при перезапуске сервера счётчики сбрасываются
- По email, не по IP (в Axum без reverse proxy IP = 127.0.0.1)
- Не защищает от distributed brute-force (разные email) — для этого нужен rate limiter по IP

#### JWT Secret

Загрузка при старте сервера (приоритет):

```
1. env JWT_SECRET          → production (задаётся в docker-compose.yml)
2. файл {db_dir}/.jwt_secret  → development (создаётся автоматически)
3. генерация 64 random bytes  → первый запуск (сохраняется в файл)
```

#### Refresh Token Rotation

```
Клиент → POST /refresh {refresh_token, access_token}
Сервер:
  1. Декодирует access_token БЕЗ проверки exp (подпись проверяется) → { sub, email }
  2. SHA-256(refresh_token) → ищет в auth.db
  3. Удаляет использованный refresh_token (rotation)
  4. session_store.get(sub) → ek (или 401 если сервер перезапустился)
  5. session_store.insert(sub, ek) → продлить TTL
  6. Создаёт новую пару access + refresh (JWT без ek)
  7. Возвращает клиенту
```

Rotation защищает от кражи: если атакующий использует украденный refresh_token, легитимный пользователь получит ошибку при следующем refresh.

### Endpoints

```
GET    /health              — проверка жизни сервера (без аутентификации)
POST   /register            — регистрация нового пользователя (JSON body)
POST   /login               — аутентификация, получение токенов (JSON body)
POST   /logout              — мгновенная revocation сессии (Bearer)
POST   /refresh             — обновление токенов (JSON body)
POST   /add                 — добавить запись (Bearer / Basic + JSON body)
GET    /list                — список всех записей (Bearer / Basic)
GET    /view/{id}           — просмотр записи с расшифровкой (Bearer / Basic)
DELETE /delete/{id}         — удалить запись (Bearer / Basic)
GET    /generate            — генерация пароля (без аутентификации, query params)
```

### Примеры

```bash
# Регистрация
curl -X POST http://127.0.0.1:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "master_password": "Secret123!"}'

# Логин (получить токены)
curl -X POST http://127.0.0.1:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "master_password": "Secret123!"}'
# → {"access_token": "eyJ...", "refresh_token": "550e8400-..."}

# Добавить запись (Bearer JWT)
curl -X POST http://127.0.0.1:3000/add \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"service_name":"GitHub","service_url":"https://github.com","login":"myuser","password":"ghpass123","notes":"work"}'

# Список записей (Bearer JWT)
curl -H "Authorization: Bearer eyJ..." http://127.0.0.1:3000/list

# Список записей (Basic Auth fallback для CLI)
curl -u "user@example.com:Secret123!" http://127.0.0.1:3000/list

# Просмотр записи
curl -H "Authorization: Bearer eyJ..." http://127.0.0.1:3000/view/<entry-id>

# Удалить запись
curl -H "Authorization: Bearer eyJ..." -X DELETE http://127.0.0.1:3000/delete/<entry-id>

# Logout (мгновенная revocation — убивает сессию + все refresh-токены)
curl -X POST http://127.0.0.1:3000/logout \
  -H "Authorization: Bearer eyJ..."
# → после logout Bearer → 401, refresh → 401

# Обновить токены
curl -X POST http://127.0.0.1:3000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "550e8400-...", "access_token": "eyJ..."}'

# Генерация пароля (все параметры опциональны)
curl "http://127.0.0.1:3000/generate?length=32&symbols=false"
```

### Архитектурные решения

- **Guard → Pass → Storage** — auth/ и vault/ полностью развязаны, мост между ними — VaultPass
- **Closure-based DI** — `guard()` принимает `FnOnce` callback, auth/ не зависит от vault/
- **Отдельные БД** — vault.db (users + entries), auth.db (refresh_tokens), .jwt_secret
- **JWT-сессии** — master_password передаётся только при `/login`; все последующие запросы используют краткосрочный access_token (15 мин)
- **Bearer + Basic fallback** — PWA использует JWT, CLI может использовать Basic Auth для обратной совместимости
- **Server-side session store** — EncryptionKey хранится в памяти сервера (`SessionStore`), не в JWT payload. JWT содержит только идентификацию (`sub` + `email`). Перехват токена не даёт ключ шифрования
- **Instant revocation** — POST /logout убивает сессию (`session_store.remove`) + все refresh-токены (`auth.db DELETE`). Старые JWT → 401 мгновенно, без ожидания exp
- **Brute-force защита** — `FailedLoginTracker` считает неудачные попытки по email. 5 попыток за 5 минут → 403 Forbidden. In-memory, конфигурируется через `const`
- **Refresh rotation** — каждый `/refresh` инвалидирует старый токен, защищая от кражи
- **spawn_blocking** — все DB-операции в blocking closure, т.к. `rusqlite::Connection` не реализует `Send`
- **Typestate сохранён** — каждый запрос проходит lifecycle: `DB<Closed> → DB<Open> → enter(VaultPass) → DB<Authenticated> → drop`
- **Tracing** — `tower_http::TraceLayer` логирует метод, путь, статус и latency каждого запроса

### Проверка корректности SessionStore

```bash
# 1. Login → Bearer request (ek из SessionStore)
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","master_password":"Secret123!"}' \
  | jq -r '.access_token')

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/list
# → 200 OK, список записей (ek достан из SessionStore)

# 2. Bearer без session entry → 401 (SessionExpired)
# Перезапустить сервер, затем:
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/list
# → 401 Unauthorized (JWT валиден, но SessionStore пуст — сервер перезапустился)

# 3. Basic Auth → Bearer request (basic кэширует ek, JWT его читает)
curl -u "user@example.com:Secret123!" http://127.0.0.1:3000/list
# → 200 OK + ek закэширован в SessionStore
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/list
# → 200 OK (после re-login ek снова в SessionStore)

# 4. Refresh → Bearer request (ek переживает refresh)
REFRESH=$(curl -s -X POST http://127.0.0.1:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","master_password":"Secret123!"}' \
  | jq -r '.refresh_token')

# Дождаться истечения access_token (15 мин) или использовать старый:
NEW_TOKEN=$(curl -s -X POST http://127.0.0.1:3000/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\",\"access_token\":\"$TOKEN\"}" \
  | jq -r '.access_token')

curl -H "Authorization: Bearer $NEW_TOKEN" http://127.0.0.1:3000/list
# → 200 OK (ek по-прежнему в SessionStore, TTL продлён)

# 5. JWT payload не содержит ek
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null
# → {"sub":"...","email":"...","exp":...}  ← нет поля "ek"
```

## Typestate: DB

```
DB<Closed>  →  DB<Open>  →  DB<Authenticated>
   new()         open()        create_pass()       ← выдать VaultPass (&self, не потребляет)
                    │           enter(VaultPass)     ← войти в хранилище (self, потребляет)
                    │               │
                    │               ├── save_entry()
                    ├── create_user()   list_entries()
                    ├── create_pass()   delete_entry()
                    │                   encrypt() / decrypt()
                    │  Нельзя:
                    │  db_open.save_entry()     ← ошибка компиляции
                    │  db_closed.create_user()  ← ошибка компиляции
```

Два пути в `Authenticated`:
- **CLI:** `create_pass(email, password)` → `VaultPass` → `enter(pass)` — проверяет PBKDF2, деривирует encryption_key, возвращает VaultPass. Заимствует `&self` (не потребляет DB).
- **HTTP (JWT):** `auth::guard(headers, jwt_secret, session_store, ...)` → decode JWT → `session_store.get(sub)` → `VaultPass` → `enter(pass)`
- **HTTP (Basic):** `auth::guard(headers, jwt_secret, session_store, |email, pw| db.create_pass(email, pw))` → `VaultPass` + кэширует ek в SessionStore → `enter(pass)`

`create_pass(&self)` **заимствует** DB, `enter(self)` **потребляет** DB (move semantics). Это позволяет создать VaultPass и затем войти в хранилище двумя отдельными шагами.

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
 ✅ 10. VaultPass — единый контракт между auth/ и vault/
 ✅ 11. Email валидация по RFC 5321/5322 (email_address crate)
 ✅ 12. auth/ и vault/ не зависят друг от друга (dependency inversion через closure)
 ✅ 13. EncryptionKey не в JWT — хранится в SessionStore (Zeroizing, серверная память)
 ✅ 14. Brute-force защита — FailedLoginTracker блокирует аккаунт по email (403)
```

## Крипто-операции

```rust
// Регистрация
hash_master_password(&MasterPassword) → (MasterPasswordHash, AuthSalt)
generate_salt() → EncryptionSalt

// Логин (create_pass)
verify_master_password(&MasterPassword, &MasterPasswordHash, &AuthSalt) → bool
derive_encryption_key(&MasterPassword, &EncryptionSalt) → EncryptionKey

// Работа с записями
encrypt_entry(&PlainEntry, &EncryptionKey) → EncryptedEntry
decrypt_entry(&EncryptedEntry, &EncryptionKey) → PlainEntry
```

## Расширяемость

### Отключить JWT?
- Удалить `auth/jwt_provider.rs`, `auth/jwt_secret.rs`, `auth/jwt_store.rs`
- Убрать маршруты `/login`, `/refresh`
- В `guard()` оставить только Basic Auth
- **Vault не трогаем вообще.** 0 изменений в хранилище.

### Добавить OAuth?
- Добавить `auth/oauth_provider.rs`
- В `guard()` добавить ветку для OAuth Bearer
- **Vault не трогаем.**

### Добавить Family Share?
- Расширить VaultPass полем `scope: AccessScope`
- Vault проверяет `pass.scope` перед операциями
- Guard определяет scope при аутентификации
- **Auth и Vault меняются минимально, контракт — VaultPass.**

## Тесты

118 unit-тестов покрывают все модули:

```
cargo test

types::tests                              (8 тестов)  — Email::parse() + VaultPass
├── parse_valid_email
├── parse_trims_whitespace
├── parse_empty_fails
├── parse_whitespace_only_fails
├── parse_invalid_rejected
├── vault_pass_accessors
├── vault_pass_into_parts
└── vault_pass_debug_hides_secrets

auth::tests                               (9 тестов)  — guard() единая точка входа + brute-force
├── guard_jwt_valid_token
├── guard_jwt_without_session_returns_session_expired
├── guard_jwt_invalid_token
├── guard_basic_auth_calls_verify
├── guard_basic_auth_verify_fails
├── guard_no_auth_header
├── guard_basic_auth_locked_returns_account_locked
├── guard_basic_auth_records_failed_attempt
└── auth_db_path_from_vault_path

auth::basic_provider::tests               (4 теста)   — Basic Auth extraction
├── extract_basic_valid
├── extract_basic_missing_header_fails
├── extract_basic_no_colon_fails
└── extract_basic_bearer_header_fails

auth::jwt_provider::tests                 (6 тестов)  — JWT encode/decode
├── create_and_decode_roundtrip
├── create_from_pass_roundtrip
├── decode_rejects_wrong_secret
├── decode_rejects_expired_token
├── decode_allow_expired_accepts_expired
└── decode_allow_expired_rejects_wrong_secret

auth::jwt_store::tests                    (6 тестов)  — AuthStore (auth.db)
├── save_and_verify_refresh_token
├── verify_deletes_token_rotation
├── verify_expired_token_fails
├── verify_nonexistent_token_fails
├── delete_all_user_tokens_clears_tokens
└── delete_all_user_tokens_does_not_affect_other_users

auth::failed_login_tracker::tests         (5 тестов)  — Brute-force защита
├── record_and_check_not_locked
├── locked_after_max_attempts
├── old_attempts_expire
├── different_emails_isolated
└── clone_shares_state

auth::session_store::tests               (7 тестов)  — SessionStore (серверная память)
├── insert_and_get
├── get_nonexistent_returns_none
├── insert_overwrites
├── remove_deletes_entry
├── expired_entry_returns_none
├── cleanup_removes_expired_on_insert
└── clone_shares_state

vault::tests                              (13 тестов) — DB typestate + VaultPass
├── test_open_database
├── create_pass_returns_vault_pass
├── create_pass_wrong_password_fails
├── create_pass_nonexistent_user_fails
├── create_pass_does_not_consume_db
├── enter_with_pass_from_create_pass
├── enter_with_external_pass
├── enter_nonexistent_user_fails
├── enter_uses_db_email_not_pass_email
├── full_flow_create_pass_then_enter
├── test_save_and_read_entry
├── test_delete_entry
└── test_user_isolation

crypto_operations::tests                  (15 тестов) — RealCrypto
├── generate_salt (hex format, uniqueness)
├── hash_master_password (PHC format, uniqueness)
├── verify_master_password (correct, wrong)
├── derive_encryption_key (hex format, deterministic, salt/password isolation)
└── encrypt/decrypt (roundtrip, different ciphertext, wrong key, invalid key, short key)

password_generator::tests                 (24 теста)
├── new (defaults, custom MIN_LENGTH)
├── from_flags (valid, all charsets, no charset panic, length below min panic)
├── length (setter, below min panic)
├── builder chain (has_*, combinations, length + charset)
├── generate (correct length, charset compliance, uniqueness, variety)
└── secure (preset length 20, all charsets)

http_api::handlers::tests                 (21 тест)  — Integration (FakeCrypto + TestApp)
├── health_returns_ok
├── generate_returns_password_of_requested_length
├── register_creates_user
├── register_invalid_email_returns_400
├── login_returns_tokens
├── login_wrong_password_returns_401
├── login_nonexistent_user_returns_401
├── add_with_bearer_token
├── list_returns_added_entries
├── view_returns_entry_details
├── delete_removes_entry
├── view_nonexistent_entry_returns_404
├── list_without_token_returns_401
├── add_without_token_returns_401
├── refresh_returns_new_tokens
├── refresh_invalidates_old_token (rotation)
├── refresh_with_wrong_token_returns_401
├── logout_revokes_session
├── logout_revokes_refresh_token
├── logout_without_token_returns_401
└── login_locked_after_max_attempts
```

`CryptoProvider` trait позволяет тестировать DB-логику без реальной криптографии:
- `FakeCrypto` (`#[cfg(test)]`) — детерминированный, мгновенный
- `RealCrypto` — PBKDF2 600K итераций, AES-256-GCM (~60с на тест с derive_key)

Handler-тесты используют `TestApp` — in-process HTTP через `tower::ServiceExt::oneshot()`, без сетевого стека.

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

# HTTP API
tokio = { version = "1.49", features = ["rt-multi-thread", "macros"] }  # Async runtime
axum = "0.8"                                                             # HTTP фреймворк
tower-http = { version = "0.6", features = ["cors", "trace"] }          # HTTP middleware
tracing-subscriber = { features = ["env-filter"] }                       # Логирование
tracing = "0.1"                                                          # Макросы info!, warn!, error!
base64 = "0.22"                                                          # Basic Auth декодирование
jsonwebtoken = { version = "10", features = ["rust_crypto"] }            # JWT encode/decode (HS256)
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
- [x] DB операции (create_user, create_pass, enter, CRUD entries)
- [x] Реализация крипто-операций (PBKDF2, AES-GCM)
- [x] CLI интерфейс (clap + rpassword)
- [x] Library crate (lib.rs) для переиспользования core-логики
- [x] Email валидация по RFC 5321/5322 (email_address crate)
- [x] HTTP API (axum): 10 endpoints, spawn_blocking, tracing
- [x] JWT-сессии: access_token (15 мин) + refresh_token (7 дней) с rotation
- [x] Bearer + Basic Auth fallback (CLI-совместимость)
- [x] Server-side SessionStore: encryption_key в памяти сервера, не в JWT payload
- [x] Instant revocation: POST /logout убивает сессию + refresh-токены мгновенно
- [x] Brute-force защита: FailedLoginTracker (5 попыток / 5 минут → 403)
- [x] JWT Secret: env var → файл → автогенерация
- [x] Архитектура Guard → Pass → Storage (auth/ и vault/ развязаны через VaultPass)
- [x] Отдельные БД: vault.db (users + entries), auth.db (refresh_tokens)
- [x] Unit-тесты (118 тестов: types, auth, failed_login_tracker, session_store, vault, crypto, password_generator, handlers)
- [ ] PWA фронтенд с E2E шифрованием в браузере
- [ ] Деплой на Hetzner CX23 Helsinki
- [ ] Браузерное расширение с автозаполнением
