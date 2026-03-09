# Changelog

## [0.1.9](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.8...vault-family-v0.1.9) (2026-03-09)


### Features

* add /api/* zero-knowledge HTTP endpoints with route restructuring ([04d1d94](https://github.com/AvdienkoSergey/vault-family/commit/04d1d947ee94d0e02807812dbecb503a7fc43f4e))
* add 4-step client-driven invite flow module ([0644b9e](https://github.com/AvdienkoSergey/vault-family/commit/0644b9eff3f37343c0222ba251af33f1d82cda52))
* add change-password endpoint with dual-purpose auth bypass ([cae50f0](https://github.com/AvdienkoSergey/vault-family/commit/cae50f04ebb841d70f51dacd70373fc9f98d1eb5))
* add DeviceTrustStore for device-based auth bypass ([94b0d20](https://github.com/AvdienkoSergey/vault-family/commit/94b0d20209f029a8003c129415832a2fe2658c43))
* add in-memory TransferStore with rate limiting and cleanup ([7c178cd](https://github.com/AvdienkoSergey/vault-family/commit/7c178cd434c849f376c119c9ae41927eecbc8b8c))
* add invite types, InviteStatus/Role enums, and invites table schema ([a5a413a](https://github.com/AvdienkoSergey/vault-family/commit/a5a413aa22c9777a90e59dacc71524f87409ea98))
* add SecurityLock module for account protection on compromise ([d4eb9c5](https://github.com/AvdienkoSergey/vault-family/commit/d4eb9c5207afba276e91246d127010142d2b2ca0))
* add sender_public_key to invite flow and /my-key endpoint ([541dfc9](https://github.com/AvdienkoSergey/vault-family/commit/541dfc9545033848ded8dd461ad0eef2051b77a7))
* add TransferCode branded type and TransferError enum ([3294e4f](https://github.com/AvdienkoSergey/vault-family/commit/3294e4f31dabe1ce853a847b3b16fdaaf2aaa1f6))
* add WASM crypto module for client-side E2E encryption ([2fb10fa](https://github.com/AvdienkoSergey/vault-family/commit/2fb10fa6a20d86324daf68269def49994976adca))
* add WebSocket real-time notification system ([0718577](https://github.com/AvdienkoSergey/vault-family/commit/0718577a44bbce8bee20e4bb9b2334d8dc6623ab))
* harden login/register with device trust and WS alerts ([6bddfc1](https://github.com/AvdienkoSergey/vault-family/commit/6bddfc1c6795500b89936a76f764d4fe843435f6))
* integrate WebSocket fan-out, SecurityLock, and login notifications ([9acdecf](https://github.com/AvdienkoSergey/vault-family/commit/9acdecf4ba5af9914a0106f88c1dd9fad2134272))
* refactor shared vault core to zero-knowledge relay model ([60ace47](https://github.com/AvdienkoSergey/vault-family/commit/60ace47662f1ec251e42cef26838c25ee569db56))
* wire transfer HTTP endpoints, DTOs, and Swagger docs ([1d5bf99](https://github.com/AvdienkoSergey/vault-family/commit/1d5bf9944b903a1c469cee83efad688399ee3186))


### Bug Fixes

* **ci:** add tools/file-stats to workspace members ([12e93ff](https://github.com/AvdienkoSergey/vault-family/commit/12e93ff1c9c70cb33a0ed716a28fc3e39450f4f4))
* **ci:** add tools/file-stats to workspace members ([cdbf695](https://github.com/AvdienkoSergey/vault-family/commit/cdbf6959ed8baf29da1a693823f46590729eaba5))
* **ci:** trigger CI on release-please branch pushes ([72bba62](https://github.com/AvdienkoSergey/vault-family/commit/72bba62d333968f70f9b8d5bb32048bb317a2b01))
* **ci:** trigger CI on release-please branch pushes ([aaa467b](https://github.com/AvdienkoSergey/vault-family/commit/aaa467b4417019090beefba163412bdc8b604729))
* resolve clippy collapsible_if warning in PBKDF2 iterations ([5a6373a](https://github.com/AvdienkoSergey/vault-family/commit/5a6373affbc73af9cc0ac05ab887875555f855c0))

## [0.1.8](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.7...vault-family-v0.1.8) (2026-03-02)


### Features

* add swagger-ui in project ([7ac9106](https://github.com/AvdienkoSergey/vault-family/commit/7ac9106eeefc0d3434299c8d514fb5cf99d9f35e))
* add swagger-ui in project ([0ac2588](https://github.com/AvdienkoSergey/vault-family/commit/0ac2588ad5ef52b7cb3036cd153d5204f71107b3))

## [0.1.7](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.6...vault-family-v0.1.7) (2026-03-02)


### Bug Fixes

* isolate auth.db per test to prevent SQLite BUSY races in CI ([a74bfd4](https://github.com/AvdienkoSergey/vault-family/commit/a74bfd450dca88ab920faf3ce8464a3453b77b28))
* isolate auth.db per test to prevent SQLite BUSY races in CI ([072dcde](https://github.com/AvdienkoSergey/vault-family/commit/072dcde981a4d0905e226dc04dcbda3d788e8d22))

## [0.1.6](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.5...vault-family-v0.1.6) (2026-03-02)


### Features

* add shared vaults with X25519 key exchange ([d16bfab](https://github.com/AvdienkoSergey/vault-family/commit/d16bfab69e8e11f75767ac8b2a5bcf38b5d0609e))

## [0.1.5](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.4...vault-family-v0.1.5) (2026-03-01)


### Features

* **auth:** add brute-force protection with FailedLoginTracker (5 attempts / 5 min → 403) ([e0aa6fa](https://github.com/AvdienkoSergey/vault-family/commit/e0aa6fa9e943e3e0460dbcaec27eacb42afb889d))
* **auth:** add POST /logout with instant session and refresh token revocation ([1565701](https://github.com/AvdienkoSergey/vault-family/commit/1565701f25c6e62d9348fc9e05dbdc489812020d))

## [0.1.4](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.3...vault-family-v0.1.4) (2026-03-01)


### Features

* add JWT access token creation and decoding ([1798b11](https://github.com/AvdienkoSergey/vault-family/commit/1798b111bf8e9f36547987fb2bf0e8ed7e6e9191))
* **auth:** add extract_bearer_token and authenticate with JWT/Basic fallback ([ff2c861](https://github.com/AvdienkoSergey/vault-family/commit/ff2c861c6dec5c73eaa9beb3fdf8553fe68c25cd))
* **auth:** add POST /refresh endpoint with token rotation ([53e80de](https://github.com/AvdienkoSergey/vault-family/commit/53e80de5bad35eb1024ff4dea0fc61719fbe9f57))
* **jwt:** add jwt_secret loader with tracing and Result error handling ([2b58e68](https://github.com/AvdienkoSergey/vault-family/commit/2b58e6841a50deaf9cb89119b178e815d39e6964))
* **jwt:** add POST /login endpoint with JWT and refresh tokens ([ddd05f8](https://github.com/AvdienkoSergey/vault-family/commit/ddd05f820ac820a6e99347ed2218f5a9322f1686))

## [0.1.3](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.2...vault-family-v0.1.3) (2026-02-28)


### Features

* add new CLI command to start http server ([efbaf62](https://github.com/AvdienkoSergey/vault-family/commit/efbaf627a430743dd52f1127047b74ddb506be77))
* added a registration route in the http api ([d395ac9](https://github.com/AvdienkoSergey/vault-family/commit/d395ac99a9b9cad09bf3e1a2d72263ee1d955aff))
* added a tracing and logging for http api ([606e847](https://github.com/AvdienkoSergey/vault-family/commit/606e847bcf4a740f68b2dc18b30a91bb9ab83ff3))
* added basic auth and all methods in http-api ([9ff85e5](https://github.com/AvdienkoSergey/vault-family/commit/9ff85e55656690b1e1a0d11b13f0ebc960c15dfc))
* implement base http server ([676c05f](https://github.com/AvdienkoSergey/vault-family/commit/676c05f3f98ef5ebe41a178c1d1611903e520d8c))


### Bug Fixes

* apply clippy range_contains suggestion in generate_handler ([02e90da](https://github.com/AvdienkoSergey/vault-family/commit/02e90da85bf3f4c2115c852e1495e58d17443f6c))

## [0.1.2](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.1...vault-family-v0.1.2) (2026-02-27)


### Features

* add RFC 5321/5322 email validation via email_address crate ([a8195dc](https://github.com/AvdienkoSergey/vault-family/commit/a8195dc3e9abfd6ee1c7ba12fea0db116c1cbf64))
* implement CLI, real crypto, lib/bin split, and Login type ([29b59d5](https://github.com/AvdienkoSergey/vault-family/commit/29b59d5cfe0a3f6439ff4d59f6788a5401cbafd8))

## [0.1.1](https://github.com/AvdienkoSergey/vault-family/compare/vault-family-v0.1.0...vault-family-v0.1.1) (2026-02-26)


### Bug Fixes

* resolve all clippy warnings and add vault demo ([777cd6d](https://github.com/AvdienkoSergey/vault-family/commit/777cd6de3b4f9817de471b1bfe561d5cfd8ae023))
