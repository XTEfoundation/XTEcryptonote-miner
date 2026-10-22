# Security review

Hardening pass on the XTE Chukwa miner (Kotlin UI, stratum and daemon clients, NDK Argon2id). Mining behavior is unchanged: explicit Start/Stop, no developer fee, pool default `xte.trrxitte.com:3333`, seednode default `eu-east.trrxitte.com:14485`.

Pool port **9999** now uses TLS. That is the cryptonote-nodejs-pool SSL port (`desc: "SSL connection"`). Ports 3333, 4444, 5555, and 7777 stay cleartext TCP. Seednode RPC stays `http://` because the daemon endpoint is HTTP.

## Findings

| Sev | Issue | Fix |
| --- | --- | --- |
| High | Stratum `readLine()` and daemon `readText()` had no size limit. A hostile pool or daemon could exhaust memory. | Stratum lines capped at 32 KiB. RPC bodies capped at 2 MiB. Oversized input is rejected and the socket or request is dropped. |
| High | `hexToBytes` accepted non-hex (`Character.digit` returns -1) and padded odd lengths, so a bad job was hashed anyway. | Even length, hex alphabet, and size are required. Stratum hashing blobs must be 43–1024 bytes. Block templates must be 43 bytes–512 KiB. |
| High | Native `nativeSetJob` / `nativeHashOnce` trusted the Java array length. A null array, a pending JNI exception, or a multi-megabyte blob could crash or pin memory. Nonce writes assume offset 39. | Reject blobs shorter than 43 or longer than 512 KiB before allocation. Null-check JNI arrays and strings. Cap job ids at 128 bytes of `[A-Za-z0-9._:-]`. |
| High | Worker threads called `CallVoidMethod` without clearing exceptions or bounding local refs. A throwing share callback could abort the VM on the next JNI call. `clearJob` did not stop an in-flight blob copy, so workers kept hashing and submitting the previous job. | `PushLocalFrame` / `ExceptionClear`. An empty or zero-target job clears the worker’s local blob. Start/stop take one lock and join workers before swapping the callback global ref, so the callback is not deleted while a worker runs. |
| Medium | Port 9999 was opened as cleartext. The pool software treats that port as SSL, so the wallet login had no server authentication. | TLS 1.2+ only, platform trust store, HTTPS hostname check, SNI via `createSocket(socket, host, port, true)`. Ciphers with `NULL`, `ANON`, `EXPORT`, `RC4`, `DES`, or `MD5` are dropped. |
| Medium | Stratum read timeout was infinite. A keepalive write failure left the reader blocked. `connect()`’s `disconnect()` could let the old reader’s `finally` clear the new session’s `running` flag. | 15s connect timeout, 30s read timeout (timeouts do not drop a quiet pool). Keepalive failure closes the socket. A generation counter ignores stale threads. There is still **no** reconnect loop; Start remains explicit. |
| Medium | Daemon `HttpURLConnection` followed redirects and put response snippets in errors and logcat. A redirect or error body could echo the wallet. | Redirects off, caches off, status code only on HTTP failure, wallet redacted, bodies not logged. |
| Medium | Login results were accepted when `result` merely contained `id` and `job`, even if the id was not the pending login. Raw stratum lines were written to logcat. | Session id is set only for the outstanding login id, and only if it matches the token charset. Rejected lines are logged by type and length, not payload. |
| Medium | Wallet and pool password could reach logcat or the on-screen log through pool or daemon error text. | Log and UI lines pass through a redactor. The active wallet, a long password, and any `XT…` address-shaped token are masked. Payloads are not logged. |
| Low | `usesCleartextTraffic="true"` with no network security config. User-added CAs would have been trusted for any TLS the app added later. | `network_security_config`: cleartext stays on because seednode RPC is HTTP; trust anchors are **system CAs only**. Stratum TLS builds its `SSLContext` from that default trust manager. |
| Low | `WAKE_LOCK`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, and `ACCESS_NETWORK_STATE` were declared and unused. | Removed. Only `INTERNET` remains. The launcher activity stays `exported` (required). No other components. |
| Low | `allowBackup` was already false, but there was no backup or device-transfer exclude for `xte_miner.xml` (wallet and pool password). | `allowBackup="false"` kept. `backup_rules` and `data_extraction_rules` exclude that prefs file. Autofill is disabled on host, port, wallet, password, and threads. |
| Low | Release builds shipped with R8 off. | `isMinifyEnabled` and `isShrinkResources` for release. ProGuard keeps `ChukwaHasher` native methods and `onNativeShareFound` (JNI looks it up by name). `@Keep` is also on that class. |
| Low | Wallet check was `length < 10`. A bad port fell through to the default. Threads were clamped only in the setter. | Addresses must start with `XT`, use the CryptoNote base58 alphabet, and be 95, 97, 106, or 108 characters (the published traaitt address is 97). Optional pool suffixes: `+` payment id (16–64 hex) and `.` fixed difficulty. Host is an ASCII DNS name or an IP. Port is 1–65535. Threads are 1–16. Pool password is 1–128 printable characters. Empty host/port/threads still fall back to the mode defaults. |
| Low | Gradle wrapper zip had no checksum. | `distributionSha256Sum` for `gradle-8.2.1-all.zip` (`7c3ad722e9b0ce8205b91560fd6ce8296ac3eadf065672242fd73c06b8eeb6ee` from gradle.org). The committed `gradle-wrapper.jar` matches the published 8.2.1 wrapper jar SHA-256 `a8451eeda314d0568b5340498b36edf147a8f0d692c5ff58082d477abe9146e4`. |
| Info | Signing material. | No keystore, pem, or env file is tracked. Release signing still reads `KEYSTORE_*` env vars, `/workspace/secrets/xte-keystore.env`, or gitignored `keystore.properties`. `.gitignore` now also covers `*.pem`, `*.p12`, `*.key`, and `*.env`. `keystore.properties.example` contains only placeholders. |
| Info | Dependency versions. | App and plugin versions are already pinned (no `+` or `latest`). They were not bumped in this pass; a major Android Gradle Plugin jump is unrelated to the issues above. |
| Info | Daemon poll loop. | The 4s `getblocktemplate` poll is intentional while Start is active. The wait is floored at 1s so it cannot spin. It is not a reconnect storm. |
| Info | Pool password at rest. | Stored in `MODE_PRIVATE` prefs, backup disabled, not logged. It is a worker name (default `x`), not the wallet spend key. It is not encrypted, to avoid a new crypto dependency for that value. |

## Native limits (kept in sync with `MinerValidation`)

- Nonce is 4 bytes little-endian at offset **39**. Blobs shorter than 43 bytes are refused.
- Hash compare loads the first 8 hash bytes as an explicit little-endian `uint64` (same result as the previous `memcpy` on ARM).
- Argon2id parameters are unchanged: t=3, m=512 KiB, p=1, salt = first 16 bytes, output 32 bytes.
- Worker threads are capped at 16.

## Tests

`app/src/test/java/com/xtefoundation/cryptonoteminer/MinerValidationTest.kt` covers address, host, port, thread, and password checks, TLS-port selection, blob and target bounds, the xmrig target and difficulty conversions, hex rejection, redaction, and the capped readers.

## Residual risk

- Cleartext stratum on the non-TLS pool ports is what the pool expects. Anyone on the path can see the wallet address (it is a public mining login) and the worker name.
- Seednode HTTP is unauthenticated. Point it at a daemon you trust. Templates larger than 512 KiB are rejected.
- A pool can still set an easy target. Chukwa is slow enough that share traffic stays small; in-flight submits are capped at 32.
