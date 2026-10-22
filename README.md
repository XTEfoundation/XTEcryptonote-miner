# XTEcryptonote-miner

Android CPU miner for **traaitt [XTE]** (Cryptonote) using **Chukwa** (Argon2id).

- Package: `com.xtefoundation.cryptonoteminer`
- Honest miner: **no developer fee**, no silent background mining — mining starts only after you enter a wallet and tap **Start**.
- ABI: `arm64-v8a`, `armeabi-v7a` · minSdk 26 · targetSdk 34
- Modes: **Pool** (stratum) and **Seednode** (solo daemon JSON-RPC)
- Security notes and the hardening pass: [`SECURITY.md`](SECURITY.md)

## Pool defaults

| Setting | Default |
|--------|---------|
| Host | `xte.trrxitte.com` |
| Port | `3333` (also 4444 / 5555 / 7777). `9999` offers TLS |
| Algo | `chukwa` |
| Password | `x` (or your worker name) |

Port **9999** is the pool’s documented TLS port. The TLS checkbox starts checked for that port and can be turned off (some pool configs serve it as cleartext). TLS checks the hostname and uses TLS 1.2 or 1.3. The other pool ports stay cleartext TCP. A dropped pool socket reconnects with backoff until you tap Stop. A rejected login does not reconnect.

Seednode RPC stays `http://`. Cleartext HTTP from the platform stack is limited to `trrxitte.com` (and subdomains) and `localhost`. Any other daemon host you enter is contacted directly, with no redirects.

Sites: [traaitt.com](https://traaitt.com) · [mine.traaitt.com](https://mine.traaitt.com) · [explorer.traaitt.com](https://explorer.traaitt.com)

## Seednode (solo) defaults

| Setting | Default |
|--------|---------|
| Host | `eu-east.trrxitte.com` |
| Port | `14485` (daemon `--rpc-bind-port`) |
| Endpoint | `POST http://HOST:PORT/json_rpc` |
| Wallet | required (coinbase address) |
| Password | unused (hidden in UI) |

Solo mining talks to an XTEnetwork daemon RPC (not stratum):

1. Poll `getblocktemplate` with `{ "reserve_size": 8, "wallet_address": "<XT…>" }`
2. Response: `difficulty`, `height`, `reserved_offset`, `blocktemplate_blob`, `status`
3. The app shows height and difficulty. It does **not** hash `blocktemplate_blob` or call `submitblock`.

traaitt hashes a parent-block hashing blob (Chukwa / Argon2id), and the nonce lives at offset 39 of **that** blob, not of the raw template. Pool jobs already carry the hashing blob. Building it from a solo template needs a tested Keccak of the miner transaction, which this app does not ship. Details are in [`SECURITY.md`](SECURITY.md). Use pool mode to mine.

If the seednode host does not resolve or the daemon is unreachable, the app logs a DNS/RPC error and stays idle (no silent mining).

## Mining architecture

### Pool mode

1. **Stratum (Cryptonote-nodejs-pool style)** over TCP JSON lines:
   - `login` → session id + first `job`
   - push `job` / `getjob`
   - `submit` with `nonce` (8 hex) + `result` (64 hex)
   - `keepalived`
2. Pool jobs carry a 4-byte target; the app maps it to `target64` the same way xmrig does.

### Seednode mode

1. **Daemon JSON-RPC** over HTTP (`/json_rpc`) as above.
2. Height and difficulty refresh every few seconds. The hasher is not started.

### Hash (both modes)

- Argon2id **Chukwa** via NDK + [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
- `t_cost=3`, `m_cost=512` (KiB), `parallelism=1`
- password = full hashing blob; salt = first **16** bytes of blob; output **32** bytes
- nonce written at hashing-blob offset **39** (4 bytes LE). That matches pool jobs. It is not the offset of the nonce inside a raw v6 `blocktemplate_blob`.
- Multi-threaded native workers; UI shows hashrate, accepted/rejected, status.

> Note: Pool mode is **not** Bitcoin `mining.subscribe` stratum. XTE’s pool software uses the Cryptonote login protocol (same family as [TRRXITTE/xte-cryptonote-nodejs-pool](https://github.com/TRRXITTE/xte-cryptonote-nodejs-pool)).

## Install APK

Release artifact: [`releases/XTEcryptonote-miner.apk`](releases/XTEcryptonote-miner.apk)

```bash
adb install -r releases/XTEcryptonote-miner.apk
```

Enable “Install unknown apps” if needed. Choose **Pool** or **Seednode**, enter an `XT…` wallet, adjust host/port/threads, tap **Start mining**.

## Build from source

Requirements: JDK 17, Android SDK 34, NDK 26+.

```bash
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
# optional release signing — see keystore.properties.example
# or export KEYSTORE_PATH / KEY_ALIAS / STORE_PASSWORD / KEY_PASSWORD

cd XTEcryptonote-miner
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew :app:assembleRelease
```

APK output:

```text
app/build/outputs/apk/release/app-release.apk
```

Copy/rename to `XTEcryptonote-miner.apk` as needed. Without release keystore env, Gradle may produce an unsigned or debug-signed release depending on config — prefer setting signing env from a local secrets file outside git.

### Debug build

```bash
./gradlew :app:assembleDebug
```

## Config example

See [`config.example.json`](config.example.json).

## License

MIT (app code). Argon2 reference implementation is CC0 / Apache-2.0 dual — see `app/src/main/cpp/argon2/LICENSE`.

Inspired by public Cryptonote / Chukwa tooling ([xmrig](https://github.com/xmrig/xmrig) algorithm params, [TRRXITTE](https://github.com/TRRXITTE) pool). No proprietary blobs copied.
