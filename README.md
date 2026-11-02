# XTEcryptonote-miner

Android CPU miner for **traaitt [XTE]** (Cryptonote) using **Chukwa** (Argon2id).

- Package: `com.xtefoundation.cryptonoteminer`
- Honest miner: **no developer fee**, no silent background mining — mining starts only after you enter a wallet and tap **Start**.
- ABI: `arm64-v8a`, `armeabi-v7a` · minSdk 26 · targetSdk 34
- Modes: **Solo / Seednode** (default: daemon JSON-RPC over HTTPS at `https://main.trrxitte.com/json_rpc`) and **Pool** (stratum)
- Security notes and the hardening pass: [`SECURITY.md`](SECURITY.md)

## Pool defaults

| Setting | Default |
|--------|---------|
| Host | `main.trrxitte.com` |
| Port | `3333` (also 4444 / 5555 / 7777). `9999` offers TLS |
| Algo | `chukwa` |
| Password | `x` (or your worker name) |

Port **9999** is the pool’s documented TLS port. The TLS checkbox starts checked for that port and can be turned off (some pool configs serve it as cleartext). TLS checks the hostname and uses TLS 1.2 or 1.3. The other pool ports stay cleartext TCP. A dropped pool socket reconnects with backoff until you tap Stop. A rejected login does not reconnect.

Seednode RPC uses HTTPS by default (port 443, system CAs, normal hostname verification). With the TLS box unchecked it speaks plain `http://`; cleartext HTTP from the platform stack is limited to `trrxitte.com` (and subdomains) and `localhost`, and any other daemon host you enter is contacted directly, with no redirects.

Sites: [traaitt.com](https://traaitt.com) · [mine.traaitt.com](https://mine.traaitt.com) · [explorer.traaitt.com](https://explorer.traaitt.com)

## Solo / Seednode defaults (the app's default mode)

| Setting | Default |
|--------|---------|
| Host | `main.trrxitte.com` |
| Port | `443` with TLS (HTTPS reverse proxy). Plain daemon RPC: `14485` with TLS off |
| TLS | on (checkbox; defaults on for port 443, off for other ports) |
| Endpoint | `POST https://main.trrxitte.com/json_rpc` |
| Wallet | required (coinbase address) |
| Password | unused (hidden in UI) |

Solo mining talks to an XTEnetwork daemon RPC (not stratum):

1. Poll `getblocktemplate` with `{ "reserve_size": 8, "wallet_address": "<XT…>" }` every 4 s.
2. Parse `blocktemplate_blob` strictly and fill the merge-mining tag root with the Keccak hash of the block hashing blob, as traaitt's own miner does.
3. Hash the parent-block hashing blob (nonce at offset 39) with Chukwa.
4. On a hit, re-check the hash with the exact `check_hash` rule, write the nonce into the full block, and send `submitblock ["<hex>"]`. Accepted/rejected blocks are counted in the UI.
5. New work on every height or previous-block change and every 30 s; work for an old tip is dropped.

Only v6 (Chukwa) templates are mined. A real template from `main.trrxitte.com` (height 1,788,054, difficulty 87,238, major 6) is kept as a unit-test fixture and builds a valid job (`LiveTemplateTest`). The block reward goes to the wallet you entered. Solo mining at network difficulty on a phone is a lottery; use pool mode for steady payouts. Construction, test vectors, and what is still unverified: [`SECURITY.md`](SECURITY.md#solo-mining-seednode-mode).

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
2. Templates become `SoloJob`s (`CryptoNoteBlock.kt`, `Keccak.kt`); the same native hasher mines them.

### Hash (both modes)

- Argon2id **Chukwa** via NDK + [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
- `t_cost=3`, `m_cost=512` (KiB), `parallelism=1`
- password = full hashing blob; salt = first **16** bytes of blob; output **32** bytes
- nonce written at hashing-blob offset **39** (4 bytes LE), for pool jobs and solo jobs alike. In the full solo block the nonce sits inside the parent block (offset 73 for a typical template); the app writes it there for `submitblock`.
- target check uses hash bytes 24–31 (the most significant 64 bits, as xmrig does).
- Multi-threaded native workers; UI shows hashrate, accepted/rejected, status.

> Note: Pool mode is **not** Bitcoin `mining.subscribe` stratum. XTE’s pool software uses the Cryptonote login protocol (same family as [TRRXITTE/xte-cryptonote-nodejs-pool](https://github.com/TRRXITTE/xte-cryptonote-nodejs-pool)).

## Install APK

Release artifact: [`releases/XTEcryptonote-miner.apk`](releases/XTEcryptonote-miner.apk)

```bash
adb install -r releases/XTEcryptonote-miner.apk
```

Enable “Install unknown apps” if needed. Keep the default **Solo (seednode)** or choose **Pool**, enter an `XT…` wallet, adjust host/port/threads, tap **Start mining**.

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
