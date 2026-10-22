# Security review

Hardening of the XTE Chukwa miner (Kotlin UI, stratum and daemon clients, NDK Argon2id). Pool and seednode modes, explicit Start/Stop, and no developer fee are unchanged. Defaults stay `xte.trrxitte.com:3333` and `eu-east.trrxitte.com:14485`.

A separate review of `main` at `34d9508` (model grok-build-0.1, then checked by hand against that tree) is cross-checked below. Severities are that review's. Each item was re-checked in this tree before the fix.

## Review cross-check

| ID | Sev | Held? | What changed |
| --- | --- | --- | --- |
| F1 | Medium | Yes | Optional pool TLS (checkbox, default on for port 9999). Network security config denies cleartext except `trrxitte.com` (and subdomains) and `localhost`. A daemon on any other configured host is reached by a direct HTTP/1.1 socket that only POSTs `/json_rpc` and refuses redirects and chunked bodies. |
| F2 | Medium | Yes | Stratum lines cap at 64 KiB. HTTP bodies cap at 256 KiB. Stratum blobs must be 43–512 bytes. The native hasher rejects blobs shorter than 43 or longer than 4096. Block templates larger than 100000 bytes are rejected while parsing and are not hashed. |
| F3 | Low | Yes | `hexToBytes` requires even length and `[0-9a-fA-F]`. Odd or non-hex input throws. |
| F4 | Low | Yes | Stratum `soTimeout` is 120s (above the 60s keepalive). A read timeout closes the socket and reconnects with backoff (2s, 4s, 8s, 16s, then 30s) until Stop. A rejected login does not reconnect. |
| F5 | Low | Yes | JNI `New*` / `Get*` / `CallVoidMethod` check null and pending exceptions, push a local frame, and `ExceptionClear` after the share callback. Exceptions are not described to logcat, because `ExceptionDescribe` can print peer data. |
| F6 | Low | Yes | `nativeStop` joins the workers, then `DeleteGlobalRef` on the callback. The next Start constructs a new hasher, which takes a new global ref. |
| F7 | Low | Yes | `distributionSha256Sum=7c3ad722e9b0ce8205b91560fd6ce8296ac3eadf065672242fd73c06b8eeb6ee` for `gradle-8.2.1-all.zip`. The committed wrapper jar matches the published 8.2.1 SHA-256 `a8451eeda314d0568b5340498b36edf147a8f0d692c5ff58082d477abe9146e4`. |
| F8 | Info | Yes | Pool payloads are not logged. A rejected line logs its length only in debug builds. |
| F9 | Info | Yes | Wallet must start with `XT`, use the CryptoNote base58 alphabet, and be 95, 97, 106, or 108 characters, plus optional `+` payment id and `.` fixed difficulty. Host is a hostname or IP (dotted quads that are not IPv4 are rejected). Port is 1–65535. Threads are 1–16. The wallet field accepts up to 192 characters so the suffix forms fit. |
| F10 | Info | Yes | Only `INTERNET` remains. The unused foreground-service and wake-lock permissions are gone. |
| F11 | Info | Yes | Release has R8 and resource shrinking. Native methods and `onNativeShareFound` are kept. |
| F12 | Info | Yes | `statusText`, `hashrate`, `stratum`, `daemon`, and `hasher` are `@Volatile`. `stop()` still joins workers before it drops the clients. The review's note that "share found after stop" was a false positive still holds. |

No Critical or High issues were confirmed. An earlier pass in this branch rated some of the same bugs High; the hand-checked review's Medium/Low scale is the one used here.

## F1 detail

Port 9999 is the cryptonote-nodejs-pool SSL port in the pool README template. A checked-in pool `config.json` has been seen with that port's `ssl` flag false, and this environment could not complete a live handshake to `xte.trrxitte.com:9999`, so TLS is optional. The box starts checked when the port is 9999 and the user has not chosen yet. Unchecking it speaks cleartext to that same configured host. TLS is 1.2 or 1.3, system trust anchors only, HTTPS endpoint identification, SNI, and ciphers containing `NULL`, `ANON`, `EXPORT`, `RC4`, `DES`, or `MD5` are dropped.

The network security config cannot list an IP address or a host the user types at runtime. `HttpURLConnection` therefore follows the allowlist. `DaemonRpcClient` uses it when `NetworkSecurityPolicy.isCleartextTrafficPermitted(host)` is true. Otherwise it opens a socket only to the already-validated host and port, writes a single `POST /json_rpc`, and parses the response itself. That parser rejects 3xx responses, `Transfer-Encoding: chunked`, and bodies over 256 KiB.

Stratum cleartext is already a raw socket to the host the user entered. It is not governed by the HTTP cleartext flag.

## Solo hashing blob (checked against traaitt)

The earlier note that seednode mode might hash the wrong bytes was checked against TRRXITTE/traaitt `master` (`RpcServer.cpp`, `BlockUtilities.cpp`, `CryptoNoteSerialization.cpp`, `hash.h`, `CryptoNoteConfig.h`). It is a real mismatch, not just a guess.

`RpcServer::on_getblocktemplate` sets `blocktemplate_blob` to the hex of the full `BlockTemplate`. There is no `blockhashing_blob`. `on_submitblock` expects that same full blob.

`getBlockLongHash` does not hash that blob. For `majorVersion != 1` (Chukwa is `BLOCK_MAJOR_VERSION_6`) it hashes `getParentBlockHashingBinaryArray(block, headerOnly=true)`:

- parent major and minor (`uint8`)
- timestamp (varint)
- parent previous-block id (32 bytes)
- nonce (`uint32`, raw)
- merkle root (32 bytes)
- transaction count (varint)
- then stop

The merkle root is `tree_hash_from_branch` of the parent miner-tx hash. `tree_depth(1) == 0`, so with a single miner transaction the root equals `getBaseTransactionHash`. For `TRANSACTION_VERSION_1` (current) that hash is `cn_fast_hash` (Keccak) of the miner transaction, not NIST SHA-3. `chukwa_slow_hash` then runs Argon2id (t=3, m=512 KiB, p=1) over that parent blob, with the salt equal to its first 16 bytes.

A v6 block header on the wire is major, minor, and previous id (34 bytes). The parent block follows. The nonce sits at about offset 73 of the full template when the timestamp varint is 5 bytes (34 + parent major + parent minor + 5 + 32). Offset 39 is the nonce offset **inside the parent hashing blob** for that same 5-byte timestamp, which is what the pool's stratum `blob` already is. Pool mode is unchanged.

This build does not construct that parent blob. Doing it correctly needs a tested Keccak and a slice of the miner transaction out of the template. An untested builder would submit blocks the node rejects, and the old path (hash the raw template, write the nonce at offset 39, `submitblock`) does that too. Seednode mode still connects and polls `getblocktemplate` so height and difficulty show up. It does not start the hasher and it does not call `submitblock`.

## Other controls

- Login session ids are accepted only for the outstanding login id and only if they match `[A-Za-z0-9._:-]{1,128}`. In-flight submits are capped at 32.
- Log and on-screen lines pass through a redactor. The active wallet, a long password, and `XT…` address-shaped tokens are masked.
- `allowBackup` is false. Backup and device-transfer rules exclude `xte_miner.xml`. Autofill is off on the form fields.
- No keystore, pem, or env file is tracked. Release signing reads `KEYSTORE_*`, `/workspace/secrets/xte-keystore.env`, or gitignored `keystore.properties`.
- App and plugin versions are pinned. They were not bumped in this pass.

## Native limits

- Nonce is 4 bytes little-endian at offset 39 of the **hashing** blob.
- Hash compare loads the first 8 hash bytes as an explicit little-endian `uint64`.
- Argon2id parameters are unchanged: t=3, m=512 KiB, p=1, salt = first 16 bytes, output 32 bytes.
- Worker threads are capped at 16.
- Argon2 symbols stay inside the library (`-fvisibility=hidden` and `--exclude-libs,ALL`). JNI entry points stay exported.

## Tests

`MinerValidationTest` covers the address, host, port, thread, and password checks, the TLS-port default, blob and target bounds, the 64 KiB / 256 KiB / 512 / 4096 caps, reconnect delays, the cleartext HTTP parser (redirect, chunked, oversize), the xmrig target and difficulty conversions, hex rejection, redaction, and the capped readers.

## Residual risk

- Cleartext stratum on ports other than a TLS session is what those pool ports expect. Anyone on the path can see the wallet address (a public mining login) and the worker name, and can still substitute a job if TLS is off.
- Seednode HTTP is unauthenticated. Point it at a daemon you trust. The direct-socket path exists so a daemon that is not on the cleartext allowlist still works; it does not follow redirects.
- Solo mode does not currently find blocks. Use pool mode to mine.
- The pool password is stored in `MODE_PRIVATE` prefs. It is not encrypted. It is a worker name (default `x`), not the spend key, and backup is off.
