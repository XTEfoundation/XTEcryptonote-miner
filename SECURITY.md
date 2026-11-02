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

## Solo mining (seednode mode)

Seednode mode now builds real work from `getblocktemplate` and submits found blocks. The construction follows TRRXITTE/traaitt `master`; file references are to that tree.

**What the daemon sends.** `RpcServer::on_getblocktemplate` returns `blocktemplate_blob`, the full serialized `BlockTemplate` (`src/rpc/RpcServer.cpp`). There is no hashing blob. For major ≥ 2 the wire format is (`src/serialization/CryptoNoteSerialization.cpp`, `serializeBlockHeader` / `ParentBlockSerializer`):

1. block header: varint major, varint minor, previous block id (32)
2. parent block: varint major, varint minor, varint timestamp, previous id (32), nonce (uint32 LE), varint transaction count, `tree_depth(count)` branch hashes, the parent base transaction, then `mmTag.depth` blockchain-branch hashes
3. the miner transaction, then varint count + 32-byte transaction hashes

`Core::getBlockTemplate` (`src/cryptonotecore/Core.cpp`) leaves the parent major, minor, and previous id zero and puts `03 21 00 <32 zero bytes>` (a depth-0 merge-mining tag with an empty root) in the parent transaction extra.

**What the miner fills in.** Exactly what traaitt's own solo miner does (`src/miner/MinerManager.cpp`, `adjustMergeMiningTag`): depth 0, `merkleRoot = getObjectHash(getBlockHashingBinaryArray())`. That is `cn_fast_hash(varint(len) || header || tree_hash(miner_tx_hash, tx_hashes…) || varint(count))` (`src/cryptonotecore/CachedBlock.cpp`, `src/common/CryptoNoteTools.h` length-prefixes object hashes of byte arrays). Nothing else in the template changes. The reserved extra-nonce bytes are left as the daemon sent them.

**What is hashed.** `getBlockLongHash` for major 6 runs `chukwa_slow_hash` over `getParentBlockHashingBinaryArray(headerOnly=true)`: parent major, minor, timestamp, previous id, nonce, `tree_hash_from_branch(branch, getBaseTransactionHash(parent tx))`, varint count (`CachedBlock.cpp`, `src/crypto/tree-hash.c`). With a 5-byte timestamp varint the nonce is at offset 39 of that blob, which is what the native hasher writes. `SoloJob` re-parses the built block and refuses the job unless the nonce is at offset 39 and the blob is 43–512 bytes. Only major 6 (Chukwa) templates are mined.

**Difficulty and submit.** A native prefilter compares the top 64 bits of the hash (bytes 24–31, little-endian) with `(2^64-1)/difficulty`. The submit thread then recomputes Chukwa for the nonce with an independent call, applies the exact `check_hash` rule (`hash * difficulty < 2^256`, `src/common/CheckDifficulty.cpp`), writes the nonce into the full block at the parent nonce offset, and calls `submitblock ["<hex>"]`. `status: OK` counts as accepted, an RPC error as rejected; error text is redacted and clipped. The request body cap for `submitblock` is 2 × 100000 + 1024 bytes; `getblocktemplate` stays at 8 KiB.

**Stale work.** The template is polled every 4 s. A new job is issued when the height or previous block changes, when the difficulty changes, and every 30 s (fresh timestamp). On a tip change all older jobs are dropped, so late results for them are ignored. At most four jobs on the current tip are kept, each job is submitted at most once, and a new template is fetched right after every submit.

**Parsing.** `CryptoNoteBlock.parse` is a bounds-checked reader: canonical varints only, no 64-bit overflow, counts capped (10000 per vector, 8 KiB extra, merge-mining depth ≤ 256, parent tx count ≤ 65535) and never allowed past the remaining bytes, major 1–6, tx version ≤ 2, coinbase inputs only, key outputs only, and no trailing bytes. Templates are still hex-checked and capped at 100000 bytes before parsing.

**Keccak.** `Keccak.kt` is a Kotlin port of the public-domain `keccak.c` by Markku-Juhani O. Saarinen (the file traaitt ships as `src/crypto/keccak.c`): Keccak-f[1600], rate 136, original `0x01 … 0x80` padding (not SHA-3 `0x06`).

### Native target fix

`hash_meets_target` used to compare the **first** 8 hash bytes with the 64-bit target. CryptoNote difficulty treats the hash as a 256-bit little-endian number, so the significant bytes are 24–31 (xmrig compares `hash + 24`). The old check passed hashes at random with respect to the target, which also made pool shares mostly worthless. It now compares bytes 24–31 with `<=`; the Kotlin side does the exact check before a block is sent.

## Other controls

- Login session ids are accepted only for the outstanding login id and only if they match `[A-Za-z0-9._:-]{1,128}`. In-flight submits are capped at 32.
- Log and on-screen lines pass through a redactor. The active wallet, a long password, and `XT…` address-shaped tokens are masked.
- `allowBackup` is false. Backup and device-transfer rules exclude `xte_miner.xml`. Autofill is off on the form fields.
- No keystore, pem, or env file is tracked. Release signing reads `KEYSTORE_*`, `/workspace/secrets/xte-keystore.env`, or gitignored `keystore.properties`.
- App and plugin versions are pinned. They were not bumped in this pass.

## Native limits

- Nonce is 4 bytes little-endian at offset 39 of the **hashing** blob.
- Hash compare loads hash bytes 24–31 (the most significant 64 bits) as an explicit little-endian `uint64` and accepts `<= target64`.
- Argon2id parameters are unchanged: t=3, m=512 KiB, p=1, salt = first 16 bytes, output 32 bytes.
- Worker threads are capped at 16.
- Argon2 symbols stay inside the library (`-fvisibility=hidden` and `--exclude-libs,ALL`). JNI entry points stay exported.

## Tests

`MinerValidationTest` covers the address, host, port, thread, and password checks, the TLS-port default, blob and target bounds, the 64 KiB / 256 KiB / 512 / 4096 caps, reconnect delays, the cleartext HTTP parser (redirect, chunked, oversize), the xmrig target and difficulty conversions, hex rejection, redaction, and the capped readers.

`SoloMiningTest` covers:

- Keccak-256 vectors (`""`, `"abc"`, one zero byte, and lengths 55/135/136/137/200/271/272/273/500 produced by traaitt's own `keccak.c` and pycryptodome), plus a BouncyCastle `KeccakDigest` cross-check.
- 13 real TurtleCoin mainnet blocks, v1–v6, from the turtlecoin-utils test suite (same block code as traaitt): every block hash and nonce reproduces; for the v6 block, Chukwa (BouncyCastle Argon2id) of the parent hashing blob reproduces the published PoW hash; the merge-mining root equals the aux header hash on all 10 depth-0 blocks.
- A real daemon `getblocktemplate` response (TurtleCoin v5): the computed root equals the root in that suite's expected merged block, the submitted block re-parses to the same hashing blob, and only the root and nonce change.
- `check_hash` against a BigInteger reference, the 64-bit prefilter never dropping a valid block, malformed or hostile blobs, and tree-hash shapes.

## Residual risk

- Cleartext stratum on ports other than a TLS session is what those pool ports expect. Anyone on the path can see the wallet address (a public mining login) and the worker name, and can still substitute a job if TLS is off.
- Seednode HTTP is unauthenticated. Point it at a daemon you trust. The direct-socket path exists so a daemon that is not on the cleartext allowlist still works; it does not follow redirects.
- Solo mode has not been tested against a live traaitt daemon: no traaitt node or explorer API was reachable from the build environment. The vectors are real TurtleCoin data, and traaitt's block, hash, and tree code is the same in the paths used. A first real block on the network is the remaining proof.
- The solo parent block keeps the daemon's zero parent major, minor, and previous id, as traaitt's own `MinerManager` does. Pools that rewrite those fields (to 1 and the block's previous id) produce a different but also valid layout; this app does not.
- At chain difficulty a phone finds a block rarely. Solo mining is a lottery; pool mode gives steady payouts.
- The pool password is stored in `MODE_PRIVATE` prefs. It is not encrypted. It is a worker name (default `x`), not the spend key, and backup is off.
