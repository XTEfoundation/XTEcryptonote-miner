#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <new>
#include <exception>

#include "argon2.h"

#define LOG_TAG "XTEChukwa"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Chukwa = Argon2id: t=3, m=512 KiB, p=1, salt=first 16 bytes of input, out=32.
// Blob limits match MinerValidation.MAX_HASH_BLOB_BYTES (nonce at offset 39).
static constexpr uint32_t CHUKWA_T_COST = 3;
static constexpr uint32_t CHUKWA_M_COST = 512; // KiB
static constexpr uint32_t CHUKWA_PARALLELISM = 1;
static constexpr size_t CHUKWA_SALT_LEN = 16;
static constexpr size_t CHUKWA_HASH_LEN = 32;
static constexpr size_t NONCE_OFFSET = 39;
static constexpr size_t MIN_BLOB = NONCE_OFFSET + 4;
static constexpr size_t MAX_BLOB = 4096;
static constexpr size_t MAX_JOB_ID = 128;

struct WorkerState {
    std::atomic<bool> running{false};
    std::atomic<uint64_t> hashes{0};
    std::vector<std::thread> threads;
    std::mutex job_mutex;
    std::vector<uint8_t> blob;
    uint64_t target64 = 0;
    std::string job_id;
    uint32_t next_nonce = 0;
    JavaVM *jvm = nullptr;
    jobject callback = nullptr; // global ref; swapped only while workers are joined
};

static WorkerState g_state;
static std::mutex g_life_mutex;

static uint64_t load_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (uint64_t) p[i] << (8 * i);
    }
    return v;
}

static bool hash_meets_target(const uint8_t hash[32], uint64_t target64) {
    // Explicit little-endian. Android is LE; do not rely on host endianness.
    return load_le64(hash) < target64;
}

static bool job_id_ok(const char *s) {
    if (s == nullptr || s[0] == '\0') return false;
    size_t n = 0;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p) {
        if (++n > MAX_JOB_ID) return false;
        const unsigned char c = *p;
        const bool ok = (c >= '0' && c <= '9') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        c == '_' || c == '-' || c == '.' || c == ':';
        if (!ok) return false;
    }
    return true;
}

static int chukwa_hash(const uint8_t *input, size_t input_len, uint8_t out[32]) {
    if (input == nullptr || input_len < CHUKWA_SALT_LEN || input_len > MAX_BLOB) return -1;
    return argon2id_hash_raw(
            CHUKWA_T_COST,
            CHUKWA_M_COST,
            CHUKWA_PARALLELISM,
            input, input_len,
            input, CHUKWA_SALT_LEN,
            out, CHUKWA_HASH_LEN
    );
}

static void clear_job_locked() {
    g_state.blob.clear();
    g_state.blob.shrink_to_fit();
    g_state.target64 = 0;
    g_state.job_id.clear();
}

// Caller holds g_life_mutex. Workers never take that lock, so joining here cannot deadlock.
static void join_workers_locked() {
    g_state.running.store(false, std::memory_order_release);
    for (auto &t : g_state.threads) {
        if (t.joinable()) t.join();
    }
    g_state.threads.clear();
}

struct UtfChars {
    JNIEnv *env;
    jstring str;
    const char *chars;
    explicit UtfChars(JNIEnv *e, jstring s) : env(e), str(s), chars(nullptr) {
        if (env != nullptr && str != nullptr) {
            chars = env->GetStringUTFChars(str, nullptr);
        }
    }
    ~UtfChars() {
        if (chars != nullptr && env != nullptr && str != nullptr) {
            env->ReleaseStringUTFChars(str, chars);
        }
    }
    UtfChars(const UtfChars &) = delete;
    UtfChars &operator=(const UtfChars &) = delete;
};

static void notify_share(JNIEnv *env, const std::string &job_id, uint32_t nonce, const uint8_t hash[32]) {
    if (env == nullptr || g_state.callback == nullptr) return;
    if (env->PushLocalFrame(16) < 0) {
        env->ExceptionClear();
        return;
    }
    jclass cls = env->GetObjectClass(g_state.callback);
    if (env->ExceptionCheck() || cls == nullptr) {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return;
    }
    jmethodID mid = env->GetMethodID(cls, "onNativeShareFound", "(Ljava/lang/String;I[B)V");
    if (env->ExceptionCheck() || mid == nullptr) {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return;
    }
    jstring jJob = env->NewStringUTF(job_id.c_str());
    jbyteArray jHash = env->NewByteArray(static_cast<jsize>(CHUKWA_HASH_LEN));
    if (env->ExceptionCheck() || jJob == nullptr || jHash == nullptr) {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return;
    }
    env->SetByteArrayRegion(jHash, 0, static_cast<jsize>(CHUKWA_HASH_LEN),
                            reinterpret_cast<const jbyte *>(hash));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return;
    }
    env->CallVoidMethod(g_state.callback, mid, jJob, static_cast<jint>(nonce), jHash);
    if (env->ExceptionCheck()) {
        // Drop the Java exception so the next JNI call on this thread does not abort.
        env->ExceptionClear();
        LOGI("share callback failed");
    }
    env->PopLocalFrame(nullptr);
}

static void worker_loop(int worker_id) {
    JNIEnv *env = nullptr;
    bool attached = false;
    if (g_state.jvm != nullptr) {
        if (g_state.jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
            if (g_state.jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            } else {
                env = nullptr;
            }
        }
    }

    std::vector<uint8_t> local_blob;
    uint64_t local_target = 0;
    std::string local_job;

    while (g_state.running.load(std::memory_order_acquire)) {
        {
            std::lock_guard<std::mutex> lock(g_state.job_mutex);
            if (g_state.blob.size() < MIN_BLOB || g_state.target64 == 0 || g_state.job_id.empty()) {
                local_blob.clear();
                local_target = 0;
                local_job.clear();
            } else {
                local_blob = g_state.blob;
                local_target = g_state.target64;
                local_job = g_state.job_id;
            }
        }

        if (local_blob.size() < MIN_BLOB || local_blob.size() > MAX_BLOB || local_target == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        uint32_t start_nonce = 0;
        {
            std::lock_guard<std::mutex> lock(g_state.job_mutex);
            if (g_state.job_id != local_job || g_state.blob.size() != local_blob.size()) {
                continue;
            }
            start_nonce = g_state.next_nonce;
            g_state.next_nonce += 64;
        }

        for (uint32_t i = 0; i < 64 && g_state.running.load(std::memory_order_acquire); ++i) {
            const uint32_t nonce = start_nonce + i;
            local_blob[NONCE_OFFSET + 0] = (uint8_t) (nonce & 0xff);
            local_blob[NONCE_OFFSET + 1] = (uint8_t) ((nonce >> 8) & 0xff);
            local_blob[NONCE_OFFSET + 2] = (uint8_t) ((nonce >> 16) & 0xff);
            local_blob[NONCE_OFFSET + 3] = (uint8_t) ((nonce >> 24) & 0xff);

            uint8_t hash[CHUKWA_HASH_LEN];
            const int rc = chukwa_hash(local_blob.data(), local_blob.size(), hash);
            g_state.hashes.fetch_add(1, std::memory_order_relaxed);
            if (rc != ARGON2_OK) continue;
            if (!hash_meets_target(hash, local_target)) continue;

            LOGI("Share found worker=%d nonce=%08x", worker_id, nonce);
            if (env != nullptr) {
                notify_share(env, local_job, nonce, hash);
            }
        }
    }

    if (attached && g_state.jvm != nullptr) {
        g_state.jvm->DetachCurrentThread();
    }
}

static bool copy_blob(JNIEnv *env, jbyteArray blob, std::vector<uint8_t> &out) {
    if (blob == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    const jsize len = env->GetArrayLength(blob);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    if (len < static_cast<jsize>(MIN_BLOB) || len > static_cast<jsize>(MAX_BLOB)) {
        LOGI("reject blob len=%d", static_cast<int>(len));
        return false;
    }
    try {
        out.assign(static_cast<size_t>(len), 0);
    } catch (const std::bad_alloc &) {
        LOGI("reject blob alloc");
        return false;
    }
    env->GetByteArrayRegion(blob, 0, len, reinterpret_cast<jbyte *>(out.data()));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        out.clear();
        return false;
    }
    return true;
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeInit(
        JNIEnv *env, jobject /*thiz*/, jobject callback) {
    std::lock_guard<std::mutex> life(g_life_mutex);
    join_workers_locked();
    if (env->GetJavaVM(&g_state.jvm) != JNI_OK) {
        g_state.jvm = nullptr;
    }
    if (g_state.callback != nullptr) {
        env->DeleteGlobalRef(g_state.callback);
        g_state.callback = nullptr;
    }
    if (callback != nullptr) {
        g_state.callback = env->NewGlobalRef(callback);
        if (env->ExceptionCheck() || g_state.callback == nullptr) {
            env->ExceptionClear();
            g_state.callback = nullptr;
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeSetJob(
        JNIEnv *env, jobject /*thiz*/,
        jbyteArray blob, jstring jobId, jlong target64) {
    std::vector<uint8_t> buf;
    const bool blob_ok = copy_blob(env, blob, buf);

    std::string job;
    bool job_ok = false;
    if (jobId != nullptr && !env->ExceptionCheck()) {
        const jsize chars = env->GetStringLength(jobId);
        if (!env->ExceptionCheck() && chars > 0 && chars <= static_cast<jsize>(MAX_JOB_ID)) {
            UtfChars utf(env, jobId);
            if (!env->ExceptionCheck() && utf.chars != nullptr && job_id_ok(utf.chars)) {
                job.assign(utf.chars);
                job_ok = true;
            } else {
                env->ExceptionClear();
            }
        } else {
            env->ExceptionClear();
        }
    } else {
        env->ExceptionClear();
    }

    std::lock_guard<std::mutex> lock(g_state.job_mutex);
    if (!blob_ok || !job_ok || target64 == 0) {
        clear_job_locked();
        return;
    }
    g_state.blob = std::move(buf);
    g_state.job_id = std::move(job);
    g_state.target64 = static_cast<uint64_t>(target64);
    g_state.next_nonce = static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xffffffffu);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeStart(
        JNIEnv * /*env*/, jobject /*thiz*/, jint threads) {
    std::lock_guard<std::mutex> life(g_life_mutex);
    if (g_state.running.load(std::memory_order_acquire)) return;
    if (!g_state.threads.empty()) join_workers_locked();
    g_state.hashes.store(0, std::memory_order_relaxed);
    int n = threads > 0 ? static_cast<int>(threads) : 1;
    if (n > 16) n = 16;
    g_state.running.store(true, std::memory_order_release);
    try {
        for (int i = 0; i < n; ++i) {
            g_state.threads.emplace_back(worker_loop, i);
        }
    } catch (const std::exception &) {
        join_workers_locked();
        LOGI("failed to start mining threads");
        return;
    }
    LOGI("Started %d mining threads (Chukwa t=3 m=512 p=1)", n);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeStop(
        JNIEnv *env, jobject /*thiz*/) {
    std::lock_guard<std::mutex> life(g_life_mutex);
    join_workers_locked();
    // Workers are joined, so notify_share cannot still be inside CallVoidMethod.
    if (env != nullptr && g_state.callback != nullptr) {
        env->DeleteGlobalRef(g_state.callback);
        g_state.callback = nullptr;
    }
    LOGI("Mining threads stopped");
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeGetHashes(
        JNIEnv * /*env*/, jobject /*thiz*/) {
    return static_cast<jlong>(g_state.hashes.load(std::memory_order_relaxed));
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeHashOnce(
        JNIEnv *env, jobject /*thiz*/, jbyteArray input) {
    if (input == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    const jsize len = env->GetArrayLength(input);
    if (env->ExceptionCheck() || len < static_cast<jsize>(CHUKWA_SALT_LEN) ||
        len > static_cast<jsize>(MAX_BLOB)) {
        env->ExceptionClear();
        return nullptr;
    }
    std::vector<uint8_t> buf;
    try {
        buf.assign(static_cast<size_t>(len), 0);
    } catch (const std::bad_alloc &) {
        return nullptr;
    }
    env->GetByteArrayRegion(input, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    uint8_t out[CHUKWA_HASH_LEN];
    if (chukwa_hash(buf.data(), buf.size(), out) != ARGON2_OK) return nullptr;
    jbyteArray result = env->NewByteArray(static_cast<jsize>(CHUKWA_HASH_LEN));
    if (result == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(CHUKWA_HASH_LEN),
                            reinterpret_cast<const jbyte *>(out));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeClearJob(
        JNIEnv * /*env*/, jobject /*thiz*/) {
    std::lock_guard<std::mutex> lock(g_state.job_mutex);
    clear_job_locked();
}
