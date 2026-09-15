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

#include "argon2.h"

#define LOG_TAG "XTEChukwa"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Chukwa = Argon2id: t=3, m=512 KiB, p=1, salt=first 16 bytes of input, out=32
static constexpr uint32_t CHUKWA_T_COST = 3;
static constexpr uint32_t CHUKWA_M_COST = 512; // KiB
static constexpr uint32_t CHUKWA_PARALLELISM = 1;
static constexpr size_t CHUKWA_SALT_LEN = 16;
static constexpr size_t CHUKWA_HASH_LEN = 32;
static constexpr size_t NONCE_OFFSET = 39;

struct WorkerState {
    std::atomic<bool> running{false};
    std::atomic<uint64_t> hashes{0};
    std::atomic<uint64_t> accepted{0}; // unused here; Java tracks submits
    std::vector<std::thread> threads;
    std::mutex job_mutex;
    std::vector<uint8_t> blob;
    uint64_t target64 = 0;
    std::string job_id;
    uint32_t next_nonce = 0;
    JavaVM *jvm = nullptr;
    jobject callback = nullptr; // global ref to MiningEngine
};

static WorkerState g_state;

static bool hash_meets_target(const uint8_t hash[32], uint64_t target64) {
    // xmrig-compatible: first 8 bytes of hash as LE uint64 < target64
    uint64_t h;
    memcpy(&h, hash, 8);
    return h < target64;
}

static int chukwa_hash(const uint8_t *input, size_t input_len, uint8_t out[32]) {
    if (input_len < CHUKWA_SALT_LEN) return -1;
    return argon2id_hash_raw(
        CHUKWA_T_COST,
        CHUKWA_M_COST,
        CHUKWA_PARALLELISM,
        input, input_len,
        input, CHUKWA_SALT_LEN, // salt = first 16 bytes of blob (xmrig Chukwa)
        out, CHUKWA_HASH_LEN
    );
}

static void notify_share(JNIEnv *env, const std::string &job_id, uint32_t nonce, const uint8_t hash[32]) {
    if (!g_state.callback) return;
    jclass cls = env->GetObjectClass(g_state.callback);
    if (!cls) return;
    jmethodID mid = env->GetMethodID(cls, "onNativeShareFound", "(Ljava/lang/String;I[B)V");
    if (!mid) {
        env->DeleteLocalRef(cls);
        return;
    }
    jstring jJob = env->NewStringUTF(job_id.c_str());
    jbyteArray jHash = env->NewByteArray(32);
    env->SetByteArrayRegion(jHash, 0, 32, reinterpret_cast<const jbyte *>(hash));
    env->CallVoidMethod(g_state.callback, mid, jJob, (jint) nonce, jHash);
    env->DeleteLocalRef(jJob);
    env->DeleteLocalRef(jHash);
    env->DeleteLocalRef(cls);
}

static void worker_loop(int worker_id) {
    JNIEnv *env = nullptr;
    bool attached = false;
    if (g_state.jvm) {
        if (g_state.jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
            if (g_state.jvm->AttachCurrentThread(&env, nullptr) == 0) {
                attached = true;
            }
        }
    }

    std::vector<uint8_t> local_blob;
    uint64_t local_target = 0;
    std::string local_job;

    while (g_state.running.load()) {
        {
            std::lock_guard<std::mutex> lock(g_state.job_mutex);
            if (g_state.blob.empty()) {
                // wait for job
            } else {
                local_blob = g_state.blob;
                local_target = g_state.target64;
                local_job = g_state.job_id;
            }
        }

        if (local_blob.size() < NONCE_OFFSET + 4 || local_target == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // Batch of nonces per lock
        uint32_t start_nonce;
        {
            std::lock_guard<std::mutex> lock(g_state.job_mutex);
            start_nonce = g_state.next_nonce;
            g_state.next_nonce += 64;
        }

        for (uint32_t i = 0; i < 64 && g_state.running.load(); ++i) {
            uint32_t nonce = start_nonce + i;
            // Write LE nonce into blob
            local_blob[NONCE_OFFSET + 0] = (uint8_t) (nonce & 0xff);
            local_blob[NONCE_OFFSET + 1] = (uint8_t) ((nonce >> 8) & 0xff);
            local_blob[NONCE_OFFSET + 2] = (uint8_t) ((nonce >> 16) & 0xff);
            local_blob[NONCE_OFFSET + 3] = (uint8_t) ((nonce >> 24) & 0xff);

            uint8_t hash[32];
            int rc = chukwa_hash(local_blob.data(), local_blob.size(), hash);
            g_state.hashes.fetch_add(1, std::memory_order_relaxed);
            if (rc != ARGON2_OK) continue;

            if (hash_meets_target(hash, local_target)) {
                LOGI("Share found worker=%d nonce=%08x", worker_id, nonce);
                if (env) {
                    notify_share(env, local_job, nonce, hash);
                }
            }
        }
    }

    if (attached && g_state.jvm) {
        g_state.jvm->DetachCurrentThread();
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeInit(
        JNIEnv *env, jobject /*thiz*/, jobject callback) {
    env->GetJavaVM(&g_state.jvm);
    if (g_state.callback) {
        env->DeleteGlobalRef(g_state.callback);
        g_state.callback = nullptr;
    }
    g_state.callback = env->NewGlobalRef(callback);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeSetJob(
        JNIEnv *env, jobject /*thiz*/,
        jbyteArray blob, jstring jobId, jlong target64) {
    jsize len = env->GetArrayLength(blob);
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    env->GetByteArrayRegion(blob, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    const char *jid = env->GetStringUTFChars(jobId, nullptr);
    {
        std::lock_guard<std::mutex> lock(g_state.job_mutex);
        g_state.blob = std::move(buf);
        g_state.job_id = jid ? jid : "";
        g_state.target64 = static_cast<uint64_t>(target64);
        // Randomize starting nonce a bit from time
        g_state.next_nonce = static_cast<uint32_t>(
                std::chrono::steady_clock::now().time_since_epoch().count() & 0xffffffffu);
    }
    if (jid) env->ReleaseStringUTFChars(jobId, jid);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeStart(
        JNIEnv * /*env*/, jobject /*thiz*/, jint threads) {
    if (g_state.running.exchange(true)) return;
    g_state.hashes.store(0);
    int n = threads > 0 ? threads : 1;
    if (n > 16) n = 16;
    g_state.threads.clear();
    for (int i = 0; i < n; ++i) {
        g_state.threads.emplace_back(worker_loop, i);
    }
    LOGI("Started %d mining threads (Chukwa t=3 m=512 p=1)", n);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeStop(
        JNIEnv * /*env*/, jobject /*thiz*/) {
    g_state.running.store(false);
    for (auto &t : g_state.threads) {
        if (t.joinable()) t.join();
    }
    g_state.threads.clear();
    LOGI("Mining threads stopped");
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeGetHashes(
        JNIEnv * /*env*/, jobject /*thiz*/) {
    return static_cast<jlong>(g_state.hashes.load());
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeHashOnce(
        JNIEnv *env, jobject /*thiz*/, jbyteArray input) {
    jsize len = env->GetArrayLength(input);
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    env->GetByteArrayRegion(input, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    uint8_t out[32];
    int rc = chukwa_hash(buf.data(), buf.size(), out);
    if (rc != ARGON2_OK) return nullptr;
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<jbyte *>(out));
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_xtefoundation_cryptonoteminer_ChukwaHasher_nativeClearJob(
        JNIEnv * /*env*/, jobject /*thiz*/) {
    std::lock_guard<std::mutex> lock(g_state.job_mutex);
    g_state.blob.clear();
    g_state.target64 = 0;
    g_state.job_id.clear();
}
