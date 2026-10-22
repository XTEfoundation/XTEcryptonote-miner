package com.xtefoundation.cryptonoteminer

import androidx.annotation.Keep

/**
 * JNI bridge to Argon2id Chukwa (t=3, m=512 KiB, p=1).
 * [onNativeShareFound] is invoked from native worker threads and looked up by name.
 * Do not rename it. Stop mining from the UI thread; the native stop joins workers.
 */
@Keep
class ChukwaHasher(private val listener: ShareListener) {

    interface ShareListener {
        fun onShareFound(jobId: String, nonce: Int, hash: ByteArray)
    }

    init {
        System.loadLibrary("xte_chukwa")
        nativeInit(this)
    }

    /** Called from JNI worker threads — must stay public with this exact signature. */
    @Keep
    fun onNativeShareFound(jobId: String, nonce: Int, hash: ByteArray) {
        if (hash.size != MinerValidation.HASH_BYTES) return
        if (!MinerValidation.isJobId(jobId)) return
        try {
            listener.onShareFound(jobId, nonce, hash)
        } catch (_: Exception) {
            // The worker keeps hashing. Native code also clears a pending JNI exception.
        }
    }

    fun setJob(blob: ByteArray, jobId: String, target64: Long) = nativeSetJob(blob, jobId, target64)
    fun clearJob() = nativeClearJob()
    fun start(threads: Int) = nativeStart(threads)
    fun stop() = nativeStop()
    fun hashes(): Long = nativeGetHashes()
    fun hashOnce(input: ByteArray): ByteArray? = nativeHashOnce(input)

    private external fun nativeInit(callback: Any)
    private external fun nativeSetJob(blob: ByteArray, jobId: String, target64: Long)
    private external fun nativeClearJob()
    private external fun nativeStart(threads: Int)
    private external fun nativeStop()
    private external fun nativeGetHashes(): Long
    private external fun nativeHashOnce(input: ByteArray): ByteArray?
}
