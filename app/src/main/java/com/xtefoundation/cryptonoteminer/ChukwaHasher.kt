package com.xtefoundation.cryptonoteminer

/**
 * JNI bridge to Argon2id Chukwa (t=3, m=512 KiB, p=1).
 * Callback [onNativeShareFound] is invoked from native worker threads.
 */
class ChukwaHasher(private val listener: ShareListener) {

    interface ShareListener {
        fun onShareFound(jobId: String, nonce: Int, hash: ByteArray)
    }

    init {
        System.loadLibrary("xte_chukwa")
        nativeInit(this)
    }

    /** Called from JNI worker threads — must be public for JNI. */
    fun onNativeShareFound(jobId: String, nonce: Int, hash: ByteArray) {
        listener.onShareFound(jobId, nonce, hash)
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
