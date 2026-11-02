package com.xtefoundation.cryptonoteminer.wallet

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * On-device wallet storage. Only the 32-byte private spend key is stored (the view key,
 * public keys, address and seed words all derive from it). It is encrypted with AES-256-GCM
 * under a non-exportable Android Keystore key (StrongBox when the device has it, else the
 * TEE/software keystore) and written to app-private storage (`filesDir/wallet/spend.bin`,
 * excluded from backup and device transfer). The public address is kept in plain prefs.
 *
 * File format: version(1) || iv(12) || ciphertext+tag. AAD binds the file to the address.
 */
class WalletStore(private val ctx: Context) {
    private val dir = File(ctx.filesDir, "wallet")
    private val file = File(dir, "spend.bin")
    private val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun hasWallet(): Boolean = file.exists() && address() != null

    fun address(): String? = prefs.getString(KEY_ADDRESS, null)

    /** False until the user has confirmed writing down the seed of the stored wallet. */
    fun isBackedUp(): Boolean = prefs.getBoolean(KEY_BACKED_UP, false)

    fun setBackedUp(v: Boolean) {
        prefs.edit().putBoolean(KEY_BACKED_UP, v).commit()
    }

    fun usesStrongBox(): Boolean = prefs.getBoolean(KEY_STRONGBOX, false)

    /** Encrypts and stores [keys], replacing any existing wallet. */
    fun save(keys: XteKeys) {
        val spend = keys.privateSpendKey()
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(keys.address.toByteArray(Charsets.US_ASCII))
            val ct = cipher.doFinal(spend)
            val iv = cipher.iv
            require(iv.size == IV_LEN)
            dir.mkdirs()
            val tmp = File(dir, "spend.bin.tmp")
            tmp.writeBytes(byteArrayOf(VERSION) + iv + ct)
            if (!tmp.renameTo(file)) {
                tmp.delete()
                throw IllegalStateException("could not write wallet file")
            }
            prefs.edit().putString(KEY_ADDRESS, keys.address).commit()
        } finally {
            spend.fill(0)
        }
    }

    /** Decrypts the stored wallet. The caller must [XteKeys.wipe] it when done. */
    fun load(): XteKeys? {
        val addr = address() ?: return null
        if (!file.exists()) return null
        val data = file.readBytes()
        if (data.size < 1 + IV_LEN + 16 + 32 || data[0] != VERSION) return null
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = ks.getKey(ALIAS, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data, 1, IV_LEN))
        cipher.updateAAD(addr.toByteArray(Charsets.US_ASCII))
        val spend = cipher.doFinal(data, 1 + IV_LEN, data.size - 1 - IV_LEN)
        return try {
            val keys = XteKeys.fromSpendKey(spend)
            if (keys.address != addr) {
                keys.wipe()
                null
            } else keys
        } finally {
            spend.fill(0)
        }
    }

    /** Removes the encrypted key file, the address, and the Keystore key. */
    fun delete() {
        file.delete()
        prefs.edit().clear().commit()
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
        } catch (e: Exception) {
            Log.w(TAG, "keystore delete failed: ${e.javaClass.simpleName}")
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val wantStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (wantStrongBox) {
            try {
                return generate(strongBox = true).also {
                    prefs.edit().putBoolean(KEY_STRONGBOX, true).apply()
                }
            } catch (_: StrongBoxUnavailableException) {
                Log.i(TAG, "StrongBox unavailable, using the default keystore")
            }
        }
        prefs.edit().putBoolean(KEY_STRONGBOX, false).apply()
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(builder.build())
        return gen.generateKey()
    }

    companion object {
        private const val TAG = "WalletStore"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "xte_wallet_spend_key_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LEN = 12
        private const val VERSION: Byte = 1
        const val PREFS = "xte_wallet"
        private const val KEY_ADDRESS = "address"
        private const val KEY_STRONGBOX = "strongbox"
        private const val KEY_BACKED_UP = "backed_up"
    }
}
