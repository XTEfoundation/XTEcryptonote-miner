package com.xtefoundation.cryptonoteminer.wallet

import android.app.Activity
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.xtefoundation.cryptonoteminer.R
import java.security.SecureRandom
import kotlin.concurrent.thread

/**
 * Create / restore / view the on-device XTE wallet. Every screen here sets FLAG_SECURE
 * (no screenshots, no recent-apps preview). Keys are never logged. Revealing the seed of
 * a stored wallet needs an explicit confirmation and, when the device has a screen lock,
 * the device credential.
 */
class WalletActivity : AppCompatActivity() {

    private lateinit var store: WalletStore
    private lateinit var root: LinearLayout
    private var backupPending = false
    private var shownWords: List<String>? = null

    private val confirmCredential = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) revealStoredSeed(afterBackupOnly = pendingBackupOnly)
        else toast("Seed not shown: device credential not confirmed.")
    }
    private var pendingBackupOnly = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        store = WalletStore(this)
        val scroll = ScrollView(this).apply { setBackgroundColor(color(R.color.bg)); isFillViewport = true }
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(16)) }
        scroll.addView(root)
        setContentView(scroll)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (backupPending) toast("Write down your 25 words and confirm first.") else finish()
            }
        })
        when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_CREATE -> confirmReplaceThen { createWallet() }
            MODE_RESTORE -> showRestore()
            MODE_BACKUP -> askRevealSeed(backupOnly = true)
            else -> showView()
        }
    }

    // ------------------------------------------------------------------ create

    private fun confirmReplaceThen(action: () -> Unit) {
        if (!store.hasWallet()) { action(); return }
        AlertDialog.Builder(this)
            .setTitle("Replace wallet?")
            .setMessage("A wallet already exists on this phone. Replacing it deletes its keys here. " +
                "Without its 25-word seed, coins sent to ${short(store.address())} are lost.")
            .setPositiveButton("Replace") { _, _ -> action() }
            .setNegativeButton("Cancel") { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun createWallet() {
        clear()
        title("Creating wallet…")
        thread(name = "wallet-create") {
            try {
                val keys = XteKeys.generate(SecureRandom())
                store.save(keys)
                store.setBackedUp(false)
                val words = keys.mnemonic()
                val address = keys.address
                keys.wipe()
                runOnUiThread { showBackup(words, address) }
            } catch (e: Exception) {
                Log.e(TAG, "wallet creation failed: ${e.javaClass.simpleName}")
                runOnUiThread { toast("Wallet creation failed."); finish() }
            }
        }
    }

    // ------------------------------------------------------------------ seed backup

    private fun showBackup(words: List<String>, address: String) {
        backupPending = !store.isBackedUp()
        shownWords = words
        clear()
        title("Back up your seed")
        warning(
            "These 25 words are the only backup of this wallet. Write them on paper, in order, and keep " +
                "them offline. Anyone with these words can spend your coins. If you lose this phone and the " +
                "words, your coins are gone. Never type them into a website or send them to anyone."
        )
        seedGrid(words)
        val cb = CheckBox(this).apply {
            text = "I wrote down all 25 words in order and stored them safely."
            setTextColor(color(R.color.text))
        }
        root.addView(cb)
        val btn = button("Continue") {
            backupPending = false
            shownWords = null
            store.setBackedUp(true)
            setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_ADDRESS, address))
            showView()
        }
        btn.isEnabled = false
        cb.setOnCheckedChangeListener { _, c -> btn.isEnabled = c }
    }

    private fun askRevealSeed(backupOnly: Boolean) {
        if (!store.hasWallet()) { toast("No wallet on this phone."); finish(); return }
        AlertDialog.Builder(this)
            .setTitle("Show seed words?")
            .setMessage("Make sure nobody can see your screen. The 25 words give full control of your coins.")
            .setPositiveButton("Show") { _, _ -> authenticateThenReveal(backupOnly) }
            .setNegativeButton("Cancel") { _, _ -> if (backupOnly) finish() }
            .show()
    }

    private fun authenticateThenReveal(backupOnly: Boolean) {
        val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        pendingBackupOnly = backupOnly
        if (km.isDeviceSecure) {
            @Suppress("DEPRECATION")
            val i = km.createConfirmDeviceCredentialIntent("XTE wallet", "Confirm to show your seed words")
            if (i != null) { confirmCredential.launch(i); return }
        }
        revealStoredSeed(backupOnly)
    }

    private fun revealStoredSeed(afterBackupOnly: Boolean) {
        val keys = try { store.load() } catch (e: Exception) {
            Log.e(TAG, "wallet load failed: ${e.javaClass.simpleName}")
            null
        }
        if (keys == null) { toast("Could not unlock the wallet."); if (afterBackupOnly) finish(); return }
        val words = keys.mnemonic()
        val address = keys.address
        keys.wipe()
        showBackup(words, address)
    }

    // ------------------------------------------------------------------ restore

    private fun showRestore() {
        clear()
        title("Restore from seed")
        text("Enter your 25-word XTE seed (English, separated by spaces).")
        val et = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            minLines = 4
            gravity = Gravity.TOP
            setTextColor(color(R.color.text))
        }
        root.addView(et)
        button("Restore") {
            val phrase = et.text.toString()
            val (keys, err) = XteKeys.fromMnemonic(phrase)
            if (keys == null) { toast(err ?: "Invalid seed."); return@button }
            val doSave = {
                try {
                    store.save(keys)
                    store.setBackedUp(true)
                    et.text.clear()
                    setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_ADDRESS, keys.address))
                    keys.wipe()
                    showView()
                } catch (e: Exception) {
                    keys.wipe()
                    Log.e(TAG, "wallet restore failed: ${e.javaClass.simpleName}")
                    toast("Could not store the wallet.")
                }
            }
            if (store.hasWallet() && store.address() != keys.address) {
                AlertDialog.Builder(this)
                    .setTitle("Replace wallet?")
                    .setMessage("This replaces the wallet ${short(store.address())} on this phone.")
                    .setPositiveButton("Replace") { _, _ -> doSave() }
                    .setNegativeButton("Cancel") { _, _ -> keys.wipe() }
                    .show()
            } else doSave()
        }
        button("Cancel") { finish() }
    }

    // ------------------------------------------------------------------ view

    private fun showView() {
        clear()
        val address = store.address()
        if (address == null || !store.hasWallet()) {
            title("No wallet")
            button("Create wallet") { confirmReplaceThen { createWallet() } }
            button("Restore from seed") { showRestore() }
            return
        }
        title("Your XTE wallet")
        text("Receive address (mining payouts go here):")
        val tv = TextView(this).apply {
            text = address
            setTextIsSelectable(true)
            typeface = Typeface.MONOSPACE
            setTextColor(color(R.color.text))
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(tv)
        qr(address)?.let { bmp ->
            root.addView(ImageView(this).apply {
                setImageBitmap(bmp)
                adjustViewBounds = true
                layoutParams = LinearLayout.LayoutParams(dp(220), dp(220)).apply { gravity = Gravity.CENTER_HORIZONTAL }
            })
        }
        button("Copy address") {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("XTE address", address))
            toast("Address copied")
        }
        button("Use this address for mining") {
            setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_ADDRESS, address))
            finish()
        }
        dim(
            "This wallet only creates keys and an address on this phone. It cannot show a balance or send " +
                "coins in this version. To spend, restore the 25-word seed in an XTE wallet that supports it. " +
                "Keys are encrypted with an Android Keystore key" +
                (if (store.usesStrongBox()) " (StrongBox)." else ".")
        )
        button("Show seed words") { askRevealSeed(backupOnly = false) }
        button("Delete wallet from this phone") {
            AlertDialog.Builder(this)
                .setTitle("Delete wallet?")
                .setMessage("This erases the keys from this phone. Without your 25-word seed, coins at this " +
                    "address are lost forever.")
                .setPositiveButton("Delete") { _, _ -> store.delete(); toast("Wallet deleted"); showView() }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    // ------------------------------------------------------------------ helpers

    private fun seedGrid(words: List<String>) {
        val sb = StringBuilder()
        words.forEachIndexed { i, w ->
            sb.append(String.format("%2d. %-12s", i + 1, w))
            if (i % 2 == 1) sb.append('\n')
        }
        root.addView(TextView(this).apply {
            text = sb.toString()
            typeface = Typeface.MONOSPACE
            textSize = 16f
            setTextColor(color(R.color.text))
            setBackgroundColor(color(R.color.card))
            setPadding(dp(12), dp(12), dp(12), dp(12))
        })
    }

    private fun qr(text: String): Bitmap? = try {
        val size = 512
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.MARGIN to 2))
        val px = IntArray(size * size) { if (m[it % size, it / size]) Color.BLACK else Color.WHITE }
        Bitmap.createBitmap(px, size, size, Bitmap.Config.ARGB_8888)
    } catch (_: Exception) {
        null
    }

    private fun clear() = root.removeAllViews()
    private fun title(s: String) = root.addView(TextView(this).apply {
        text = s; textSize = 20f; setTextColor(color(R.color.text)); setPadding(0, 0, 0, dp(12))
    })
    private fun text(s: String) = root.addView(TextView(this).apply { text = s; setTextColor(color(R.color.text)) })
    private fun dim(s: String) = root.addView(TextView(this).apply {
        text = s; textSize = 12f; setTextColor(color(R.color.text_dim)); setPadding(0, dp(12), 0, dp(4))
    })
    private fun warning(s: String) = root.addView(TextView(this).apply {
        text = s; setTextColor(color(R.color.danger)); setPadding(0, 0, 0, dp(12))
    })
    private fun button(label: String, onClick: () -> Unit): Button = Button(this).apply {
        text = label
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            .apply { topMargin = dp(8) }
    }.also { root.addView(it) }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
    private fun color(id: Int) = ContextCompat.getColor(this, id)
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun short(a: String?) = if (a == null || a.length < 16) "this wallet" else a.take(8) + "…" + a.takeLast(6)

    override fun onStop() {
        super.onStop()
        // Do not leave seed words on screen when the app goes to the background.
        if (shownWords != null && store.isBackedUp()) {
            backupPending = false
            shownWords = null
            showView()
        }
    }

    companion object {
        private const val TAG = "WalletActivity"
        const val EXTRA_MODE = "mode"
        const val EXTRA_ADDRESS = "address"
        const val MODE_CREATE = "create"
        const val MODE_RESTORE = "restore"
        const val MODE_VIEW = "view"
        const val MODE_BACKUP = "backup"
    }
}
