package com.xtefoundation.cryptonoteminer

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/**
 * Strict parser for a serialized traaitt (CryptoNote / TurtleCoin family) block or
 * `getblocktemplate` blob, plus the hashing blobs the consensus code derives from it.
 *
 * Source of truth: TRRXITTE/traaitt master
 * - `src/serialization/CryptoNoteSerialization.cpp`: `serializeBlockHeader`,
 *   `serialize(BlockTemplate)`, `serialize(ParentBlockSerializer)`,
 *   `serialize(Transaction)`, `serialize(BaseTransaction)`, mm-tag `doSerialize`
 * - `src/cryptonotecore/CachedBlock.cpp`: `getBlockHashingBinaryArray`,
 *   `getParentBlockHashingBinaryArray`, `getBlockHash`, `getBlockLongHash`,
 *   `getAuxiliaryBlockHeaderHash`
 * - `src/common/CryptoNoteTools.h`: `getObjectHash`, `getBaseTransactionHash`
 * - `src/common/TransactionExtra.cpp`: `parseTransactionExtra`
 * - `src/crypto/tree-hash.c`: `tree_hash`, `tree_depth`, `tree_hash_from_branch`
 * - `src/miner/MinerManager.cpp` + `src/miner/BlockUtilities.cpp`: the coin's own
 *   solo miner (`adjustMergeMiningTag`, `getMerkleRoot`, `getBlockLongHash`)
 * - `src/common/CheckDifficulty.cpp`: `check_hash`
 *
 * Every read is bounds-checked; any malformed, truncated, oversized or trailing data
 * throws [IllegalArgumentException]. Unsupported shapes (key inputs in a coinbase,
 * non-key outputs, unknown versions) are rejected rather than guessed.
 */
class CryptoNoteBlock private constructor(
    /** Serialized block exactly as received (never modified). */
    val raw: ByteArray,
    val majorVersion: Int,
    val minorVersion: Int,
    /** For v1: header timestamp. For v2+: the parent-block timestamp (`BlockTemplate.timestamp`). */
    val timestamp: Long,
    val previousBlockHash: ByteArray,
    /** Offset of the 4-byte LE `BlockTemplate.nonce` inside [raw]. */
    val nonceOffset: Int,
    /** `raw[0, headerEnd)` is the serialized `BlockHeader` (major, minor, prev_id for v2+). */
    private val headerEnd: Int,
    private val parent: ParentBlock?,
    val minerTx: TxSpan,
    val transactionHashes: List<ByteArray>
) {
    class TxSpan(
        val start: Int,
        /** End of the transaction prefix (after `extra`). */
        val prefixEnd: Int,
        val end: Int,
        val version: Long,
        val extraStart: Int,
        val extraLength: Int
    )

    class ParentBlock(
        /** `raw[headerStart, headerEnd)` = major, minor, timestamp, prevId, nonce. */
        val headerStart: Int,
        val headerEnd: Int,
        val transactionCount: Int,
        val baseTransactionBranch: List<ByteArray>,
        val baseTransaction: TxSpan,
        /** Offset in raw of the 32-byte merge-mining tag merkle root. */
        val mmRootOffset: Int,
        val mmDepth: Int,
        val blockchainBranch: List<ByteArray>,
        val end: Int
    )

    val nonce: Int get() = loadLe32(raw, nonceOffset)
    val hasParentBlock: Boolean get() = parent != null
    val parentMmRootOffset: Int get() = parent?.mmRootOffset ?: -1
    val parentMmDepth: Int get() = parent?.mmDepth ?: -1

    /** `getObjectHash(block.baseTransaction)` — Transaction serialization, raw cn_fast_hash. */
    fun minerTxHash(): ByteArray = Keccak.cnFastHash(raw.copyOfRange(minerTx.start, minerTx.end))

    /** `CachedBlock::getTransactionTreeHash`. */
    fun transactionTreeHash(): ByteArray = treeHash(listOf(minerTxHash()) + transactionHashes)

    /** `CachedBlock::getBlockHashingBinaryArray`: BlockHeader || tree hash || varint(tx count). */
    fun blockHashingBlob(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(raw, 0, headerEnd)
        out.write(transactionTreeHash())
        out.write(varint((transactionHashes.size + 1).toLong()))
        return out.toByteArray()
    }

    /**
     * `CachedBlock::getAuxiliaryBlockHeaderHash` = `getObjectHash(getBlockHashingBinaryArray())`.
     * `getObjectHash` of a BinaryArray serializes it first, so the hash input is
     * `varint(size) || blob`. This is the value the coin's miner writes into the
     * parent coinbase merge-mining tag (`MinerManager.cpp: adjustMergeMiningTag`).
     */
    fun auxiliaryBlockHeaderHash(): ByteArray = objectHashOfBlob(blockHashingBlob())

    /** `getBaseTransactionHash(parentBlock.baseTransaction)` for the parent coinbase. */
    private fun parentBaseTxHash(p: ParentBlock): ByteArray {
        val tx = p.baseTransaction
        if (tx.version < 2) {
            return Keccak.cnFastHash(raw.copyOfRange(tx.start, tx.end))
        }
        val data = ByteArray(96)
        System.arraycopy(Keccak.cnFastHash(raw.copyOfRange(tx.start, tx.prefixEnd)), 0, data, 0, 32)
        System.arraycopy(V2_BASE_TX_RCT_HASH, 0, data, 32, 32)
        return Keccak.cnFastHash(data)
    }

    /**
     * `serialize(ParentBlockSerializer)` with `hashingSerialization=true`.
     * headerOnly=true is the PoW input (`getParentBlockHashingBinaryArray(true)`).
     */
    fun parentHashingBlob(headerOnly: Boolean): ByteArray {
        val p = parent ?: throw IllegalStateException("v1 block has no parent block")
        val out = ByteArrayOutputStream()
        out.write(raw, p.headerStart, p.headerEnd - p.headerStart)
        out.write(treeHashFromBranch(p.baseTransactionBranch, parentBaseTxHash(p)))
        out.write(varint(p.transactionCount.toLong()))
        if (!headerOnly) {
            for (h in p.baseTransactionBranch) out.write(h)
            out.write(raw, p.baseTransaction.start, p.baseTransaction.end - p.baseTransaction.start)
            for (h in p.blockchainBranch) out.write(h)
        }
        return out.toByteArray()
    }

    /** `CachedBlock::getBlockLongHash` input (Chukwa for major 6). */
    fun powHashingBlob(): ByteArray =
        if (majorVersion == 1) blockHashingBlob() else parentHashingBlob(headerOnly = true)

    /** Offset of the nonce inside [powHashingBlob]. */
    fun powNonceOffset(): Int = if (parent == null) nonceOffset else nonceOffset - parent.headerStart

    /** `CachedBlock::getBlockHash` (block id shown by explorers). */
    fun blockHash(): ByteArray {
        val blob = blockHashingBlob()
        val input = if (parent == null) blob else blob + parentHashingBlob(headerOnly = false)
        return objectHashOfBlob(input)
    }

    companion object {
        const val MAX_MAJOR_VERSION = 6 // BLOCK_MAJOR_VERSION_6, serializeBlockHeader rejects higher
        const val CHUKWA_MAJOR_VERSION = 6 // HASHING_ALGORITHMS_BY_BLOCK_VERSION: v6 -> chukwa_slow_hash
        private const val HASH = 32
        private const val TAG_BASE_INPUT = 0xff
        private const val TAG_KEY_INPUT = 0x02
        private const val TAG_KEY_OUTPUT = 0x02
        private const val TX_EXTRA_TAG_PADDING = 0x00
        private const val TX_EXTRA_TAG_PUBKEY = 0x01
        private const val TX_EXTRA_NONCE = 0x02
        private const val TX_EXTRA_MERGE_MINING_TAG = 0x03
        private const val MAX_VEC = 10_000 // inputs/outputs/tx hashes per block, far above real use
        private const val MAX_EXTRA = 8_192
        private const val MAX_MM_DEPTH = 8 * HASH // CryptoNoteSerialization.cpp: depth > 8*sizeof(Hash)

        /** Constant from `getBaseTransactionHash` (CryptoNoteTools.h) for v2 base transactions. */
        private val V2_BASE_TX_RCT_HASH = MinerValidation.hexToBytes(
            "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
        )

        fun parse(blob: ByteArray): CryptoNoteBlock {
            require(blob.size in 1..MinerValidation.MAX_BLOCK_BLOB_BYTES) { "block blob size" }
            val r = Reader(blob)
            val major = r.varint8()
            val minor = r.varint8()
            if (major < 1 || major > MAX_MAJOR_VERSION) throw IllegalArgumentException("unsupported major version")
            val timestamp: Long
            val prev: ByteArray
            val nonceOffset: Int
            val headerEnd: Int
            var parent: ParentBlock? = null
            if (major == 1) {
                timestamp = r.varint()
                prev = r.bytes(HASH)
                nonceOffset = r.pos
                r.skip(4)
                headerEnd = r.pos
            } else {
                prev = r.bytes(HASH)
                headerEnd = r.pos
                // ParentBlockSerializer (hashingSerialization=false, headerOnly=false)
                val pStart = r.pos
                r.varint8() // parent majorVersion
                r.varint8() // parent minorVersion
                timestamp = r.varint()
                r.skip(HASH) // parent prevId
                nonceOffset = r.pos
                r.skip(4)
                val pHeaderEnd = r.pos
                val txNum = r.varint()
                if (txNum < 1 || txNum > 0xffff) throw IllegalArgumentException("parent tx count")
                val branch = List(treeDepth(txNum.toInt())) { r.bytes(HASH) }
                val ptx = readTx(r, base = true)
                val mm = findMergeMiningTag(blob, ptx.extraStart, ptx.extraLength)
                    ?: throw IllegalArgumentException("parent coinbase has no merge mining tag")
                if (mm.second > MAX_MM_DEPTH) throw IllegalArgumentException("merge mining depth")
                val bcBranch = List(mm.second) { r.bytes(HASH) }
                parent = ParentBlock(
                    pStart, pHeaderEnd, txNum.toInt(), branch, ptx, mm.first, mm.second, bcBranch, r.pos
                )
            }
            val minerTx = readTx(r, base = false)
            val n = r.count()
            val hashes = List(n) { r.bytes(HASH) }
            if (!r.atEnd()) throw IllegalArgumentException("trailing bytes after block")
            return CryptoNoteBlock(
                blob.copyOf(), major, minor, timestamp, prev, nonceOffset, headerEnd, parent, minerTx, hashes
            )
        }

        /**
         * `serialize(Transaction)` (base=false) / `serialize(BaseTransaction)` (base=true).
         * Only coinbase shapes are accepted: base inputs (0xff) and key outputs (0x02).
         * A base input carries no signatures (`getSignaturesCount(BaseInput) == 0`).
         */
        private fun readTx(r: Reader, base: Boolean): TxSpan {
            val start = r.pos
            val version = r.varint()
            if (version > 2) throw IllegalArgumentException("unsupported tx version")
            r.varint() // unlockTime
            val inputs = r.count()
            for (i in 0 until inputs) {
                when (r.u8()) {
                    TAG_BASE_INPUT -> r.varint() // blockIndex
                    TAG_KEY_INPUT -> throw IllegalArgumentException("key input in coinbase")
                    else -> throw IllegalArgumentException("unknown input type")
                }
            }
            val outputs = r.count()
            for (i in 0 until outputs) {
                r.varint() // amount
                if (r.u8() != TAG_KEY_OUTPUT) throw IllegalArgumentException("unknown output type")
                r.skip(HASH)
            }
            val extraLen = r.varint()
            if (extraLen > MAX_EXTRA) throw IllegalArgumentException("tx extra too large")
            val extraStart = r.pos
            r.skip(extraLen.toInt())
            val prefixEnd = r.pos
            if (base && version >= 2) r.varint() // BaseTransaction "ignored" field
            return TxSpan(start, prefixEnd, r.pos, version, extraStart, extraLen.toInt())
        }

        /**
         * `parseTransactionExtra` + `getMergeMiningTagFromExtra`.
         * Returns (offset of the merkle root in the blob, depth) or null.
         */
        private fun findMergeMiningTag(blob: ByteArray, start: Int, len: Int): Pair<Int, Int>? {
            val r = Reader(blob, start, start + len)
            var seenPk = false
            var seenNonce = false
            while (!r.atEnd()) {
                when (r.u8()) {
                    // Padding runs to the end of extra, so no mm tag can follow it.
                    TX_EXTRA_TAG_PADDING -> return null
                    TX_EXTRA_TAG_PUBKEY -> {
                        if (seenPk) return null
                        seenPk = true
                        r.skip(HASH)
                    }
                    TX_EXTRA_NONCE -> {
                        if (seenNonce) return null
                        seenNonce = true
                        r.skip(r.u8())
                    }
                    TX_EXTRA_MERGE_MINING_TAG -> {
                        val fieldLen = r.varint()
                        val fieldStart = r.pos
                        if (fieldLen > 64) throw IllegalArgumentException("mm tag size")
                        r.skip(fieldLen.toInt())
                        val f = Reader(blob, fieldStart, fieldStart + fieldLen.toInt())
                        val depth = f.varint()
                        val rootOffset = f.pos
                        f.skip(HASH)
                        if (!f.atEnd()) throw IllegalArgumentException("mm tag trailing bytes")
                        if (depth > MAX_MM_DEPTH) throw IllegalArgumentException("merge mining depth")
                        return Pair(rootOffset, depth.toInt())
                    }
                    else -> return null
                }
            }
            return null
        }

        /** `tree_depth` from tree-hash.c (floor(log2(count))). */
        fun treeDepth(count: Int): Int {
            require(count > 0) { "tree depth of 0" }
            return 31 - Integer.numberOfLeadingZeros(count)
        }

        /** `tree_hash` from tree-hash.c. */
        fun treeHash(hashes: List<ByteArray>): ByteArray {
            val count = hashes.size
            require(count > 0) { "empty tree" }
            hashes.forEach { require(it.size == HASH) { "hash size" } }
            if (count == 1) return hashes[0].copyOf()
            if (count == 2) return Keccak.cnFastHash(hashes[0] + hashes[1])
            var cnt = Integer.highestOneBit(count - 1) // largest power of two < count
            val ints = ArrayList<ByteArray>(cnt)
            for (k in 0 until 2 * cnt - count) ints.add(hashes[k])
            var i = 2 * cnt - count
            while (i < count) {
                ints.add(Keccak.cnFastHash(hashes[i] + hashes[i + 1]))
                i += 2
            }
            check(ints.size == cnt)
            while (cnt > 2) {
                cnt = cnt shr 1
                for (j in 0 until cnt) ints[j] = Keccak.cnFastHash(ints[2 * j] + ints[2 * j + 1])
            }
            return Keccak.cnFastHash(ints[0] + ints[1])
        }

        /** `tree_hash_from_branch` with a zero path (leaf is always the left child). */
        fun treeHashFromBranch(branch: List<ByteArray>, leaf: ByteArray): ByteArray {
            var cur = leaf.copyOf()
            for (d in branch.indices.reversed()) cur = Keccak.cnFastHash(cur + branch[d])
            return cur
        }

        /** `getObjectHash(BinaryArray)`: cn_fast_hash(varint(size) || blob). */
        fun objectHashOfBlob(blob: ByteArray): ByteArray = Keccak.cnFastHash(varint(blob.size.toLong()) + blob)

        fun varint(value: Long): ByteArray {
            require(value >= 0) { "negative varint" }
            val out = ByteArrayOutputStream(10)
            var v = value
            while (v >= 0x80) {
                out.write(((v and 0x7f) or 0x80).toInt())
                v = v ushr 7
            }
            out.write(v.toInt())
            return out.toByteArray()
        }

        private val TWO_256: BigInteger = BigInteger.ONE.shiftLeft(256)

        /**
         * `check_hash` (CheckDifficulty.cpp): the hash, read as a 256-bit little-endian
         * integer, times difficulty must not overflow 256 bits.
         */
        fun checkHash(hash: ByteArray, difficulty: Long): Boolean {
            require(hash.size == HASH) { "hash size" }
            if (difficulty == 0L) return false
            val be = hash.reversedArray()
            val h = BigInteger(1, be)
            val d = BigInteger(java.lang.Long.toUnsignedString(difficulty))
            return h.multiply(d) < TWO_256
        }

        fun loadLe32(b: ByteArray, off: Int): Int =
            (b[off].toInt() and 0xff) or
                ((b[off + 1].toInt() and 0xff) shl 8) or
                ((b[off + 2].toInt() and 0xff) shl 16) or
                ((b[off + 3].toInt() and 0xff) shl 24)

        fun storeLe32(b: ByteArray, off: Int, v: Int) {
            b[off] = v.toByte()
            b[off + 1] = (v ushr 8).toByte()
            b[off + 2] = (v ushr 16).toByte()
            b[off + 3] = (v ushr 24).toByte()
        }
    }

    /** Bounds-checked cursor over `buf[pos, limit)`. */
    private class Reader(private val buf: ByteArray, start: Int = 0, private val limit: Int = buf.size) {
        var pos: Int = start
            private set

        init {
            require(start in 0..limit && limit <= buf.size) { "bad reader range" }
        }

        fun atEnd(): Boolean = pos == limit

        fun u8(): Int {
            if (pos >= limit) throw IllegalArgumentException("truncated")
            return buf[pos++].toInt() and 0xff
        }

        fun skip(n: Int) {
            if (n < 0 || n > limit - pos) throw IllegalArgumentException("truncated")
            pos += n
        }

        fun bytes(n: Int): ByteArray {
            val start = pos
            skip(n)
            return buf.copyOfRange(start, start + n)
        }

        /** CryptoNote varint (LEB128), at most 63 bits, canonical (no trailing zero groups). */
        fun varint(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                val b = u8()
                if (shift == 63 && b > 1) throw IllegalArgumentException("varint overflow")
                if (shift > 63) throw IllegalArgumentException("varint overflow")
                result = result or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) {
                    if (b == 0 && shift > 0) throw IllegalArgumentException("non-canonical varint")
                    if (result < 0) throw IllegalArgumentException("varint overflow")
                    return result
                }
                shift += 7
            }
        }

        fun varint8(): Int {
            val v = varint()
            if (v > 0xff) throw IllegalArgumentException("uint8 out of range")
            return v.toInt()
        }

        /** Element count, capped so that a hostile count cannot drive huge allocations. */
        fun count(): Int {
            val v = varint()
            if (v > MAX_VEC || v > (limit - pos).toLong()) throw IllegalArgumentException("count out of range")
            return v.toInt()
        }
    }
}

/**
 * A solo job derived from a `getblocktemplate` response, prepared the way the coin's
 * own miner does it (`src/miner/MinerManager.cpp: adjustMergeMiningTag`): the parent
 * coinbase merge-mining tag (depth 0) gets `merkleRoot = getMerkleRoot(block)` =
 * aux header hash. Nothing else in the template is changed. The PoW input is
 * `getParentBlockHashingBinaryArray(headerOnly=true)`, the nonce is
 * `BlockTemplate.nonce` (serialized inside the parent block header).
 */
class SoloJob private constructor(
    val jobId: String,
    val height: Long,
    val difficulty: Long,
    val majorVersion: Int,
    val previousBlockHash: ByteArray,
    /** Full block blob with the mm tag filled in; nonce bytes are overwritten on submit. */
    private val blockBlob: ByteArray,
    private val blockNonceOffset: Int,
    /** Chukwa input; the native hasher writes the nonce at [MinerValidation.NONCE_OFFSET]. */
    val hashingBlob: ByteArray
) {
    val target64: Long get() = MinerValidation.targetFromDifficulty(difficulty)

    fun hashingBlobCopy(): ByteArray = hashingBlob.copyOf()

    /** Full block for `submitblock` with [nonce] written at the header nonce position. */
    fun blockWithNonce(nonce: Int): ByteArray {
        val b = blockBlob.copyOf()
        CryptoNoteBlock.storeLe32(b, blockNonceOffset, nonce)
        return b
    }

    /** Hashing blob with [nonce] at offset 39, as the native worker hashes it. */
    fun hashingBlobWithNonce(nonce: Int): ByteArray {
        val b = hashingBlob.copyOf()
        CryptoNoteBlock.storeLe32(b, MinerValidation.NONCE_OFFSET, nonce)
        return b
    }

    companion object {
        /**
         * @param requireChukwa reject templates whose major version is not hashed with
         * Chukwa. The app only implements Chukwa, so production always passes true.
         */
        fun fromTemplate(
            jobId: String,
            templateBlob: ByteArray,
            height: Long,
            difficulty: Long,
            requireChukwa: Boolean = true
        ): SoloJob {
            require(MinerValidation.isJobId(jobId)) { "bad job id" }
            require(difficulty != 0L) { "difficulty is 0" }
            val tpl = CryptoNoteBlock.parse(templateBlob)
            if (requireChukwa && tpl.majorVersion != CryptoNoteBlock.CHUKWA_MAJOR_VERSION) {
                throw IllegalArgumentException("template major version is not Chukwa (v6)")
            }
            if (!tpl.hasParentBlock) throw IllegalArgumentException("v1 templates are not supported")
            if (tpl.parentMmDepth != 0) throw IllegalArgumentException("unexpected merge mining depth")

            // adjustMergeMiningTag: depth 0, merkleRoot = getMerkleRoot(block).
            // The aux hash covers header + tx tree only (no nonce, no parent), so it is fixed per template.
            val filled = templateBlob.copyOf()
            val aux = tpl.auxiliaryBlockHeaderHash()
            System.arraycopy(aux, 0, filled, tpl.parentMmRootOffset, 32)

            val block = CryptoNoteBlock.parse(filled)
            val hashing = block.powHashingBlob()
            if (block.powNonceOffset() != MinerValidation.NONCE_OFFSET) {
                throw IllegalArgumentException("nonce not at hashing-blob offset 39")
            }
            if (hashing.size < MinerValidation.MIN_BLOB_BYTES || hashing.size > MinerValidation.MAX_JOB_BLOB_BYTES) {
                throw IllegalArgumentException("hashing blob size")
            }
            return SoloJob(
                jobId, height, difficulty, block.majorVersion, block.previousBlockHash,
                filled, block.nonceOffset, hashing
            )
        }
    }
}
