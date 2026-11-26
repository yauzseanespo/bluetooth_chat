package com.bluetooth.chat

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoAndFraming {
    const val FRAME_HEADER_SIZE = 5
    private const val FLAG_LAST_CHUNK: Byte = 0x01
    private val rng = SecureRandom()

    fun hexToBytes32(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length == 64) { "Anahtar 64 hex karakter (32 byte) olmalıdır." }
        return ByteArray(32) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun encryptAesGcm(key: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 için 32 byte anahtar gerekir." }
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        return nonce + ciphertext
    }

    fun decryptAesGcm(key: ByteArray, payload: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 için 32 byte anahtar gerekir." }
        require(payload.size >= 12) { "Şifreli veri 12-byte nonce içermiyor." }
        val nonce = payload.copyOfRange(0, 12)
        val ciphertext = payload.copyOfRange(12, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext)
    }

    fun chunkMessage(data: ByteArray, maxPacketSize: Int = 20): List<ByteArray> {
        require(maxPacketSize > FRAME_HEADER_SIZE) { "MTU > $FRAME_HEADER_SIZE olmalıdır." }
        val maxPayload = maxPacketSize - FRAME_HEADER_SIZE
        val total = if (data.isEmpty()) 1 else (data.size + maxPayload - 1) / maxPayload
        val frames = ArrayList<ByteArray>(total)

        if (data.isEmpty()) {
            val bb = ByteBuffer.allocate(FRAME_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            bb.put(FLAG_LAST_CHUNK)
            bb.putShort(0)
            bb.putShort(1)
            frames.add(bb.array())
            return frames
        }

        var offset = 0
        var seq = 0
        while (offset < data.size) {
            val end = minOf(offset + maxPayload, data.size)
            val sliceLen = end - offset
            val flags: Byte = if (seq + 1 == total) FLAG_LAST_CHUNK else 0
            val bb = ByteBuffer.allocate(FRAME_HEADER_SIZE + sliceLen).order(ByteOrder.LITTLE_ENDIAN)
            bb.put(flags)
            bb.putShort(seq.toShort())
            bb.putShort(total.toShort())
            bb.put(data, offset, sliceLen)
            frames.add(bb.array())
            offset = end
            seq++
        }
        return frames
    }
}

class FrameAssembler {
    private var expectedTotal: Int? = null
    private var receivedCount = 0
    private var slots: Array<ByteArray?> = emptyArray()

    fun reset() {
        expectedTotal = null
        receivedCount = 0
        slots = emptyArray()
    }

    fun pushChunk(frame: ByteArray): ByteArray? {
        if (frame.size < CryptoAndFraming.FRAME_HEADER_SIZE) return null
        val bb = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN)
        bb.get() // flags
        val seq = bb.short.toInt() and 0xFFFF
        val total = bb.short.toInt() and 0xFFFF
        if (total == 0 || seq >= total) return null

        val payload = frame.copyOfRange(CryptoAndFraming.FRAME_HEADER_SIZE, frame.size)
        if (expectedTotal == null) {
            expectedTotal = total
            slots = arrayOfNulls(total)
        } else if (expectedTotal != total) {
            reset()
            return null
        }

        if (slots[seq] == null) {
            slots[seq] = payload
            receivedCount++
        }

        if (receivedCount == total) {
            val totalBytes = slots.sumOf { it?.size ?: 0 }
            val result = ByteArray(totalBytes)
            var pos = 0
            for (slot in slots) {
                if (slot != null) {
                    System.arraycopy(slot, 0, result, pos, slot.size)
                    pos += slot.size
                }
            }
            reset()
            return result
        }
        return null
    }
}
