package io.datasteward.steward_app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.security.SecureRandom
import java.net.URI
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecurePairingExecutor(context: Context) {
    private val preferences =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val random = SecureRandom()

    @Synchronized
    fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            val response =
                when (call.method) {
                    "status" -> status()
                    "createPending" ->
                        createPending(
                            requireString(call, "pairingAttemptId"),
                            requireString(call, "hubId"),
                            requireString(call, "baseUrl"),
                            requireString(call, "certFingerprint"),
                            requireString(call, "pairingSessionId"),
                            requireStringList(call, "requestedCapabilities"),
                        )
                    "loadPending" -> pendingMap(requireRecord("pending"))
                    "saveHello" ->
                        saveHello(
                            requireString(call, "deviceId"),
                            requireString(call, "shortCode"),
                        )
                    "activate" ->
                        activate(
                            requireString(call, "deviceId"),
                            requireString(call, "hubId"),
                            requireString(call, "baseUrl"),
                            requireString(call, "certFingerprint"),
                            requireInt(call, "capabilityEpoch"),
                            requireStringList(call, "grantedCapabilities"),
                        )
                    "loadActive" -> activeMap(requireRecord("active"))
                    "updateActiveEndpoint" ->
                        updateActiveEndpoint(
                            requireString(call, "hubId"),
                            requireString(call, "baseUrl"),
                            requireString(call, "certFingerprint"),
                        )
                    "updateActiveAuthorization" ->
                        updateActiveAuthorization(
                            requireString(call, "deviceId"),
                            requireString(call, "hubId"),
                            requireInt(call, "capabilityEpoch"),
                            requireStringList(call, "grantedCapabilities"),
                        )
                    "updateActiveEndpointAndAuthorization" ->
                        updateActiveEndpointAndAuthorization(
                            requireString(call, "deviceId"),
                            requireString(call, "hubId"),
                            requireString(call, "baseUrl"),
                            requireString(call, "certFingerprint"),
                            requireInt(call, "capabilityEpoch"),
                            requireStringList(call, "grantedCapabilities"),
                        )
                    "delete" -> delete()
                    else -> {
                        result.notImplemented()
                        return
                    }
                }
            result.success(response)
        } catch (error: SecurePairingStorageException) {
            result.error(error.code, error.code, null)
        } catch (_: Exception) {
            result.error("secure_storage_unavailable", "secure_storage_unavailable", null)
        }
    }

    private fun status(): Map<String, Any> {
        if (!preferences.contains(KEY_CIPHERTEXT) && !preferences.contains(KEY_IV)) {
            return mapOf("status" to "empty")
        }
        val record = loadRecord()
        return mapOf("status" to requireState(record))
    }

    private fun createPending(
        pairingAttemptId: String,
        hubId: String,
        baseUrl: String,
        certFingerprint: String,
        pairingSessionId: String,
        requestedCapabilities: List<String>,
    ): Map<String, Any?> {
        requireUlid(pairingAttemptId)
        requireUlid(hubId)
        requireUlid(pairingSessionId)
        requireBaseUrl(baseUrl)
        requireFingerprint(certFingerprint)
        val capabilities = canonicalCapabilities(requestedCapabilities)
        if (preferences.contains(KEY_CIPHERTEXT) || preferences.contains(KEY_IV)) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        val record =
            JSONObject().apply {
                put("version", RECORD_VERSION)
                put("state", "pending")
                put("pairingAttemptId", pairingAttemptId)
                put("hubId", hubId)
                put("baseUrl", baseUrl)
                put("certFingerprint", certFingerprint)
                put("pairingSessionId", pairingSessionId)
                put("requestedCapabilities", JSONArray(capabilities))
                put("deviceCredential", randomSecret(32))
                put("claimSecret", randomSecret(32))
                put("clientNonce", randomSecret(16))
                put("deviceId", JSONObject.NULL)
                put("shortCode", JSONObject.NULL)
            }
        saveVerified(record)
        return pendingMap(record)
    }

    private fun saveHello(deviceId: String, shortCode: String): Map<String, Any> {
        requireUlid(deviceId)
        if (!HUMAN32.matches(shortCode)) invalid()
        val record = requireRecord("pending")
        val existingDevice = record.optStringOrNull("deviceId")
        val existingCode = record.optStringOrNull("shortCode")
        if ((existingDevice != null && existingDevice != deviceId) ||
            (existingCode != null && existingCode != shortCode)
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        record.put("deviceId", deviceId)
        record.put("shortCode", shortCode)
        saveVerified(record)
        return mapOf("status" to "pending")
    }

    private fun activate(
        deviceId: String,
        hubId: String,
        baseUrl: String,
        certFingerprint: String,
        capabilityEpoch: Int,
        grantedCapabilities: List<String>,
    ): Map<String, Any> {
        requireUlid(deviceId)
        requireUlid(hubId)
        requireBaseUrl(baseUrl)
        requireFingerprint(certFingerprint)
        if (capabilityEpoch < 1) invalid()
        val capabilities = canonicalCapabilities(grantedCapabilities)
        val current = requireRecord("pending")
        if (current.optStringOrNull("deviceId") != deviceId ||
            current.optStringOrNull("shortCode") == null ||
            current.optString("hubId") != hubId ||
            current.optString("baseUrl") != baseUrl ||
            current.optString("certFingerprint") != certFingerprint
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        val active =
            JSONObject().apply {
                put("version", RECORD_VERSION)
                put("state", "active")
                put("deviceId", deviceId)
                put("hubId", hubId)
                put("baseUrl", baseUrl)
                put("certFingerprint", certFingerprint)
                put("deviceCredential", requireSecret(current, "deviceCredential", 43))
                put("capabilityEpoch", capabilityEpoch)
                put("grantedCapabilities", JSONArray(capabilities))
            }
        saveVerified(active)
        return mapOf("status" to "active")
    }

    private fun requirePrivateServiceBaseUrl(value: String): String {
        requireBaseUrl(value)
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            invalid()
        }
        val octets = uri.host.split('.').map { it.toIntOrNull() ?: invalid() }
        val privateIpv4 =
            octets.size == 4 && octets.all { it in 0..255 } &&
                (octets[0] == 10 ||
                    (octets[0] == 172 && octets[1] in 16..31) ||
                    (octets[0] == 192 && octets[1] == 168))
        if (!privateIpv4 || uri.port !in 1..65535 ||
            (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/")
        ) {
            invalid()
        }
        return value
    }

    private fun delete(): Map<String, Any> {
        if (!preferences.edit().remove(KEY_CIPHERTEXT).remove(KEY_IV).commit()) {
            throw SecurePairingStorageException("secure_storage_unavailable")
        }
        val keyStore = keyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        if (preferences.contains(KEY_CIPHERTEXT) || preferences.contains(KEY_IV)) {
            throw SecurePairingStorageException("secure_storage_unavailable")
        }
        return mapOf("status" to "empty")
    }

    private fun updateActiveEndpoint(
        hubId: String,
        baseUrl: String,
        certFingerprint: String,
    ): Map<String, Any> {
        requireUlid(hubId)
        requirePrivateServiceBaseUrl(baseUrl)
        requireFingerprint(certFingerprint)
        val record = requireRecord("active")
        if (record.optString("hubId") != hubId ||
            record.optString("certFingerprint") != certFingerprint
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        record.put("baseUrl", baseUrl)
        saveVerified(record)
        return mapOf("status" to "active")
    }

    private fun updateActiveAuthorization(
        deviceId: String,
        hubId: String,
        capabilityEpoch: Int,
        grantedCapabilities: List<String>,
    ): Map<String, Any> {
        requireUlid(deviceId)
        requireUlid(hubId)
        if (capabilityEpoch < 1) invalid()
        val capabilities = canonicalCapabilities(grantedCapabilities)
        val record = requireRecord("active")
        if (record.optString("deviceId") != deviceId ||
            record.optString("hubId") != hubId
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        val currentEpoch = record.optInt("capabilityEpoch", -1)
        if (capabilityEpoch < currentEpoch) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        if (capabilityEpoch == currentEpoch) {
            val current = requireCapabilities(record, "grantedCapabilities")
            if (current != capabilities) {
                throw SecurePairingStorageException("secure_storage_state")
            }
            return mapOf("status" to "active")
        }
        record.put("capabilityEpoch", capabilityEpoch)
        record.put("grantedCapabilities", JSONArray(capabilities))
        saveVerified(record)
        return mapOf("status" to "active")
    }

    private fun updateActiveEndpointAndAuthorization(
        deviceId: String,
        hubId: String,
        baseUrl: String,
        certFingerprint: String,
        capabilityEpoch: Int,
        grantedCapabilities: List<String>,
    ): Map<String, Any> {
        requireUlid(deviceId)
        requireUlid(hubId)
        requirePrivateServiceBaseUrl(baseUrl)
        requireFingerprint(certFingerprint)
        if (capabilityEpoch < 1) invalid()
        val capabilities = canonicalCapabilities(grantedCapabilities)
        val record = requireRecord("active")
        if (record.optString("deviceId") != deviceId ||
            record.optString("hubId") != hubId ||
            record.optString("certFingerprint") != certFingerprint
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        val currentEpoch = record.optInt("capabilityEpoch", -1)
        if (capabilityEpoch < currentEpoch) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        if (capabilityEpoch == currentEpoch &&
            requireCapabilities(record, "grantedCapabilities") != capabilities
        ) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        record.put("baseUrl", baseUrl)
        record.put("capabilityEpoch", capabilityEpoch)
        record.put("grantedCapabilities", JSONArray(capabilities))
        saveVerified(record)
        return mapOf("status" to "active")
    }

    private fun pendingMap(record: JSONObject): Map<String, Any?> {
        requireState(record, "pending")
        return mapOf(
            "pairingAttemptId" to requireUlid(record, "pairingAttemptId"),
            "hubId" to requireUlid(record, "hubId"),
            "baseUrl" to requireBaseUrl(record.optString("baseUrl", "")),
            "certFingerprint" to requireFingerprint(record.optString("certFingerprint", "")),
            "pairingSessionId" to requireUlid(record, "pairingSessionId"),
            "requestedCapabilities" to requireCapabilities(record, "requestedCapabilities"),
            "deviceCredential" to requireSecret(record, "deviceCredential", 43),
            "claimSecret" to requireSecret(record, "claimSecret", 43),
            "clientNonce" to requireSecret(record, "clientNonce", 22),
            "deviceId" to record.optStringOrNull("deviceId"),
            "shortCode" to record.optStringOrNull("shortCode"),
        )
    }

    private fun activeMap(record: JSONObject): Map<String, Any> {
        requireState(record, "active")
        val epoch = record.optInt("capabilityEpoch", -1)
        if (epoch < 1) corrupt()
        val raw = record.optJSONArray("grantedCapabilities") ?: corrupt()
        val capabilities = mutableListOf<String>()
        for (index in 0 until raw.length()) {
            val item = raw.optString(index, "")
            if (item.isEmpty()) corrupt()
            capabilities += item
        }
        if (canonicalCapabilities(capabilities) != capabilities) corrupt()
        return mapOf(
            "deviceId" to requireUlid(record, "deviceId"),
            "hubId" to requireUlid(record, "hubId"),
            "baseUrl" to requireBaseUrl(record.optString("baseUrl", "")),
            "certFingerprint" to requireFingerprint(record.optString("certFingerprint", "")),
            "deviceCredential" to requireSecret(record, "deviceCredential", 43),
            "capabilityEpoch" to epoch,
            "grantedCapabilities" to capabilities,
        )
    }

    private fun requireRecord(expectedState: String): JSONObject {
        if (!preferences.contains(KEY_CIPHERTEXT) && !preferences.contains(KEY_IV)) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        if (!preferences.contains(KEY_CIPHERTEXT) || !preferences.contains(KEY_IV)) {
            corrupt()
        }
        return loadRecord().also { requireState(it, expectedState) }
    }

    private fun saveVerified(record: JSONObject) {
        validateRecordShape(record)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(AAD)
        val encrypted = cipher.doFinal(record.toString().toByteArray(Charsets.UTF_8))
        val committed =
            preferences
                .edit()
                .putString(KEY_CIPHERTEXT, encode(encrypted))
                .putString(KEY_IV, encode(cipher.iv))
                .commit()
        if (!committed) throw SecurePairingStorageException("secure_storage_unavailable")
        val roundTrip = loadRecord()
        if (roundTrip.toString() != record.toString()) {
            throw SecurePairingStorageException("secure_storage_unavailable")
        }
    }

    private fun loadRecord(): JSONObject {
        val ciphertextText = preferences.getString(KEY_CIPHERTEXT, null)
        val ivText = preferences.getString(KEY_IV, null)
        if (ciphertextText == null || ivText == null) corrupt()
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, requireKey(), GCMParameterSpec(128, decode(ivText)))
            cipher.updateAAD(AAD)
            val plaintext = cipher.doFinal(decode(ciphertextText))
            val record = JSONObject(String(plaintext, Charsets.UTF_8))
            plaintext.fill(0)
            validateRecordShape(record)
            return record
        } catch (error: SecurePairingStorageException) {
            throw error
        } catch (_: Exception) {
            corrupt()
        }
    }

    private fun validateRecordShape(record: JSONObject) {
        if (record.optInt("version", -1) != RECORD_VERSION) corrupt()
        when (requireState(record)) {
            "pending" -> {
                val expected = setOf(
                    "version", "state", "pairingAttemptId", "hubId", "baseUrl",
                    "certFingerprint", "pairingSessionId", "requestedCapabilities",
                    "deviceCredential", "claimSecret", "clientNonce", "deviceId", "shortCode",
                )
                if (record.keys().asSequence().toSet() != expected) corrupt()
                pendingMap(record)
            }
            "active" -> {
                val expected = setOf(
                    "version", "state", "deviceId", "hubId", "baseUrl",
                    "certFingerprint", "deviceCredential", "capabilityEpoch",
                    "grantedCapabilities",
                )
                if (record.keys().asSequence().toSet() != expected) corrupt()
                activeMap(record)
            }
            else -> corrupt()
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val existing = keyStore().getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec
                .Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun requireKey(): SecretKey =
        keyStore().getKey(KEY_ALIAS, null) as? SecretKey ?: corrupt()

    private fun keyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun randomSecret(bytes: Int): String =
        ByteArray(bytes).also(random::nextBytes).let(::encode)

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(value: String): ByteArray =
        Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun requireState(record: JSONObject, expected: String? = null): String {
        val state = record.optString("state", "")
        if (state != "pending" && state != "active") corrupt()
        if (expected != null && state != expected) {
            throw SecurePairingStorageException("secure_storage_state")
        }
        return state
    }

    private fun requireString(call: MethodCall, key: String): String =
        call.argument<String>(key)?.takeIf { it.isNotEmpty() } ?: invalid()

    private fun requireInt(call: MethodCall, key: String): Int =
        call.argument<Int>(key) ?: invalid()

    private fun requireStringList(call: MethodCall, key: String): List<String> {
        val raw = call.argument<List<*>>(key) ?: invalid()
        return raw.map { it as? String ?: invalid() }
    }

    private fun requireUlid(value: String): String {
        if (!ULID.matches(value)) invalid()
        return value
    }

    private fun requireUlid(record: JSONObject, key: String): String {
        val value = record.optString(key, "")
        if (!ULID.matches(value)) corrupt()
        return value
    }

    private fun requireSecret(record: JSONObject, key: String, length: Int): String {
        val value = record.optString(key, "")
        if (value.length != length || !BASE64URL.matches(value)) corrupt()
        return value
    }

    private fun requireFingerprint(value: String): String {
        if (!FINGERPRINT.matches(value)) invalid()
        return value
    }

    private fun requireBaseUrl(value: String): String {
        try {
            val uri = URI(value)
            if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.host == "0.0.0.0" ||
                uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null
            ) {
                invalid()
            }
        } catch (error: SecurePairingStorageException) {
            throw error
        } catch (_: Exception) {
            invalid()
        }
        return value
    }

    private fun requireCapabilities(record: JSONObject, key: String): List<String> {
        val raw = record.optJSONArray(key) ?: corrupt()
        val values = mutableListOf<String>()
        for (index in 0 until raw.length()) {
            values += raw.optString(index, "")
        }
        val canonical = canonicalCapabilities(values)
        if (canonical != values) corrupt()
        return canonical
    }

    private fun canonicalCapabilities(values: List<String>): List<String> {
        if (values.size > 32 || values.toSet().size != values.size ||
            values.any { it.length > 64 || !CAPABILITY.matches(it) }
        ) {
            invalid()
        }
        return values.sorted()
    }

    private fun JSONObject.optStringOrNull(key: String): String? =
        if (isNull(key)) null else optString(key, "").takeIf { it.isNotEmpty() } ?: corrupt()

    private fun invalid(): Nothing =
        throw SecurePairingStorageException("secure_storage_invalid")

    private fun corrupt(): Nothing =
        throw SecurePairingStorageException("secure_storage_corrupt")

    companion object {
        private const val PREFERENCES_NAME = "secure_pairing_v1"
        private const val KEY_ALIAS = "io.datasteward.app.secure_pairing.v1"
        private const val KEY_CIPHERTEXT = "record_ciphertext"
        private const val KEY_IV = "record_iv"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val RECORD_VERSION = 1
        private val AAD = "DataStewardSecurePairing/v1".toByteArray(Charsets.UTF_8)
        private val ULID = Regex("^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val HUMAN32 = Regex("^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$")
        private val BASE64URL = Regex("^[A-Za-z0-9_-]+$")
        private val FINGERPRINT = Regex("^[0-9a-f]{64}$")
        private val CAPABILITY = Regex("^[a-z][a-z0-9]*(?:\\.[a-z][a-z0-9]*)+$")
    }
}

private class SecurePairingStorageException(val code: String) : RuntimeException(code)
