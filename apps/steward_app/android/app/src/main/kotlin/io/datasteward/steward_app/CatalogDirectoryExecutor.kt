package io.datasteward.steward_app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import org.json.JSONObject

class CatalogDirectoryExecutor(private val context: Context) {
    private val resolver = context.contentResolver
    private val preferences =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun getCatalogState(result: MethodChannel.Result) {
        respond(result) {
            val storedUri = preferences.getString(KEY_TREE_URI, null)
                ?: return@respond notAuthorizedState()
            val treeUri = parseStoredUri(storedUri)
            requirePersistedReadGrant(treeUri)
            inspectRoot(treeUri)
            val expectedRootId = tokenFor("root:$treeUri")
            val storedRootId = preferences.getString(KEY_ROOT_ID, null)
                ?: throw CatalogContractFailure(
                    "catalog_state_corrupt",
                    CATALOG_STATE_CORRUPT_MESSAGE,
                )
            if (!secureEquals(expectedRootId, storedRootId)) {
                throw CatalogContractFailure(
                    "catalog_state_corrupt",
                    CATALOG_STATE_CORRUPT_MESSAGE,
                )
            }
            authorizedState(treeUri, storedRootId, restored = true)
        }
    }

    fun authorizeCatalogDirectory(
        treeUri: Uri,
        intentFlags: Int,
        result: MethodChannel.Result,
    ) {
        respond(result) {
            if (!DocumentsContract.isTreeUri(treeUri)) {
                throw CatalogContractFailure("invalid_directory", INVALID_CATALOG_DIRECTORY_MESSAGE)
            }
            val grantFlags = intentFlags and Intent.FLAG_GRANT_READ_URI_PERMISSION
            if (grantFlags != Intent.FLAG_GRANT_READ_URI_PERMISSION) {
                throw CatalogContractFailure("permission_lost", CATALOG_PERMISSION_LOST_MESSAGE)
            }

            inspectRoot(treeUri)
            val rootId = tokenFor("root:$treeUri")
            try {
                resolver.takePersistableUriPermission(treeUri, grantFlags)
            } catch (_: SecurityException) {
                throw CatalogContractFailure("permission_lost", CATALOG_PERMISSION_LOST_MESSAGE)
            }

            val previousUri = preferences.getString(KEY_TREE_URI, null)?.let(Uri::parse)
            val stored =
                preferences
                    .edit()
                    .putString(KEY_TREE_URI, treeUri.toString())
                    .putInt(KEY_GRANT_FLAGS, grantFlags)
                    .putString(KEY_ROOT_ID, rootId)
                    .putBoolean(KEY_CONTENT_ANALYSIS_ENABLED, false)
                    .remove(KEY_LOCATOR_MAP)
                    .remove(KEY_LAST_SNAPSHOT_SHA256)
                    .remove(KEY_OCR_OUTBOX_PAYLOAD)
                    .remove(KEY_OCR_OUTBOX_SHA256)
                    .commit()
            if (!stored) {
                runCatching { resolver.releasePersistableUriPermission(treeUri, grantFlags) }
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }

            if (previousUri != null && previousUri != treeUri) {
                runCatching {
                    resolver.releasePersistableUriPermission(
                        previousUri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION,
                    )
                }
            }
            authorizedState(treeUri, rootId, restored = false)
        }
    }

    fun buildCatalogSnapshot(result: MethodChannel.Result) {
        respond(result) {
            val treeUri = authorizedTreeUri()
            val rootId = requireStoredRootId(treeUri)
            val sourceEntries = queryDirectChildren(treeUri)
            val snapshot =
                CatalogSnapshotBuilder { canonicalLocator ->
                    tokenFor("document:$canonicalLocator")
                }.build(rootId, sourceEntries)

            val locatorMap = JSONObject()
            for (entry in sourceEntries) {
                if (entry.isDirectory || entry.isVirtual) {
                    continue
                }
                val token = tokenFor("document:${entry.canonicalLocator}")
                locatorMap.put(token, entry.canonicalLocator)
            }
            if (locatorMap.toString().toByteArray(Charsets.UTF_8).size > MAX_LOCATOR_MAP_BYTES) {
                throw CatalogContractFailure("catalog_too_large", CATALOG_TOO_LARGE_MESSAGE)
            }
            val stored =
                preferences
                    .edit()
                    .putString(KEY_LOCATOR_MAP, locatorMap.toString())
                    .putString(KEY_LAST_SNAPSHOT_SHA256, snapshot.snapshotSha256)
                    .commit()
            if (!stored) {
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }
            snapshot.toMap(
                System.currentTimeMillis(),
                preferences.getBoolean(KEY_CONTENT_ANALYSIS_ENABLED, false),
            )
        }
    }

    fun setContentAnalysisEnabled(arguments: Any?, result: MethodChannel.Result) {
        respond(result) {
            val values = arguments as? Map<*, *>
                ?: throw CatalogContractFailure("catalog_policy_invalid", CATALOG_POLICY_MESSAGE)
            if (values.keys != setOf("enabled") || values["enabled"] !is Boolean) {
                throw CatalogContractFailure("catalog_policy_invalid", CATALOG_POLICY_MESSAGE)
            }
            val treeUri = authorizedTreeUri()
            val rootId = requireStoredRootId(treeUri)
            val enabled = values["enabled"] as Boolean
            val editor = preferences.edit().putBoolean(KEY_CONTENT_ANALYSIS_ENABLED, enabled)
            if (!enabled) {
                editor.remove(KEY_OCR_OUTBOX_PAYLOAD).remove(KEY_OCR_OUTBOX_SHA256)
            }
            if (!editor.commit()) {
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }
            authorizedState(treeUri, rootId, restored = true)
        }
    }

    fun forgetCatalogDirectory(result: MethodChannel.Result) {
        respond(result) {
            val storedUri = preferences.getString(KEY_TREE_URI, null)
            val cleared = preferences.edit().clear().commit()
            if (!cleared) {
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }
            var released = false
            if (storedUri != null) {
                val treeUri = runCatching { Uri.parse(storedUri) }.getOrNull()
                if (treeUri != null) {
                    released =
                        runCatching {
                            resolver.releasePersistableUriPermission(
                                treeUri,
                                Intent.FLAG_GRANT_READ_URI_PERMISSION,
                            )
                            true
                        }.getOrDefault(false)
                }
            }
            mapOf(
                "schemaVersion" to CATALOG_STATE_SCHEMA,
                "status" to "forgotten",
                "authorized" to false,
                "canRead" to false,
                "restored" to false,
                "contentAnalysisEnabled" to false,
                "permissionReleased" to released,
            )
        }
    }

    fun saveCatalogOutbox(arguments: Any?, result: MethodChannel.Result) {
        respond(result) {
            val values = arguments as? Map<*, *>
                ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            if (values.keys != setOf("payload", "sha256")) {
                throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            }
            val payload = values["payload"] as? String
                ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            val digest = values["sha256"] as? String
                ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            val bytes = payload.toByteArray(Charsets.UTF_8)
            if (bytes.isEmpty() || bytes.size > MAX_OUTBOX_BYTES ||
                !digest.matches(Regex("^[0-9a-f]{64}$")) ||
                !secureEquals(sha256(bytes), digest)
            ) {
                throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            }
            if (!preferences.edit()
                    .putString(KEY_OUTBOX_PAYLOAD, payload)
                    .putString(KEY_OUTBOX_SHA256, digest)
                    .commit()
            ) {
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }
            mapOf("status" to "saved", "sha256" to digest)
        }
    }

    fun loadCatalogOutbox(result: MethodChannel.Result) {
        respond(result) {
            val payload = preferences.getString(KEY_OUTBOX_PAYLOAD, null)
            val digest = preferences.getString(KEY_OUTBOX_SHA256, null)
            if (payload == null && digest == null) {
                return@respond mapOf("status" to "empty")
            }
            if (payload == null || digest == null) {
                throw CatalogContractFailure("catalog_outbox_corrupt", CATALOG_IO_ERROR_MESSAGE)
            }
            val bytes = payload.toByteArray(Charsets.UTF_8)
            if (bytes.isEmpty() || bytes.size > MAX_OUTBOX_BYTES ||
                !digest.matches(Regex("^[0-9a-f]{64}$")) ||
                !secureEquals(sha256(bytes), digest)
            ) {
                throw CatalogContractFailure("catalog_outbox_corrupt", CATALOG_IO_ERROR_MESSAGE)
            }
            mapOf("status" to "pending", "payload" to payload, "sha256" to digest)
        }
    }

    fun clearCatalogOutbox(arguments: Any?, result: MethodChannel.Result) {
        respond(result) {
            val values = arguments as? Map<*, *>
                ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            if (values.keys != setOf("sha256")) {
                throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            }
            val expected = values["sha256"] as? String
                ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
            val stored = preferences.getString(KEY_OUTBOX_SHA256, null)
            if (stored == null || !secureEquals(expected, stored)) {
                throw CatalogContractFailure("catalog_outbox_conflict", CATALOG_IO_ERROR_MESSAGE)
            }
            if (!preferences.edit().remove(KEY_OUTBOX_PAYLOAD).remove(KEY_OUTBOX_SHA256).commit()) {
                throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
            }
            mapOf("status" to "cleared")
        }
    }

    private fun authorizedTreeUri(): Uri {
        val storedUri = preferences.getString(KEY_TREE_URI, null)
            ?: throw CatalogContractFailure("not_authorized", CATALOG_NOT_AUTHORIZED_MESSAGE)
        val treeUri = parseStoredUri(storedUri)
        requirePersistedReadGrant(treeUri)
        inspectRoot(treeUri)
        return treeUri
    }

    internal fun resolveAndroidOcrRequest(
        request: AndroidOcrBatchRequest,
    ): List<ResolvedAndroidOcrInput> {
        val treeUri = authorizedTreeUri()
        val rootId = requireStoredRootId(treeUri)
        if (!preferences.getBoolean(KEY_CONTENT_ANALYSIS_ENABLED, false)) {
            throw AndroidOcrFailure("ocr_opt_in_required", OCR_OPT_IN_REQUIRED_MESSAGE)
        }
        if (!secureEquals(rootId, request.catalogRootId) ||
            !secureEquals(
                preferences.getString(KEY_LAST_SNAPSHOT_SHA256, "").orEmpty(),
                request.snapshotSha256,
            )
        ) {
            throw AndroidOcrFailure("ocr_snapshot_stale", OCR_SNAPSHOT_STALE_MESSAGE)
        }
        val rawMap = preferences.getString(KEY_LOCATOR_MAP, null)
            ?: throw AndroidOcrFailure("ocr_snapshot_stale", OCR_SNAPSHOT_STALE_MESSAGE)
        val locatorMap =
            runCatching { JSONObject(rawMap) }
                .getOrElse {
                    throw AndroidOcrFailure("ocr_state_corrupt", OCR_STATE_CORRUPT_MESSAGE)
                }
        val resolved = mutableListOf<ResolvedAndroidOcrInput>()
        var totalBytes = 0L
        for (item in request.items) {
            val locator =
                runCatching { locatorMap.getString(item.locatorToken) }
                    .getOrElse {
                        throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
                    }
            val uri =
                runCatching { Uri.parse(locator) }
                    .getOrElse {
                        throw AndroidOcrFailure("ocr_state_corrupt", OCR_STATE_CORRUPT_MESSAGE)
                    }
            if (uri.toString() != locator) {
                throw AndroidOcrFailure("ocr_state_corrupt", OCR_STATE_CORRUPT_MESSAGE)
            }
            val projection = projectOcrDocument(rootId, item.locatorToken, uri)
            if (!secureEquals(projection.revision, item.revision)) {
                throw AndroidOcrFailure("ocr_revision_changed", OCR_REVISION_CHANGED_MESSAGE)
            }
            val size = projection.sizeBytes
                ?: throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
            if (size <= 0 || size > MAX_OCR_IMAGE_BYTES) {
                throw AndroidOcrFailure("ocr_image_too_large", OCR_IMAGE_TOO_LARGE_MESSAGE)
            }
            totalBytes += size
            if (totalBytes > MAX_OCR_BATCH_BYTES) {
                throw AndroidOcrFailure("ocr_image_too_large", OCR_IMAGE_TOO_LARGE_MESSAGE)
            }
            resolved +=
                ResolvedAndroidOcrInput(
                    locatorToken = item.locatorToken,
                    revision = item.revision,
                    format = projection.extension,
                    uri = uri,
                    sizeBytes = size,
                )
        }
        return resolved
    }

    internal fun verifyAndroidOcrInput(input: ResolvedAndroidOcrInput) {
        val treeUri = authorizedTreeUri()
        val rootId = requireStoredRootId(treeUri)
        val projection = projectOcrDocument(rootId, input.locatorToken, input.uri)
        if (!secureEquals(projection.revision, input.revision) ||
            projection.extension != input.format ||
            projection.sizeBytes != input.sizeBytes
        ) {
            throw AndroidOcrFailure("ocr_revision_changed", OCR_REVISION_CHANGED_MESSAGE)
        }
    }

    fun saveOcrOutbox(arguments: Any?, result: MethodChannel.Result) {
        respond(result) {
            requireOcrPolicy()
            saveOutbox(
                arguments = arguments,
                payloadKey = KEY_OCR_OUTBOX_PAYLOAD,
                digestKey = KEY_OCR_OUTBOX_SHA256,
                maxBytes = MAX_OCR_OUTBOX_BYTES,
            )
        }
    }

    fun loadOcrOutbox(result: MethodChannel.Result) {
        respond(result) {
            requireOcrPolicy()
            loadOutbox(
                payloadKey = KEY_OCR_OUTBOX_PAYLOAD,
                digestKey = KEY_OCR_OUTBOX_SHA256,
                maxBytes = MAX_OCR_OUTBOX_BYTES,
            )
        }
    }

    fun clearOcrOutbox(arguments: Any?, result: MethodChannel.Result) {
        respond(result) {
            requireOcrPolicy()
            clearOutbox(
                arguments = arguments,
                payloadKey = KEY_OCR_OUTBOX_PAYLOAD,
                digestKey = KEY_OCR_OUTBOX_SHA256,
            )
        }
    }

    private fun requireOcrPolicy() {
        authorizedTreeUri()
        if (!preferences.getBoolean(KEY_CONTENT_ANALYSIS_ENABLED, false)) {
            throw CatalogContractFailure("ocr_opt_in_required", OCR_OPT_IN_REQUIRED_MESSAGE)
        }
    }

    private fun saveOutbox(
        arguments: Any?,
        payloadKey: String,
        digestKey: String,
        maxBytes: Int,
    ): Map<String, Any?> {
        val values = arguments as? Map<*, *>
            ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        if (values.keys != setOf("payload", "sha256")) {
            throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        }
        val payload = values["payload"] as? String
            ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        val digest = values["sha256"] as? String
            ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        val bytes = payload.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > maxBytes ||
            !digest.matches(Regex("^[0-9a-f]{64}$")) ||
            !secureEquals(sha256(bytes), digest)
        ) {
            throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        }
        if (!preferences.edit().putString(payloadKey, payload).putString(digestKey, digest).commit()) {
            throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        }
        return mapOf("status" to "saved", "sha256" to digest)
    }

    private fun loadOutbox(
        payloadKey: String,
        digestKey: String,
        maxBytes: Int,
    ): Map<String, Any?> {
        val payload = preferences.getString(payloadKey, null)
        val digest = preferences.getString(digestKey, null)
        if (payload == null && digest == null) return mapOf("status" to "empty")
        if (payload == null || digest == null) {
            throw CatalogContractFailure("catalog_outbox_corrupt", CATALOG_IO_ERROR_MESSAGE)
        }
        val bytes = payload.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > maxBytes ||
            !digest.matches(Regex("^[0-9a-f]{64}$")) ||
            !secureEquals(sha256(bytes), digest)
        ) {
            throw CatalogContractFailure("catalog_outbox_corrupt", CATALOG_IO_ERROR_MESSAGE)
        }
        return mapOf("status" to "pending", "payload" to payload, "sha256" to digest)
    }

    private fun clearOutbox(
        arguments: Any?,
        payloadKey: String,
        digestKey: String,
    ): Map<String, Any?> {
        val values = arguments as? Map<*, *>
            ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        if (values.keys != setOf("sha256")) {
            throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        }
        val expected = values["sha256"] as? String
            ?: throw CatalogContractFailure("catalog_outbox_invalid", CATALOG_IO_ERROR_MESSAGE)
        val stored = preferences.getString(digestKey, null)
        if (stored == null || !secureEquals(expected, stored)) {
            throw CatalogContractFailure("catalog_outbox_conflict", CATALOG_IO_ERROR_MESSAGE)
        }
        if (!preferences.edit().remove(payloadKey).remove(digestKey).commit()) {
            throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        }
        return mapOf("status" to "cleared")
    }

    private fun projectOcrDocument(
        rootId: String,
        expectedToken: String,
        uri: Uri,
    ): CatalogItemProjection {
        val entry = queryDocumentEntry(uri)
        if (entry.mimeType?.trim()?.lowercase() !in OCR_IMAGE_MIME_TYPES) {
            throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
        }
        val projection =
            CatalogSnapshotBuilder { canonicalLocator ->
                tokenFor("document:$canonicalLocator")
            }.build(rootId, listOf(entry)).items.singleOrNull()
                ?: throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
        if (!secureEquals(projection.locatorToken, expectedToken) ||
            projection.mimeFamily != "image" ||
            projection.extension !in OCR_IMAGE_FORMATS
        ) {
            throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
        }
        return projection
    }

    private fun queryDocumentEntry(uri: Uri): CatalogSourceEntry {
        try {
            resolver.query(
                uri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE,
                    DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                    DocumentsContract.Document.COLUMN_FLAGS,
                ),
                null,
                null,
                null,
            )?.use { cursor ->
                if (!cursor.moveToFirst()) {
                    throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
                }
                val mime =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE),
                    )
                val flags =
                    cursor.getInt(
                        cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_FLAGS),
                    )
                return CatalogSourceEntry(
                    canonicalLocator = uri.toString(),
                    displayName =
                        cursor.getString(
                            cursor.getColumnIndexOrThrow(
                                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                            ),
                        ) ?: "",
                    mimeType = mime,
                    sizeBytes =
                        cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE).let {
                            if (cursor.isNull(it)) null else cursor.getLong(it)
                        },
                    modifiedAtMillis =
                        cursor.getColumnIndexOrThrow(
                            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                        ).let { if (cursor.isNull(it)) null else cursor.getLong(it) },
                    isDirectory = mime == DocumentsContract.Document.MIME_TYPE_DIR,
                    isVirtual =
                        flags and DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT != 0,
                )
            }
            throw AndroidOcrFailure("ocr_asset_not_allowed", OCR_ASSET_NOT_ALLOWED_MESSAGE)
        } catch (failure: AndroidOcrFailure) {
            throw failure
        } catch (_: SecurityException) {
            throw AndroidOcrFailure("ocr_permission_lost", OCR_PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            throw AndroidOcrFailure("ocr_io_error", OCR_IO_ERROR_MESSAGE)
        }
    }

    private fun parseStoredUri(value: String): Uri =
        runCatching { Uri.parse(value) }
            .getOrElse {
                throw CatalogContractFailure(
                    "catalog_state_corrupt",
                    CATALOG_STATE_CORRUPT_MESSAGE,
                )
            }

    private fun requireStoredRootId(treeUri: Uri): String {
        val storedRootId = preferences.getString(KEY_ROOT_ID, null)
            ?: throw CatalogContractFailure(
                "catalog_state_corrupt",
                CATALOG_STATE_CORRUPT_MESSAGE,
            )
        if (!secureEquals(tokenFor("root:$treeUri"), storedRootId)) {
            throw CatalogContractFailure(
                "catalog_state_corrupt",
                CATALOG_STATE_CORRUPT_MESSAGE,
            )
        }
        return storedRootId
    }

    private fun requirePersistedReadGrant(treeUri: Uri) {
        val storedFlags = preferences.getInt(KEY_GRANT_FLAGS, 0)
        val granted =
            resolver.persistedUriPermissions.any { permission ->
                permission.uri == treeUri &&
                    permission.isReadPermission &&
                    storedFlags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0
            }
        if (!granted) {
            throw CatalogContractFailure("permission_lost", CATALOG_PERMISSION_LOST_MESSAGE)
        }
    }

    private fun inspectRoot(treeUri: Uri) {
        val treeDocumentId =
            runCatching { DocumentsContract.getTreeDocumentId(treeUri) }
                .getOrElse {
                    throw CatalogContractFailure(
                        "invalid_directory",
                        INVALID_CATALOG_DIRECTORY_MESSAGE,
                    )
                }
        if (treeDocumentId.isBlank() ||
            treeDocumentId.length > MAX_DOCUMENT_ID_CHARS ||
            treeDocumentId.any(Char::isISOControl) ||
            BROAD_EXTERNAL_STORAGE_ROOT.matches(treeDocumentId)
        ) {
            throw CatalogContractFailure("invalid_directory", INVALID_CATALOG_DIRECTORY_MESSAGE)
        }
        val documentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocumentId)
        try {
            resolver.query(
                documentUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                ),
                null,
                null,
                null,
            )?.use { cursor ->
                if (!cursor.moveToFirst()) {
                    throw CatalogContractFailure(
                        "invalid_directory",
                        INVALID_CATALOG_DIRECTORY_MESSAGE,
                    )
                }
                val name =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(
                            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        ),
                    )
                val mime =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(
                            DocumentsContract.Document.COLUMN_MIME_TYPE,
                        ),
                    )
                if (name.isNullOrBlank() || mime != DocumentsContract.Document.MIME_TYPE_DIR) {
                    throw CatalogContractFailure(
                        "invalid_directory",
                        INVALID_CATALOG_DIRECTORY_MESSAGE,
                    )
                }
            } ?: throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        } catch (failure: CatalogContractFailure) {
            throw failure
        } catch (_: SecurityException) {
            throw CatalogContractFailure("permission_lost", CATALOG_PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        }
    }

    private fun queryDirectChildren(treeUri: Uri): List<CatalogSourceEntry> {
        val treeDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
        val childrenUri =
            DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)
        val entries = mutableListOf<CatalogSourceEntry>()
        try {
            resolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE,
                    DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                    DocumentsContract.Document.COLUMN_FLAGS,
                ),
                null,
                null,
                null,
            )?.use { cursor ->
                val idColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val mimeColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val sizeColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
                val modifiedColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                val flagsColumn =
                    cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_FLAGS)

                while (cursor.moveToNext()) {
                    if (entries.size >= MAX_CATALOG_SOURCE_ROWS) {
                        throw CatalogContractFailure(
                            "catalog_too_large",
                            CATALOG_TOO_LARGE_MESSAGE,
                        )
                    }
                    val documentId = cursor.getString(idColumn)
                    if (documentId.isNullOrBlank() ||
                        documentId.length > MAX_DOCUMENT_ID_CHARS ||
                        documentId.any(Char::isISOControl)
                    ) {
                        throw CatalogContractFailure(
                            "catalog_invalid_entry",
                            INVALID_ENTRY_MESSAGE,
                        )
                    }
                    val documentUri =
                        DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
                    val mimeType = if (cursor.isNull(mimeColumn)) null else cursor.getString(mimeColumn)
                    val flags = if (cursor.isNull(flagsColumn)) 0 else cursor.getInt(flagsColumn)
                    entries +=
                        CatalogSourceEntry(
                            canonicalLocator = documentUri.toString(),
                            displayName = cursor.getString(nameColumn) ?: "",
                            mimeType = mimeType,
                            sizeBytes = if (cursor.isNull(sizeColumn)) null else cursor.getLong(sizeColumn),
                            modifiedAtMillis =
                                if (cursor.isNull(modifiedColumn)) null else cursor.getLong(modifiedColumn),
                            isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR,
                            isVirtual =
                                flags and DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT != 0,
                        )
                }
            } ?: throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        } catch (failure: CatalogContractFailure) {
            throw failure
        } catch (_: SecurityException) {
            throw CatalogContractFailure("permission_lost", CATALOG_PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            throw CatalogContractFailure("io_error", CATALOG_IO_ERROR_MESSAGE)
        }
        return entries
    }

    private fun authorizedState(
        treeUri: Uri,
        rootId: String,
        restored: Boolean,
    ): Map<String, Any?> =
        mapOf(
            "schemaVersion" to CATALOG_STATE_SCHEMA,
            "status" to "authorized",
            "authorized" to true,
            "canRead" to true,
            "restored" to restored,
            "provider" to safeProvider(treeUri.authority),
            "catalogRootId" to rootId,
            "contentAnalysisEnabled" to
                preferences.getBoolean(KEY_CONTENT_ANALYSIS_ENABLED, false),
        )

    private fun notAuthorizedState(): Map<String, Any?> =
        mapOf(
            "schemaVersion" to CATALOG_STATE_SCHEMA,
            "status" to "not_authorized",
            "authorized" to false,
            "canRead" to false,
            "restored" to false,
            "contentAnalysisEnabled" to false,
        )

    private fun safeProvider(authority: String?): String {
        val value = authority.orEmpty()
        return if (value.length in 1..253 && PROVIDER_PATTERN.matches(value)) value else "unknown"
    }

    private fun tokenFor(value: String): String {
        val key = loadOrCreateHmacKey()
        val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
        mac.init(key)
        return mac.doFinal(value.toByteArray(Charsets.UTF_8)).joinToString("") { byte ->
            "%02x".format(byte)
        }
    }

    @Synchronized
    private fun loadOrCreateHmacKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(LOCATOR_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                LOCATOR_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN,
            ).setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun secureEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(Charsets.US_ASCII), right.toByteArray(Charsets.US_ASCII))

    private fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { byte ->
            "%02x".format(byte)
        }

    private fun respond(
        result: MethodChannel.Result,
        operation: () -> Map<String, Any?>,
    ) {
        try {
            result.success(operation())
        } catch (failure: CatalogContractFailure) {
            result.error(failure.code, failure.safeMessage, null)
        } catch (_: Exception) {
            result.error("io_error", CATALOG_IO_ERROR_MESSAGE, null)
        }
    }

    companion object {
        private const val MAX_OUTBOX_BYTES = 768 * 1024
        private const val MAX_OCR_OUTBOX_BYTES = 192 * 1024
        private const val KEY_OUTBOX_PAYLOAD = "catalog_outbox_payload_v1"
        private const val KEY_OUTBOX_SHA256 = "catalog_outbox_sha256_v1"
        private const val PREFERENCES_NAME = "data_steward_catalog"
        private const val KEY_TREE_URI = "tree_uri"
        private const val KEY_GRANT_FLAGS = "grant_flags"
        private const val KEY_ROOT_ID = "root_id"
        private const val KEY_LOCATOR_MAP = "locator_map"
        private const val KEY_LAST_SNAPSHOT_SHA256 = "last_snapshot_sha256"
        internal const val KEY_CONTENT_ANALYSIS_ENABLED = "content_analysis_enabled_v1"
        internal const val KEY_OCR_OUTBOX_PAYLOAD = "ocr_outbox_payload_v1"
        internal const val KEY_OCR_OUTBOX_SHA256 = "ocr_outbox_sha256_v1"
        private const val LOCATOR_KEY_ALIAS = "data_steward_catalog_locator_v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val MAX_DOCUMENT_ID_CHARS = 1024
        private const val MAX_LOCATOR_MAP_BYTES = 768 * 1024

        private val PROVIDER_PATTERN = Regex("^[A-Za-z0-9._-]+\$")
        private val BROAD_EXTERNAL_STORAGE_ROOT = Regex("^[A-Za-z0-9._-]+:\$")

        private const val CATALOG_NOT_AUTHORIZED_MESSAGE =
            "No Android catalog directory is authorized."
        private const val CATALOG_PERMISSION_LOST_MESSAGE =
            "The Android catalog permission is unavailable."
        private const val INVALID_CATALOG_DIRECTORY_MESSAGE =
            "Select a dedicated materials directory, not a storage root."
        private const val CATALOG_IO_ERROR_MESSAGE =
            "The Android catalog operation could not be completed."
        private const val CATALOG_POLICY_MESSAGE =
            "The Android content policy is invalid."
    }
}

internal data class ResolvedAndroidOcrInput(
    val locatorToken: String,
    val revision: String,
    val format: String,
    val uri: Uri,
    val sizeBytes: Long,
)

internal const val MAX_OCR_IMAGE_BYTES = 12L * 1024 * 1024
private val OCR_IMAGE_MIME_TYPES = setOf("image/jpeg", "image/png")
internal const val MAX_OCR_BATCH_BYTES = 36L * 1024 * 1024
internal const val OCR_OPT_IN_REQUIRED_MESSAGE = "Enable Android OCR for this directory first."
internal const val OCR_SNAPSHOT_STALE_MESSAGE = "Refresh the Android catalog before OCR."
internal const val OCR_STATE_CORRUPT_MESSAGE = "The Android OCR state is invalid."
internal const val OCR_ASSET_NOT_ALLOWED_MESSAGE = "The requested image is not allowed."
internal const val OCR_REVISION_CHANGED_MESSAGE = "The requested image has changed."
internal const val OCR_IMAGE_TOO_LARGE_MESSAGE = "The requested image exceeds the safe limit."
internal const val OCR_PERMISSION_LOST_MESSAGE = "The Android directory permission is unavailable."
internal const val OCR_IO_ERROR_MESSAGE = "The Android OCR operation could not be completed."
