package io.datasteward.steward_app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import org.json.JSONObject

class SafExecutor(private val context: Context) {
    private val resolver = context.contentResolver
    private val preferences =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun getPermissionState(result: MethodChannel.Result) {
        respond(result) {
            val storedUri = preferences.getString(KEY_TREE_URI, null)
                ?: return@respond notAuthorizedState()
            val uri =
                runCatching { Uri.parse(storedUri) }
                    .getOrElse { throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE) }
            val grant = requirePersistedGrant(uri)
            val directory = inspectDirectory(uri, allowProbeOnly = true)
            directory.probeUri?.let(::validateOwnedProbe)
            permissionState(
                uri = uri,
                canRead = grant.isReadPermission,
                canWrite = grant.isWritePermission,
                restored = true,
            )
        }
    }

    fun authorizeDirectory(
        uri: Uri,
        intentFlags: Int,
        result: MethodChannel.Result,
    ) {
        respond(result) {
            if (!DocumentsContract.isTreeUri(uri)) {
                throw SafFailure("invalid_directory", INVALID_DIRECTORY_MESSAGE)
            }

            val grantFlags =
                intentFlags and
                    (Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            if (grantFlags and REQUIRED_GRANT_FLAGS != REQUIRED_GRANT_FLAGS) {
                throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
            }

            inspectDirectory(uri, allowProbeOnly = false)
            try {
                resolver.takePersistableUriPermission(uri, grantFlags)
            } catch (_: SecurityException) {
                throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
            }

            val stored =
                preferences
                    .edit()
                    .putString(KEY_TREE_URI, uri.toString())
                    .putInt(KEY_GRANT_FLAGS, grantFlags)
                    .remove(KEY_PROBE_SHA256)
                    .remove(KEY_PROBE_COMMAND_ID)
                    .commit()
            if (!stored) {
                runCatching { resolver.releasePersistableUriPermission(uri, grantFlags) }
                throw SafFailure("io_error", IO_ERROR_MESSAGE)
            }

            permissionState(
                uri = uri,
                canRead = grantFlags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0,
                canWrite = grantFlags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION != 0,
                restored = false,
            )
        }
    }

    fun writeProbe(result: MethodChannel.Result) {
        respond(result) {
            val uri = authorizedUri()
            val directory = inspectDirectory(uri, allowProbeOnly = true)
            directory.probeUri?.let(::validateOwnedProbe)
            val commandId = UUID.randomUUID().toString()
            val timestamp = utcTimestamp()
            val content =
                JSONObject()
                    .put("schemaVersion", SCHEMA_VERSION)
                    .put("commandId", commandId)
                    .put("timestamp", timestamp)
                    .toString()
                    .toByteArray(StandardCharsets.UTF_8)

            val probeUri =
                directory.probeUri
                    ?: DocumentsContract.createDocument(
                        resolver,
                        directory.documentUri,
                        "text/plain",
                        PROBE_FILE_NAME,
                    )
                    ?: throw SafFailure("io_error", IO_ERROR_MESSAGE)

            try {
                resolver.openOutputStream(probeUri, "wt")?.use { output ->
                    output.write(content)
                    output.flush()
                } ?: throw SafFailure("io_error", IO_ERROR_MESSAGE)
            } catch (_: SecurityException) {
                throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
            } catch (failure: SafFailure) {
                throw failure
            } catch (_: Exception) {
                throw SafFailure("io_error", IO_ERROR_MESSAGE)
            }

            val readBack = readProbeBytes(probeUri)
            if (!readBack.contentEquals(content)) {
                throw SafFailure("io_error", IO_ERROR_MESSAGE)
            }
            val parsedProbe = parseProbe(readBack)
            if (parsedProbe.commandId != commandId || parsedProbe.timestamp != timestamp) {
                throw SafFailure("io_error", IO_ERROR_MESSAGE)
            }
            val probeSha256 = sha256(readBack)
            saveProbeMetadata(probeSha256, commandId)

            mapOf(
                "status" to "write_success",
                "commandId" to commandId,
                "timestamp" to timestamp,
                "sha256" to probeSha256,
            )
        }
    }

    fun readProbe(result: MethodChannel.Result) {
        respond(result) {
            val uri = authorizedUri()
            val probeUri =
                inspectDirectory(uri, allowProbeOnly = true).probeUri
                    ?: throw SafFailure("probe_not_found", PROBE_NOT_FOUND_MESSAGE)
            val probe = validateOwnedProbe(probeUri)

            mapOf(
                "status" to "read_success",
                "commandId" to probe.commandId,
                "sha256" to probe.sha256,
            )
        }
    }

    fun deleteProbe(result: MethodChannel.Result) {
        respond(result) {
            val uri = authorizedUri()
            val probeUri = inspectDirectory(uri, allowProbeOnly = true).probeUri
            if (probeUri == null) {
                clearProbeMetadata()
                return@respond mapOf("status" to "already_absent")
            }
            validateOwnedProbe(probeUri)

            val deleted =
                try {
                    DocumentsContract.deleteDocument(resolver, probeUri)
                } catch (_: SecurityException) {
                    throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
                } catch (_: Exception) {
                    throw SafFailure("io_error", IO_ERROR_MESSAGE)
                }
            if (!deleted) {
                throw SafFailure("io_error", IO_ERROR_MESSAGE)
            }
            clearProbeMetadata()
            mapOf("status" to "delete_success")
        }
    }

    private fun validateOwnedProbe(uri: Uri): ParsedProbe {
        val content = readProbeBytes(uri)
        val parsedProbe = parseProbe(content)
        val currentSha256 = sha256(content)
        val storedSha256 = preferences.getString(KEY_PROBE_SHA256, null)
        val storedCommandId = preferences.getString(KEY_PROBE_COMMAND_ID, null)
        if (storedSha256 == null ||
            !storedSha256.equals(currentSha256, ignoreCase = true) ||
            (storedCommandId != null && storedCommandId != parsedProbe.commandId)
        ) {
            throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
        }
        return parsedProbe.copy(sha256 = currentSha256)
    }

    private fun parseProbe(content: ByteArray): ParsedProbe {
        val json =
            try {
                JSONObject(String(content, StandardCharsets.UTF_8))
            } catch (_: Exception) {
                throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
            }
        if (json.optString("schemaVersion", "") != SCHEMA_VERSION) {
            throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
        }

        val commandId = json.optString("commandId", "")
        val parsedUuid =
            runCatching { UUID.fromString(commandId) }
                .getOrElse { throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE) }
        if (!parsedUuid.toString().equals(commandId, ignoreCase = true)) {
            throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
        }

        val timestamp = json.optString("timestamp", "")
        if (!isValidUtcTimestamp(timestamp)) {
            throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
        }
        return ParsedProbe(commandId = commandId, timestamp = timestamp, sha256 = "")
    }

    private fun isValidUtcTimestamp(value: String): Boolean {
        val parser =
            SimpleDateFormat(TIMESTAMP_PATTERN, Locale.US).apply {
                isLenient = false
                timeZone = TimeZone.getTimeZone("UTC")
            }
        val position = ParsePosition(0)
        return parser.parse(value, position) != null && position.index == value.length
    }

    private fun saveProbeMetadata(sha256: String, commandId: String) {
        val stored =
            preferences
                .edit()
                .putString(KEY_PROBE_SHA256, sha256)
                .putString(KEY_PROBE_COMMAND_ID, commandId)
                .commit()
        if (!stored) {
            throw SafFailure("io_error", IO_ERROR_MESSAGE)
        }
    }

    private fun clearProbeMetadata() {
        val cleared =
            preferences
                .edit()
                .remove(KEY_PROBE_SHA256)
                .remove(KEY_PROBE_COMMAND_ID)
                .commit()
        if (!cleared) {
            throw SafFailure("io_error", IO_ERROR_MESSAGE)
        }
    }

    private fun authorizedUri(): Uri {
        val storedUri =
            preferences.getString(KEY_TREE_URI, null)
                ?: throw SafFailure("not_authorized", NOT_AUTHORIZED_MESSAGE)
        val uri =
            runCatching { Uri.parse(storedUri) }
                .getOrElse { throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE) }
        requirePersistedGrant(uri)
        return uri
    }

    private fun requirePersistedGrant(uri: Uri): android.content.UriPermission {
        val storedFlags = preferences.getInt(KEY_GRANT_FLAGS, 0)
        val grant =
            resolver.persistedUriPermissions.firstOrNull {
                it.uri == uri &&
                    it.isReadPermission &&
                    it.isWritePermission &&
                    storedFlags and REQUIRED_GRANT_FLAGS == REQUIRED_GRANT_FLAGS
            }
        return grant ?: throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
    }

    private fun inspectDirectory(
        treeUri: Uri,
        allowProbeOnly: Boolean,
    ): DirectoryInspection {
        val treeDocumentId =
            runCatching { DocumentsContract.getTreeDocumentId(treeUri) }
                .getOrElse { throw SafFailure("invalid_directory", INVALID_DIRECTORY_MESSAGE) }
        val documentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocumentId)

        val rootDetails =
            querySingleDocument(documentUri)
                ?: throw SafFailure("invalid_directory", INVALID_DIRECTORY_MESSAGE)
        if (rootDetails.first != REQUIRED_DIRECTORY_NAME ||
            rootDetails.second != DocumentsContract.Document.MIME_TYPE_DIR
        ) {
            throw SafFailure("invalid_directory", INVALID_DIRECTORY_MESSAGE)
        }

        val childrenUri =
            DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)
        var childCount = 0
        var probeUri: Uri? = null
        try {
            resolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
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
                while (cursor.moveToNext()) {
                    childCount += 1
                    val name = cursor.getString(nameColumn)
                    val mimeType = cursor.getString(mimeColumn)
                    if (name != PROBE_FILE_NAME ||
                        mimeType == DocumentsContract.Document.MIME_TYPE_DIR ||
                        probeUri != null
                    ) {
                        throw SafFailure("unsafe_directory", UNSAFE_DIRECTORY_MESSAGE)
                    }
                    probeUri =
                        DocumentsContract.buildDocumentUriUsingTree(
                            treeUri,
                            cursor.getString(idColumn),
                        )
                }
            } ?: throw SafFailure("io_error", IO_ERROR_MESSAGE)
        } catch (failure: SafFailure) {
            throw failure
        } catch (_: SecurityException) {
            throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            throw SafFailure("io_error", IO_ERROR_MESSAGE)
        }

        if (!allowProbeOnly && childCount != 0) {
            throw SafFailure("unsafe_directory", UNSAFE_DIRECTORY_MESSAGE)
        }
        if (allowProbeOnly && childCount > 1) {
            throw SafFailure("unsafe_directory", UNSAFE_DIRECTORY_MESSAGE)
        }

        return DirectoryInspection(documentUri = documentUri, probeUri = probeUri)
    }

    private fun querySingleDocument(uri: Uri): Pair<String, String>? {
        try {
            resolver.query(
                uri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                ),
                null,
                null,
                null,
            )?.use { cursor ->
                if (!cursor.moveToFirst()) {
                    return null
                }
                val name =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(
                            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        ),
                    )
                val mimeType =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(
                            DocumentsContract.Document.COLUMN_MIME_TYPE,
                        ),
                    )
                return name to mimeType
            }
        } catch (_: SecurityException) {
            throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
        } catch (failure: SafFailure) {
            throw failure
        } catch (_: Exception) {
            throw SafFailure("io_error", IO_ERROR_MESSAGE)
        }
        return null
    }

    private fun readProbeBytes(uri: Uri): ByteArray {
        try {
            resolver.openInputStream(uri)?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) {
                        break
                    }
                    total += count
                    if (total > MAX_PROBE_BYTES) {
                        throw SafFailure("unsafe_probe", UNSAFE_PROBE_MESSAGE)
                    }
                    output.write(buffer, 0, count)
                }
                return output.toByteArray()
            } ?: throw SafFailure("io_error", IO_ERROR_MESSAGE)
        } catch (failure: SafFailure) {
            throw failure
        } catch (_: SecurityException) {
            throw SafFailure("permission_lost", PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            throw SafFailure("io_error", IO_ERROR_MESSAGE)
        }
    }

    private fun respond(
        result: MethodChannel.Result,
        operation: () -> Map<String, Any>,
    ) {
        try {
            result.success(operation())
        } catch (failure: SafFailure) {
            result.error(failure.code, failure.safeMessage, null)
        } catch (_: Exception) {
            result.error("io_error", IO_ERROR_MESSAGE, null)
        }
    }

    private fun permissionState(
        uri: Uri,
        canRead: Boolean,
        canWrite: Boolean,
        restored: Boolean,
    ): Map<String, Any> =
        mapOf(
            "status" to "authorized",
            "authorized" to true,
            "provider" to (uri.authority ?: "unknown"),
            "uriSha256" to sha256(uri.toString().toByteArray(StandardCharsets.UTF_8)),
            "canRead" to canRead,
            "canWrite" to canWrite,
            "restored" to restored,
        )

    private fun notAuthorizedState(): Map<String, Any> =
        mapOf(
            "status" to "not_authorized",
            "authorized" to false,
            "canRead" to false,
            "canWrite" to false,
            "restored" to false,
        )

    private fun utcTimestamp(): String =
        SimpleDateFormat(TIMESTAMP_PATTERN, Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date())

    private fun sha256(content: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(content)
            .joinToString("") { byte -> "%02X".format(byte) }

    private data class DirectoryInspection(
        val documentUri: Uri,
        val probeUri: Uri?,
    )

    private data class ParsedProbe(
        val commandId: String,
        val timestamp: String,
        val sha256: String,
    )

    private class SafFailure(
        val code: String,
        val safeMessage: String,
    ) : RuntimeException()

    companion object {
        private const val PREFERENCES_NAME = "data_steward_saf"
        private const val KEY_TREE_URI = "tree_uri"
        private const val KEY_GRANT_FLAGS = "grant_flags"
        private const val KEY_PROBE_SHA256 = "probe_sha256"
        private const val KEY_PROBE_COMMAND_ID = "probe_command_id"
        private const val REQUIRED_DIRECTORY_NAME = "DataStewardDemo"
        private const val PROBE_FILE_NAME = "data-steward-saf-probe.txt"
        private const val SCHEMA_VERSION = "data-steward.saf-probe/v1"
        private const val TIMESTAMP_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        private const val MAX_PROBE_BYTES = 64 * 1024
        private const val REQUIRED_GRANT_FLAGS =
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION

        private const val NOT_AUTHORIZED_MESSAGE = "No SAF directory is authorized."
        private const val PERMISSION_LOST_MESSAGE = "The persisted SAF permission is unavailable."
        private const val INVALID_DIRECTORY_MESSAGE =
            "Select the dedicated DataStewardDemo directory."
        private const val UNSAFE_DIRECTORY_MESSAGE =
            "The selected directory contains unexpected content."
        private const val UNSAFE_PROBE_MESSAGE =
            "The probe did not pass the ownership check."
        private const val PROBE_NOT_FOUND_MESSAGE = "The SAF probe does not exist."
        private const val IO_ERROR_MESSAGE = "The SAF operation could not be completed."
    }
}
