package io.datasteward.steward_app

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale

internal data class CatalogSourceEntry(
    val canonicalLocator: String,
    val displayName: String,
    val mimeType: String?,
    val sizeBytes: Long?,
    val modifiedAtMillis: Long?,
    val isDirectory: Boolean,
    val isVirtual: Boolean,
)

internal data class CatalogItemProjection(
    val locatorToken: String,
    val displayName: String,
    val extension: String,
    val mimeFamily: String,
    val sizeBytes: Long?,
    val modifiedAtMillis: Long?,
    val revision: String,
    val contentEligible: Boolean,
) {
    fun toMap(): Map<String, Any?> =
        mapOf(
            "locatorToken" to locatorToken,
            "displayName" to displayName,
            "extension" to extension,
            "mimeFamily" to mimeFamily,
            "sizeBytes" to sizeBytes,
            "modifiedAtMillis" to modifiedAtMillis,
            "revision" to revision,
            "contentEligible" to contentEligible,
        )
}

internal data class CatalogSnapshotProjection(
    val catalogRootId: String,
    val snapshotSha256: String,
    val itemCount: Int,
    val skippedCount: Int,
    val items: List<CatalogItemProjection>,
) {
    fun toMap(
        generatedAtMillis: Long,
        contentAnalysisEnabled: Boolean = false,
    ): Map<String, Any?> =
        mapOf(
            "schemaVersion" to CATALOG_SNAPSHOT_SCHEMA,
            "catalogRootId" to catalogRootId,
            "snapshotSha256" to snapshotSha256,
            "generatedAtMillis" to generatedAtMillis,
            "itemCount" to itemCount,
            "skippedCount" to skippedCount,
            "contentAnalysisEnabled" to contentAnalysisEnabled,
            "items" to items.map(CatalogItemProjection::toMap),
        )
}

internal class CatalogSnapshotBuilder(
    private val tokenForLocator: (String) -> String,
) {
    fun build(
        catalogRootId: String,
        sourceEntries: List<CatalogSourceEntry>,
    ): CatalogSnapshotProjection {
        requireDigest(catalogRootId, "catalog_state_corrupt")
        if (sourceEntries.size > MAX_CATALOG_SOURCE_ROWS) {
            throw CatalogContractFailure("catalog_too_large", CATALOG_TOO_LARGE_MESSAGE)
        }

        val seenLocators = mutableSetOf<String>()
        val seenTokens = mutableSetOf<String>()
        var metadataBytes = 0
        var skippedCount = 0
        val items = mutableListOf<CatalogItemProjection>()

        for (source in sourceEntries) {
            if (source.isDirectory || source.isVirtual) {
                skippedCount += 1
                continue
            }
            validateLocator(source.canonicalLocator)
            if (!seenLocators.add(source.canonicalLocator)) {
                throw CatalogContractFailure("catalog_duplicate_entry", DUPLICATE_ENTRY_MESSAGE)
            }

            val displayName = validateDisplayName(source.displayName)
            val mimeType = canonicalMimeType(source.mimeType)
            val sizeBytes = validateOptionalNonNegative(source.sizeBytes)
            val modifiedAtMillis = validateOptionalNonNegative(source.modifiedAtMillis)
            val locatorToken = tokenForLocator(source.canonicalLocator)
            requireDigest(locatorToken, "catalog_state_corrupt")
            if (!seenTokens.add(locatorToken)) {
                throw CatalogContractFailure("catalog_duplicate_entry", DUPLICATE_ENTRY_MESSAGE)
            }

            metadataBytes +=
                source.canonicalLocator.toByteArray(StandardCharsets.UTF_8).size +
                displayName.toByteArray(StandardCharsets.UTF_8).size +
                mimeType.toByteArray(StandardCharsets.UTF_8).size +
                96
            if (metadataBytes > MAX_CATALOG_METADATA_BYTES) {
                throw CatalogContractFailure("catalog_too_large", CATALOG_TOO_LARGE_MESSAGE)
            }

            val extension = catalogSafeExtension(displayName)
            val mimeFamily = mimeFamily(mimeType, extension)
            val revision =
                catalogRevision(displayName, mimeType, sizeBytes, modifiedAtMillis)
            items +=
                CatalogItemProjection(
                    locatorToken = locatorToken,
                    displayName = displayName,
                    extension = extension,
                    mimeFamily = mimeFamily,
                    sizeBytes = sizeBytes,
                    modifiedAtMillis = modifiedAtMillis,
                    revision = revision,
                    contentEligible = extension in CONTENT_ELIGIBLE_EXTENSIONS,
                )
        }

        val sortedItems = items.sortedBy(CatalogItemProjection::locatorToken)
        val snapshotProjection =
            buildString {
                append(canonicalFields(CATALOG_SNAPSHOT_SCHEMA, catalogRootId))
                for (item in sortedItems) {
                    append(
                        canonicalFields(
                            item.locatorToken,
                            item.displayName,
                            item.extension,
                            item.mimeFamily,
                            item.sizeBytes?.toString() ?: "null",
                            item.modifiedAtMillis?.toString() ?: "null",
                            item.revision,
                            item.contentEligible.toString(),
                        ),
                    )
                }
                append(canonicalFields("skipped", skippedCount.toString()))
            }

        return CatalogSnapshotProjection(
            catalogRootId = catalogRootId,
            snapshotSha256 = sha256Hex(snapshotProjection),
            itemCount = sortedItems.size,
            skippedCount = skippedCount,
            items = sortedItems,
        )
    }

    private fun validateLocator(value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        if (value.isBlank() || bytes.size > MAX_CANONICAL_LOCATOR_BYTES || value.any(Char::isISOControl)) {
            throw CatalogContractFailure("catalog_invalid_entry", INVALID_ENTRY_MESSAGE)
        }
    }

    private fun validateDisplayName(value: String): String {
        val normalized = Normalizer.normalize(value, Normalizer.Form.NFC)
        val bytes = normalized.toByteArray(StandardCharsets.UTF_8)
        if (normalized.isBlank() ||
            normalized == "." ||
            normalized == ".." ||
            bytes.size > MAX_DISPLAY_NAME_BYTES ||
            normalized.any {
                it.isISOControl() ||
                    it == '/' ||
                    it == '\\' ||
                    it in UNSAFE_DISPLAY_CHARACTERS
            }
        ) {
            throw CatalogContractFailure("catalog_invalid_entry", INVALID_ENTRY_MESSAGE)
        }
        return normalized
    }

    private fun validateOptionalNonNegative(value: Long?): Long? {
        if (value != null && value < 0) {
            throw CatalogContractFailure("catalog_invalid_entry", INVALID_ENTRY_MESSAGE)
        }
        return value
    }

    private fun canonicalMimeType(value: String?): String {
        val normalized = value?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (normalized.isEmpty()) {
            return DEFAULT_MIME_TYPE
        }
        if (normalized.length > MAX_MIME_TYPE_CHARS || !MIME_TYPE_PATTERN.matches(normalized)) {
            throw CatalogContractFailure("catalog_invalid_entry", INVALID_ENTRY_MESSAGE)
        }
        return normalized
    }

    private fun mimeFamily(mimeType: String, extension: String): String {
        val prefix = mimeType.substringBefore('/', "")
        if (prefix in setOf("image", "audio", "video", "text")) {
            return prefix
        }
        if (extension in DOCUMENT_EXTENSIONS) {
            return "document"
        }
        if (extension in ARCHIVE_EXTENSIONS) {
            return "archive"
        }
        return "other"
    }

    private fun requireDigest(value: String, errorCode: String) {
        if (!LOWERCASE_SHA256.matches(value)) {
            throw CatalogContractFailure(errorCode, CATALOG_STATE_CORRUPT_MESSAGE)
        }
    }

    private fun canonicalFields(vararg fields: String): String =
        fields.joinToString(separator = "", postfix = "\n") { field ->
            val bytes = field.toByteArray(StandardCharsets.UTF_8)
            "${bytes.size}:$field"
        }
}

internal class CatalogContractFailure(
    val code: String,
    val safeMessage: String,
) : RuntimeException()

internal fun sha256Hex(value: String): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { byte -> "%02x".format(byte) }

internal fun catalogSafeExtension(displayName: String): String {
    val candidate = displayName.substringAfterLast('.', "").lowercase(Locale.ROOT)
    return if (EXTENSION_PATTERN.matches(candidate)) candidate else ""
}

internal fun catalogRevision(
    displayName: String,
    mimeType: String,
    sizeBytes: Long?,
    modifiedAtMillis: Long?,
): String =
    sha256Hex(
        catalogCanonicalFields(
            displayName,
            mimeType,
            sizeBytes?.toString() ?: "null",
            modifiedAtMillis?.toString() ?: "null",
        ),
    )

private fun catalogCanonicalFields(vararg fields: String): String =
    fields.joinToString(separator = "", postfix = "\n") { field ->
        val bytes = field.toByteArray(StandardCharsets.UTF_8)
        "${bytes.size}:$field"
    }

internal const val CATALOG_STATE_SCHEMA = "data-steward.catalog-state/v1"
internal const val CATALOG_SNAPSHOT_SCHEMA = "data-steward.catalog-snapshot/v1"
internal const val MAX_CATALOG_SOURCE_ROWS = 512
internal const val MAX_CATALOG_METADATA_BYTES = 512 * 1024
internal const val MAX_DISPLAY_NAME_BYTES = 255
internal const val MAX_CANONICAL_LOCATOR_BYTES = 2048

private const val MAX_MIME_TYPE_CHARS = 127
private const val DEFAULT_MIME_TYPE = "application/octet-stream"
private val LOWERCASE_SHA256 = Regex("^[0-9a-f]{64}$")
private val EXTENSION_PATTERN = Regex("^[a-z0-9]{1,16}$")
private val MIME_TYPE_PATTERN =
    Regex("^[a-z0-9][a-z0-9!#\$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#\$&^_.+-]{0,62}\$")
private val CONTENT_ELIGIBLE_EXTENSIONS = setOf("txt", "md", "docx", "pptx", "pdf")
private val DOCUMENT_EXTENSIONS =
    setOf("txt", "md", "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx")
private val ARCHIVE_EXTENSIONS = setOf("zip", "rar", "7z", "tar", "gz")
private val UNSAFE_DISPLAY_CHARACTERS =
    setOf(
        '\u200b',
        '\u200c',
        '\u200d',
        '\u200e',
        '\u200f',
        '\u2028',
        '\u2029',
        '\u202a',
        '\u202b',
        '\u202c',
        '\u202d',
        '\u202e',
        '\u2066',
        '\u2067',
        '\u2068',
        '\u2069',
        '\ufeff',
    )

internal const val CATALOG_TOO_LARGE_MESSAGE = "The catalog exceeds the safe local limit."
internal const val DUPLICATE_ENTRY_MESSAGE = "The document provider returned duplicate entries."
internal const val INVALID_ENTRY_MESSAGE = "The document provider returned invalid metadata."
internal const val CATALOG_STATE_CORRUPT_MESSAGE = "The catalog authorization state is invalid."
