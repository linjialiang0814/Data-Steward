package io.datasteward.steward_app

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale

internal data class AndroidOcrRequestItem(
    val locatorToken: String,
    val revision: String,
)

internal data class AndroidOcrBatchRequest(
    val catalogRootId: String,
    val snapshotSha256: String,
    val items: List<AndroidOcrRequestItem>,
)

internal data class AndroidOcrRawResult(
    val locatorToken: String,
    val revision: String,
    val format: String,
    val text: String,
    val confidences: List<Float>,
    val languageHints: List<String>,
)

internal data class AndroidOcrProjectionItem(
    val locatorToken: String,
    val revision: String,
    val format: String,
    val status: String,
    val text: String,
    val textSha256: String,
    val charCount: Int,
    val truncated: Boolean,
    val confidence: Double?,
    val languageHints: List<String>,
) {
    fun toMap(): Map<String, Any?> =
        mapOf(
            "locatorToken" to locatorToken,
            "revision" to revision,
            "format" to format,
            "status" to status,
            "text" to text,
            "textSha256" to textSha256,
            "charCount" to charCount,
            "truncated" to truncated,
            "confidence" to confidence,
            "languageHints" to languageHints,
            "extractorId" to OCR_EXTRACTOR_ID,
            "extractorVersion" to OCR_EXTRACTOR_VERSION,
        )
}

internal data class AndroidOcrBatchProjection(
    val catalogRootId: String,
    val snapshotSha256: String,
    val generatedAtMillis: Long,
    val items: List<AndroidOcrProjectionItem>,
) {
    fun toMap(): Map<String, Any?> =
        mapOf(
            "schemaVersion" to ANDROID_OCR_BATCH_SCHEMA,
            "catalogRootId" to catalogRootId,
            "snapshotSha256" to snapshotSha256,
            "generatedAtMillis" to generatedAtMillis,
            "itemCount" to items.size,
            "recognizedCount" to items.count { it.status == "recognized" },
            "noTextCount" to items.count { it.status == "no_text" },
            "items" to items.map(AndroidOcrProjectionItem::toMap),
        )
}

internal object AndroidOcrProjectionContract {
    fun parseRequest(arguments: Any?): AndroidOcrBatchRequest {
        val values = arguments as? Map<*, *>
            ?: throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        if (values.keys != setOf("catalogRootId", "snapshotSha256", "items")) {
            throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        }
        val rootId = requireDigest(values["catalogRootId"])
        val snapshot = requireDigest(values["snapshotSha256"])
        val rawItems = values["items"] as? List<*>
            ?: throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        if (rawItems.isEmpty() || rawItems.size > MAX_OCR_BATCH_ITEMS) {
            throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        }
        val items =
            rawItems.map { raw ->
                val item = raw as? Map<*, *>
                    ?: throw AndroidOcrFailure(
                        "ocr_request_invalid",
                        OCR_REQUEST_INVALID_MESSAGE,
                    )
                if (item.keys != setOf("locatorToken", "revision")) {
                    throw AndroidOcrFailure(
                        "ocr_request_invalid",
                        OCR_REQUEST_INVALID_MESSAGE,
                    )
                }
                AndroidOcrRequestItem(
                    locatorToken = requireDigest(item["locatorToken"]),
                    revision = requireDigest(item["revision"]),
                )
            }
        if (items.map { it.locatorToken }.toSet().size != items.size) {
            throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        }
        return AndroidOcrBatchRequest(rootId, snapshot, items)
    }

    fun build(
        request: AndroidOcrBatchRequest,
        results: List<AndroidOcrRawResult>,
        generatedAtMillis: Long,
    ): AndroidOcrBatchProjection {
        if (generatedAtMillis < 0 || results.size != request.items.size) {
            throw AndroidOcrFailure("ocr_result_invalid", OCR_RESULT_INVALID_MESSAGE)
        }
        val expected = request.items.associateBy(AndroidOcrRequestItem::locatorToken)
        var totalChars = 0
        val projected =
            results.map { raw ->
                val requestItem = expected[raw.locatorToken]
                    ?: throw AndroidOcrFailure("ocr_result_invalid", OCR_RESULT_INVALID_MESSAGE)
                if (requestItem.revision != raw.revision || raw.format !in OCR_IMAGE_FORMATS) {
                    throw AndroidOcrFailure("ocr_result_invalid", OCR_RESULT_INVALID_MESSAGE)
                }
                val normalized = normalizeText(raw.text)
                val truncatedText = takeCodePoints(normalized, MAX_OCR_TEXT_CHARS)
                val truncated = truncatedText != normalized
                val charCount = truncatedText.codePointCount(0, truncatedText.length)
                totalChars += charCount
                if (totalChars > MAX_OCR_BATCH_TEXT_CHARS) {
                    throw AndroidOcrFailure("ocr_result_too_large", OCR_RESULT_TOO_LARGE_MESSAGE)
                }
                val languages =
                    raw.languageHints
                        .map { it.trim() }
                        .filter { OCR_LANGUAGE_PATTERN.matches(it) }
                        .distinct()
                        .sorted()
                        .take(MAX_OCR_LANGUAGE_HINTS)
                val usableConfidences = raw.confidences.filter { it >= 0f && it <= 1f }
                val confidence =
                    if (truncatedText.isEmpty() || usableConfidences.isEmpty()) {
                        null
                    } else {
                        val average = usableConfidences.average()
                        String.format(Locale.ROOT, "%.4f", average).toDouble()
                    }
                AndroidOcrProjectionItem(
                    locatorToken = raw.locatorToken,
                    revision = raw.revision,
                    format = raw.format,
                    status = if (truncatedText.isEmpty()) "no_text" else "recognized",
                    text = truncatedText,
                    textSha256 = sha256Bytes(truncatedText.toByteArray(StandardCharsets.UTF_8)),
                    charCount = charCount,
                    truncated = truncated,
                    confidence = confidence,
                    languageHints = languages,
                )
            }
        if (projected.map { it.locatorToken }.toSet().size != projected.size) {
            throw AndroidOcrFailure("ocr_result_invalid", OCR_RESULT_INVALID_MESSAGE)
        }
        return AndroidOcrBatchProjection(
            catalogRootId = request.catalogRootId,
            snapshotSha256 = request.snapshotSha256,
            generatedAtMillis = generatedAtMillis,
            items = projected.sortedBy(AndroidOcrProjectionItem::locatorToken),
        )
    }

    private fun normalizeText(value: String): String {
        val normalized =
            Normalizer
                .normalize(value, Normalizer.Form.NFC)
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .lines()
                .joinToString("\n") { line -> line.trim().replace(Regex("[\\t ]+"), " ") }
                .trim()
        if (normalized.any { it.isISOControl() && it != '\n' && it != '\t' } ||
            normalized.toByteArray(StandardCharsets.UTF_8).size > MAX_OCR_TEXT_UTF8_BYTES
        ) {
            throw AndroidOcrFailure("ocr_result_invalid", OCR_RESULT_INVALID_MESSAGE)
        }
        return normalized
    }

    private fun takeCodePoints(value: String, limit: Int): String {
        val count = value.codePointCount(0, value.length)
        if (count <= limit) return value
        return value.substring(0, value.offsetByCodePoints(0, limit))
    }

    private fun requireDigest(value: Any?): String {
        val text = value as? String
            ?: throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        if (!OCR_DIGEST_PATTERN.matches(text)) {
            throw AndroidOcrFailure("ocr_request_invalid", OCR_REQUEST_INVALID_MESSAGE)
        }
        return text
    }
}

internal class AndroidOcrFailure(
    val code: String,
    val safeMessage: String,
) : RuntimeException()

internal fun sha256Bytes(value: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { byte ->
        "%02x".format(byte)
    }

internal const val ANDROID_OCR_BATCH_SCHEMA = "data-steward.android-ocr-batch/v1"
internal const val OCR_EXTRACTOR_ID = "mlkit-chinese-bundled"
internal const val OCR_EXTRACTOR_VERSION = "16.0.1"
internal const val MAX_OCR_BATCH_ITEMS = 6
internal const val MAX_OCR_TEXT_CHARS = 4_000
internal const val MAX_OCR_BATCH_TEXT_CHARS = 20_000
internal const val MAX_OCR_TEXT_UTF8_BYTES = 32 * 1024
internal const val MAX_OCR_LANGUAGE_HINTS = 8
internal val OCR_IMAGE_FORMATS = setOf("jpg", "jpeg", "png")

private val OCR_DIGEST_PATTERN = Regex("^[0-9a-f]{64}$")
private val OCR_LANGUAGE_PATTERN = Regex("^(und|[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*)$")
internal const val OCR_REQUEST_INVALID_MESSAGE = "The OCR request is invalid."
internal const val OCR_RESULT_INVALID_MESSAGE = "The OCR result is invalid."
internal const val OCR_RESULT_TOO_LARGE_MESSAGE = "The OCR result exceeds the safe limit."
