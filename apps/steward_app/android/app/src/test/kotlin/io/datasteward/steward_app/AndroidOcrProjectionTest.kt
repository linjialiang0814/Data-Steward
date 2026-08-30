package io.datasteward.steward_app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidOcrProjectionTest {
    private val root = "a".repeat(64)
    private val snapshot = "b".repeat(64)
    private val token = "c".repeat(64)
    private val revision = "d".repeat(64)

    @Test
    fun parsesExactBoundedRequest() {
        val request =
            AndroidOcrProjectionContract.parseRequest(
                mapOf(
                    "catalogRootId" to root,
                    "snapshotSha256" to snapshot,
                    "items" to
                        listOf(
                            mapOf(
                                "locatorToken" to token,
                                "revision" to revision,
                            ),
                        ),
                ),
            )

        assertEquals(root, request.catalogRootId)
        assertEquals(token, request.items.single().locatorToken)
    }

    @Test
    fun rejectsUnknownDuplicateAndOversizedRequestItems() {
        val valid = mapOf("locatorToken" to token, "revision" to revision)
        assertFailure("ocr_request_invalid") {
            AndroidOcrProjectionContract.parseRequest(
                mapOf(
                    "catalogRootId" to root,
                    "snapshotSha256" to snapshot,
                    "items" to listOf(valid),
                    "extra" to true,
                ),
            )
        }
        assertFailure("ocr_request_invalid") {
            AndroidOcrProjectionContract.parseRequest(
                mapOf(
                    "catalogRootId" to root,
                    "snapshotSha256" to snapshot,
                    "items" to listOf(valid, valid),
                ),
            )
        }
        assertFailure("ocr_request_invalid") {
            AndroidOcrProjectionContract.parseRequest(
                mapOf(
                    "catalogRootId" to root,
                    "snapshotSha256" to snapshot,
                    "items" to
                        List(MAX_OCR_BATCH_ITEMS + 1) { index ->
                            mapOf(
                                "locatorToken" to index.toString().padStart(64, '0'),
                                "revision" to revision,
                            )
                        },
                ),
            )
        }
    }

    @Test
    fun buildsNormalizedProjectionWithConfidenceAndLanguageHints() {
        val request = request()
        val projection =
            AndroidOcrProjectionContract.build(
                request,
                listOf(
                    AndroidOcrRawResult(
                        locatorToken = token,
                        revision = revision,
                        format = "jpg",
                        text = "  课堂   重点\r\n复习导数  ",
                        confidences = listOf(0f, 0.8f, 1f),
                        languageHints = listOf("zh", "en", "zh", "bad tag!"),
                    ),
                ),
                generatedAtMillis = 1_800_000_000_000,
            )
        val item = projection.items.single()

        assertEquals("课堂 重点\n复习导数", item.text)
        assertEquals(0.6, item.confidence!!, 0.0001)
        assertEquals(listOf("en", "zh"), item.languageHints)
        assertEquals("recognized", item.status)
        assertEquals(1, projection.toMap()["recognizedCount"])
    }

    @Test
    fun emptyTextHasNoConfidenceWhenRecognizerDoesNotProvideIt() {
        val item =
            AndroidOcrProjectionContract.build(
                request(),
                listOf(
                    AndroidOcrRawResult(token, revision, "png", "  ", listOf(0f), listOf("und")),
                ),
                1,
            ).items.single()

        assertEquals("no_text", item.status)
        assertEquals(0, item.charCount)
        assertNull(item.confidence)
        assertTrue(item.text.isEmpty())
    }

    @Test
    fun rejectsChangedRevisionAndUnsafeControls() {
        assertFailure("ocr_result_invalid") {
            AndroidOcrProjectionContract.build(
                request(),
                listOf(
                    AndroidOcrRawResult(token, "e".repeat(64), "jpg", "text", emptyList(), emptyList()),
                ),
                1,
            )
        }
        assertFailure("ocr_result_invalid") {
            AndroidOcrProjectionContract.build(
                request(),
                listOf(
                    AndroidOcrRawResult(token, revision, "jpg", "bad\u0000text", emptyList(), emptyList()),
                ),
                1,
            )
        }
    }

    @Test
    fun truncatesByUnicodeCodePointWithoutSplittingSurrogatePair() {
        val source = "课".repeat(MAX_OCR_TEXT_CHARS - 1) + "😀尾"
        val item =
            AndroidOcrProjectionContract.build(
                request(),
                listOf(AndroidOcrRawResult(token, revision, "jpg", source, emptyList(), emptyList())),
                1,
            ).items.single()

        assertEquals(MAX_OCR_TEXT_CHARS, item.charCount)
        assertTrue(item.text.endsWith("😀"))
        assertTrue(item.truncated)
    }

    @Test
    fun boundedDecodeSampleSizeKeepsMemoryBudget() {
        assertEquals(1, calculateOcrInSampleSize(774, 349))
        assertEquals(2, calculateOcrInSampleSize(4000, 3000))
        assertEquals(4, calculateOcrInSampleSize(8192, 1000))
    }

    private fun request() =
        AndroidOcrBatchRequest(
            catalogRootId = root,
            snapshotSha256 = snapshot,
            items = listOf(AndroidOcrRequestItem(token, revision)),
        )

    private fun assertFailure(code: String, operation: () -> Unit) {
        val failure = assertThrows(AndroidOcrFailure::class.java, operation)
        assertEquals(code, failure.code)
    }
}
