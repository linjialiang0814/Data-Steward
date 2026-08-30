package io.datasteward.steward_app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CatalogSnapshotBuilderTest {
    private val builder = CatalogSnapshotBuilder { value -> sha256Hex("fixture-key|$value") }
    private val rootId = sha256Hex("fixture-root")

    @Test
    fun stableSnapshotIsSortedAndClassified() {
        val note = entry("doc-2", "高等数学课堂笔记.md", "text/markdown", 28, 1_720_000)
        val photo = entry("doc-1", "IMG_20260804_090000.JPG", "image/jpeg", 512, 1_710_000)

        val first = builder.build(rootId, listOf(note, photo))
        val second = builder.build(rootId, listOf(photo, note))

        assertEquals(first.snapshotSha256, second.snapshotSha256)
        assertEquals(2, first.itemCount)
        assertEquals(0, first.skippedCount)
        assertEquals(first.items.sortedBy(CatalogItemProjection::locatorToken), first.items)
        assertTrue(first.items.single { it.displayName.endsWith(".md") }.contentEligible)
        assertEquals("image", first.items.single { it.extension == "jpg" }.mimeFamily)
    }

    @Test
    fun directoriesAndVirtualDocumentsAreSkipped() {
        val result =
            builder.build(
                rootId,
                listOf(
                    entry("dir", "子目录", "vnd.android.document/directory", null, null, directory = true),
                    entry("virtual", "在线占位.pdf", "application/pdf", null, null, virtual = true),
                    entry("file", "作业.txt", "text/plain", 4, 10),
                ),
            )

        assertEquals(1, result.itemCount)
        assertEquals(2, result.skippedCount)
        assertEquals("作业.txt", result.items.single().displayName)
    }

    @Test
    fun unicodeNamesAreNormalizedBeforeHashing() {
        val decomposed = entry("doc", "Cafe\u0301.md", "text/markdown", 1, 2)
        val composed = entry("doc", "Café.md", "text/markdown", 1, 2)

        val left = builder.build(rootId, listOf(decomposed))
        val right = builder.build(rootId, listOf(composed))

        assertEquals("Café.md", left.items.single().displayName)
        assertEquals(left.snapshotSha256, right.snapshotSha256)
    }

    @Test
    fun changedMetadataChangesRevisionAndSnapshot() {
        val left = builder.build(rootId, listOf(entry("doc", "课件.pptx", null, 10, 20)))
        val right = builder.build(rootId, listOf(entry("doc", "课件.pptx", null, 11, 20)))

        assertNotEquals(left.items.single().revision, right.items.single().revision)
        assertNotEquals(left.snapshotSha256, right.snapshotSha256)
        assertEquals("document", left.items.single().mimeFamily)
    }

    @Test
    fun duplicateProviderLocatorFailsClosed() {
        val failure =
            expectCatalogFailure {
                builder.build(
                    rootId,
                    listOf(
                        entry("same", "a.txt", "text/plain", 1, 1),
                        entry("same", "b.txt", "text/plain", 1, 1),
                    ),
                )
            }

        assertEquals("catalog_duplicate_entry", failure.code)
    }

    @Test
    fun tokenCollisionFailsClosed() {
        val collisionBuilder = CatalogSnapshotBuilder { "a".repeat(64) }
        val failure =
            expectCatalogFailure {
                collisionBuilder.build(
                    rootId,
                    listOf(
                        entry("one", "a.txt", "text/plain", 1, 1),
                        entry("two", "b.txt", "text/plain", 1, 1),
                    ),
                )
            }

        assertEquals("catalog_duplicate_entry", failure.code)
    }

    @Test
    fun invalidNamesMimeAndNegativeMetadataFailClosed() {
        val invalidEntries =
            listOf(
                entry("one", "../secret.txt", "text/plain", 1, 1),
                entry("two", "bad\u0000.txt", "text/plain", 1, 1),
                entry("bidi", "safe\u202efdp.exe", "text/plain", 1, 1),
                entry("three", "okay.txt", "not a mime", 1, 1),
                entry("four", "okay.txt", "text/plain", -1, 1),
                entry("five", "okay.txt", "text/plain", 1, -1),
            )

        for (invalid in invalidEntries) {
            assertEquals(
                "catalog_invalid_entry",
                expectCatalogFailure { builder.build(rootId, listOf(invalid)) }.code,
            )
        }
    }

    @Test
    fun sourceRowAndMetadataLimitsFailClosed() {
        val tooMany =
            (0..MAX_CATALOG_SOURCE_ROWS).map { index ->
                entry("doc-$index", "$index.txt", "text/plain", 1, 1)
            }
        assertEquals(
            "catalog_too_large",
            expectCatalogFailure { builder.build(rootId, tooMany) }.code,
        )

        val hugeProjection =
            (0 until 300).map { index ->
                entry("doc-$index-${"x".repeat(1800)}", "$index.txt", "text/plain", 1, 1)
            }
        assertEquals(
            "catalog_too_large",
            expectCatalogFailure { builder.build(rootId, hugeProjection) }.code,
        )
    }

    @Test
    fun snapshotMapContainsNoCanonicalLocator() {
        val result = builder.build(rootId, listOf(entry("private-uri", "课堂.txt", null, 1, 1)))
        val mapText = result.toMap(1234).toString()

        assertFalse(mapText.contains("private-uri"))
        assertFalse(mapText.contains("content://"))
        assertTrue(mapText.contains(CATALOG_SNAPSHOT_SCHEMA))
    }

    private fun entry(
        locator: String,
        name: String,
        mime: String?,
        size: Long?,
        modified: Long?,
        directory: Boolean = false,
        virtual: Boolean = false,
    ) =
        CatalogSourceEntry(
            canonicalLocator = locator,
            displayName = name,
            mimeType = mime,
            sizeBytes = size,
            modifiedAtMillis = modified,
            isDirectory = directory,
            isVirtual = virtual,
        )

    private fun expectCatalogFailure(action: () -> Unit): CatalogContractFailure {
        try {
            action()
        } catch (failure: CatalogContractFailure) {
            return failure
        }
        fail("Expected CatalogContractFailure")
        error("unreachable")
    }
}
