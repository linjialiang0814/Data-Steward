package io.datasteward.steward_app

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import com.google.android.gms.tasks.Tasks
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.chinese.ChineseTextRecognizerOptions
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

internal class CatalogOcrExecutor(
    private val activity: Activity,
    private val catalog: CatalogDirectoryExecutor,
) : AutoCloseable {
    private val busy = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val worker = Executors.newSingleThreadExecutor(OcrThreadFactory())

    fun analyze(arguments: Any?, result: MethodChannel.Result) {
        if (closed.get()) {
            result.error("ocr_unavailable", OCR_UNAVAILABLE_MESSAGE, null)
            return
        }
        if (!busy.compareAndSet(false, true)) {
            result.error("ocr_busy", OCR_BUSY_MESSAGE, null)
            return
        }
        val request =
            try {
                AndroidOcrProjectionContract.parseRequest(arguments)
            } catch (failure: AndroidOcrFailure) {
                busy.set(false)
                result.error(failure.code, failure.safeMessage, null)
                return
            }
        try {
            worker.execute {
                try {
                    val projection = execute(request)
                    respondSuccess(result, projection.toMap())
                } catch (failure: AndroidOcrFailure) {
                    Log.w(OCR_LOG_TAG, "operation_failed:${failure.code}")
                    respondError(result, failure.code, failure.safeMessage)
                } catch (_: Exception) {
                    Log.w(OCR_LOG_TAG, "operation_failed:ocr_unavailable")
                    respondError(result, "ocr_unavailable", OCR_UNAVAILABLE_MESSAGE)
                } finally {
                    busy.set(false)
                }
            }
        } catch (_: RuntimeException) {
            busy.set(false)
            result.error("ocr_unavailable", OCR_UNAVAILABLE_MESSAGE, null)
        }
    }

    private fun execute(request: AndroidOcrBatchRequest): AndroidOcrBatchProjection {
        if (closed.get()) {
            throw AndroidOcrFailure("ocr_unavailable", OCR_UNAVAILABLE_MESSAGE)
        }
        val inputs = catalog.resolveAndroidOcrRequest(request)
        val recognizer =
            TextRecognition.getClient(ChineseTextRecognizerOptions.Builder().build())
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_OCR_BATCH_SECONDS)
        try {
            val raw =
                inputs.map { input ->
                    val remainingNanos = deadline - System.nanoTime()
                    if (remainingNanos <= 0) {
                        throw AndroidOcrFailure("ocr_timeout", OCR_TIMEOUT_MESSAGE)
                    }
                    val bitmap = decodeBoundedBitmap(input)
                    val image = InputImage.fromBitmap(bitmap, 0)
                    val timeoutNanos =
                        min(remainingNanos, TimeUnit.SECONDS.toNanos(MAX_OCR_IMAGE_SECONDS))
                    val recognized =
                        try {
                            Tasks.await(recognizer.process(image), timeoutNanos, TimeUnit.NANOSECONDS)
                        } catch (_: TimeoutException) {
                            throw AndroidOcrFailure("ocr_timeout", OCR_TIMEOUT_MESSAGE)
                        } catch (_: Exception) {
                            throw AndroidOcrFailure("ocr_unavailable", OCR_UNAVAILABLE_MESSAGE)
                        } finally {
                            bitmap.recycle()
                        }
                    catalog.verifyAndroidOcrInput(input)
                    val elements =
                        recognized.textBlocks.flatMap { block ->
                            block.lines.flatMap { line -> line.elements }
                        }
                    AndroidOcrRawResult(
                        locatorToken = input.locatorToken,
                        revision = input.revision,
                        format = input.format,
                        text = recognized.text,
                        confidences = elements.map { it.confidence },
                        languageHints = elements.map { it.recognizedLanguage },
                    )
                }
            catalog.resolveAndroidOcrRequest(request)
            return AndroidOcrProjectionContract.build(request, raw, System.currentTimeMillis())
        } finally {
            recognizer.close()
        }
    }

    private fun decodeBoundedBitmap(input: ResolvedAndroidOcrInput): Bitmap {
        val encoded = readBoundedImageBytes(input)
        try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(encoded, 0, encoded.size, bounds)
            val width = bounds.outWidth
            val height = bounds.outHeight
            if (width <= 0 || height <= 0) {
                throw AndroidOcrFailure("ocr_image_decode_failed", OCR_IMAGE_DECODE_FAILED_MESSAGE)
            }
            if (width > MAX_OCR_IMAGE_EDGE || height > MAX_OCR_IMAGE_EDGE ||
                width.toLong() * height.toLong() > MAX_OCR_IMAGE_PIXELS
            ) {
                throw AndroidOcrFailure(
                    "ocr_image_dimensions_unsafe",
                    OCR_IMAGE_DIMENSIONS_UNSAFE_MESSAGE,
                )
            }
            val options =
                BitmapFactory.Options().apply {
                    inSampleSize = calculateOcrInSampleSize(width, height)
                    inPreferredConfig = Bitmap.Config.ARGB_8888
                }
            val bitmap =
                BitmapFactory.decodeByteArray(encoded, 0, encoded.size, options)
                    ?: throw AndroidOcrFailure(
                        "ocr_image_decode_failed",
                        OCR_IMAGE_DECODE_FAILED_MESSAGE,
                    )
            if (bitmap.width <= 0 || bitmap.height <= 0 ||
                bitmap.width > MAX_OCR_DECODE_EDGE || bitmap.height > MAX_OCR_DECODE_EDGE ||
                bitmap.width.toLong() * bitmap.height.toLong() > MAX_OCR_DECODE_PIXELS
            ) {
                bitmap.recycle()
                throw AndroidOcrFailure(
                    "ocr_image_dimensions_unsafe",
                    OCR_IMAGE_DIMENSIONS_UNSAFE_MESSAGE,
                )
            }
            return bitmap
        } finally {
            encoded.fill(0)
        }
    }

    private fun readBoundedImageBytes(input: ResolvedAndroidOcrInput): ByteArray {
        if (input.sizeBytes <= 0 || input.sizeBytes > MAX_OCR_ENCODED_BYTES) {
            throw AndroidOcrFailure("ocr_image_stream_unavailable", OCR_IMAGE_STREAM_MESSAGE)
        }
        val encoded = ByteArray(input.sizeBytes.toInt())
        try {
            activity.contentResolver.openInputStream(input.uri)?.use { stream ->
                var offset = 0
                while (offset < encoded.size) {
                    val read = stream.read(encoded, offset, encoded.size - offset)
                    if (read < 0) {
                        throw AndroidOcrFailure(
                            "ocr_revision_changed",
                            OCR_REVISION_CHANGED_MESSAGE,
                        )
                    }
                    if (read == 0) {
                        throw AndroidOcrFailure(
                            "ocr_image_stream_unavailable",
                            OCR_IMAGE_STREAM_MESSAGE,
                        )
                    }
                    offset += read
                }
                if (stream.read() != -1) {
                    throw AndroidOcrFailure(
                        "ocr_revision_changed",
                        OCR_REVISION_CHANGED_MESSAGE,
                    )
                }
            } ?: throw AndroidOcrFailure(
                "ocr_image_stream_unavailable",
                OCR_IMAGE_STREAM_MESSAGE,
            )
            return encoded
        } catch (failure: AndroidOcrFailure) {
            encoded.fill(0)
            throw failure
        } catch (_: SecurityException) {
            encoded.fill(0)
            throw AndroidOcrFailure("ocr_permission_lost", OCR_PERMISSION_LOST_MESSAGE)
        } catch (_: Exception) {
            encoded.fill(0)
            throw AndroidOcrFailure("ocr_image_stream_unavailable", OCR_IMAGE_STREAM_MESSAGE)
        }
    }

    private fun respondSuccess(result: MethodChannel.Result, value: Map<String, Any?>) {
        activity.runOnUiThread {
            if (!closed.get()) {
                result.success(value)
            } else {
                result.error("ocr_unavailable", OCR_UNAVAILABLE_MESSAGE, null)
            }
        }
    }

    private fun respondError(result: MethodChannel.Result, code: String, message: String) {
        activity.runOnUiThread { result.error(code, message, null) }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        worker.shutdownNow()
        runCatching { worker.awaitTermination(2, TimeUnit.SECONDS) }
    }

    private class OcrThreadFactory : ThreadFactory {
        override fun newThread(operation: Runnable): Thread =
            Thread(operation, "data-steward-ocr-1").apply {
                isDaemon = false
                priority = Thread.NORM_PRIORITY - 1
            }
    }
}

private const val MAX_OCR_IMAGE_EDGE = 8192
private const val MAX_OCR_IMAGE_PIXELS = 16_000_000L
private const val MAX_OCR_ENCODED_BYTES = 12L * 1024 * 1024
private const val MAX_OCR_DECODE_EDGE = 2048
private const val MAX_OCR_DECODE_PIXELS = 4_000_000L
private const val OCR_LOG_TAG = "DataStewardOcr"
private const val MAX_OCR_IMAGE_SECONDS = 10L
private const val MAX_OCR_BATCH_SECONDS = 45L
private const val OCR_BUSY_MESSAGE = "An OCR operation is already active."
private const val OCR_TIMEOUT_MESSAGE = "The OCR operation timed out."
private const val OCR_IMAGE_STREAM_MESSAGE = "The requested image stream is unavailable."
private const val OCR_IMAGE_DECODE_FAILED_MESSAGE = "The requested image encoding is invalid."
private const val OCR_IMAGE_DIMENSIONS_UNSAFE_MESSAGE = "The requested image dimensions are unsafe."
private const val OCR_UNAVAILABLE_MESSAGE = "On-device OCR is unavailable."

internal fun calculateOcrInSampleSize(width: Int, height: Int): Int {
    var sampleSize = 1
    while (width / sampleSize > MAX_OCR_DECODE_EDGE ||
        height / sampleSize > MAX_OCR_DECODE_EDGE ||
        (width.toLong() * height.toLong()) / (sampleSize.toLong() * sampleSize) >
        MAX_OCR_DECODE_PIXELS
    ) {
        sampleSize *= 2
    }
    return sampleSize
}
