package io.datasteward.steward_app

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.ArrayDeque

class LanDiscoveryExecutor(private val context: Context) {
    private val handler = Handler(Looper.getMainLooper())
    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private var active: DiscoverySession? = null

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "discoverHub" -> discover(call.arguments, result)
            "cancelDiscovery" -> {
                active?.finishError("discovery_cancelled")
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    fun close() {
        active?.finishError("discovery_cancelled")
        active = null
    }

    private fun discover(arguments: Any?, result: MethodChannel.Result) {
        if (active != null) {
            result.error("discovery_busy", "A discovery attempt is already active.", null)
            return
        }
        val value = arguments as? Map<*, *>
        if (value == null || value.keys != REQUIRED_KEYS) {
            result.error("discovery_request_invalid", "Discovery request is invalid.", null)
            return
        }
        val hubId = value["hubId"] as? String
        val fingerprint = value["certFingerprint"] as? String
        val protocolVersion = value["protocolVersion"] as? String
        val timeoutMs = value["timeoutMs"] as? Int
        if (
            hubId == null || !ULID.matches(hubId) ||
            fingerprint == null || !FINGERPRINT.matches(fingerprint) ||
            protocolVersion != "1" ||
            timeoutMs == null || timeoutMs !in 3_000..10_000
        ) {
            result.error("discovery_request_invalid", "Discovery request is invalid.", null)
            return
        }
        val session = DiscoverySession(hubId, fingerprint, protocolVersion, timeoutMs, result)
        active = session
        session.start()
    }

    private inner class DiscoverySession(
        private val hubId: String,
        private val fingerprint: String,
        private val protocolVersion: String,
        private val timeoutMs: Int,
        private val result: MethodChannel.Result,
    ) : NsdManager.DiscoveryListener {
        private val queued = ArrayDeque<NsdServiceInfo>()
        private val seen = mutableSetOf<String>()
        private val candidates = linkedSetOf<String>()
        private val multicastLock: WifiManager.MulticastLock =
            wifiManager.createMulticastLock("data-steward-discovery").apply {
                setReferenceCounted(false)
            }
        private var discoveryStarted = false
        private var collectionEnded = false
        private var resolving = false
        private var resolveScheduled = false
        private var finished = false

        fun start() {
            try {
                multicastLock.acquire()
                handler.postDelayed({ finishFromCandidates() }, timeoutMs.toLong())
                handler.postDelayed({ endCollection() }, COLLECTION_WINDOW_MS)
                nsdManager.discoverServices(
                    SERVICE_TYPE,
                    NsdManager.PROTOCOL_DNS_SD,
                    this,
                )
            } catch (_: RuntimeException) {
                finishError("discovery_unavailable")
            }
        }

        override fun onDiscoveryStarted(serviceType: String) {
            discoveryStarted = true
        }

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            if (finished || normalizeType(serviceInfo.serviceType) != SERVICE_TYPE) return
            val identity = "${serviceInfo.serviceName}|${serviceInfo.serviceType}"
            if (!seen.add(identity)) return
            if (seen.size > MAX_SERVICES) {
                finishError("discovery_saturated")
                return
            }
            safeEndpoint(serviceInfo)?.let {
                candidates.add(it)
                if (candidates.size > 1) finishError("discovery_ambiguous")
                return
            }
            queued.addLast(serviceInfo)
            if (collectionEnded) scheduleResolve()
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit

        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            finishError("discovery_unavailable")
        }

        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
            if (!finished) finishError("discovery_unavailable")
        }

        override fun onDiscoveryStopped(serviceType: String) {
            discoveryStarted = false
            scheduleResolve()
        }

        private fun endCollection() {
            if (finished || collectionEnded) return
            collectionEnded = true
            if (discoveryStarted) {
                try {
                    nsdManager.stopServiceDiscovery(this)
                } catch (_: RuntimeException) {
                    finishError("discovery_unavailable")
                }
            } else {
                scheduleResolve()
            }
        }

        @Suppress("DEPRECATION")
        private fun resolveNext() {
            if (finished || resolving || queued.isEmpty()) return
            resolving = true
            val next = queued.removeFirst()
            try {
                nsdManager.resolveService(
                    next,
                    object : NsdManager.ResolveListener {
                        override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                            resolving = false
                            scheduleResolve()
                        }

                        override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                            safeEndpoint(serviceInfo)?.let { candidates.add(it) }
                            resolving = false
                            if (candidates.size > 1) {
                                finishError("discovery_ambiguous")
                            } else {
                                scheduleResolve()
                            }
                        }
                    },
                )
            } catch (_: RuntimeException) {
                resolving = false
                scheduleResolve()
            }
        }

        private fun scheduleResolve() {
            if (finished || resolving || resolveScheduled || queued.isEmpty()) return
            resolveScheduled = true
            handler.postDelayed(
                {
                    resolveScheduled = false
                    resolveNext()
                },
                RESOLVE_SETTLE_MS,
            )
        }

        private fun safeEndpoint(info: NsdServiceInfo): String? {
            val attributes = info.attributes
            if (attributes.keys != TXT_KEYS) return null
            val values = attributes.mapValues { decodeUtf8(it.value) ?: return null }
            if (
                values["hub_id"] != hubId ||
                values["protocol_version"] != protocolVersion ||
                values["cert_fingerprint"] != fingerprint ||
                values["pairing_available"] !in setOf("true", "false")
            ) return null
            val host = info.host?.hostAddress ?: return null
            if (!privateIpv4(host) || info.port !in 1..65_535) return null
            return "https://$host:${info.port}"
        }

        private fun finishFromCandidates() {
            when (candidates.size) {
                1 -> finishSuccess(candidates.single())
                0 -> finishError("discovery_not_found")
                else -> finishError("discovery_ambiguous")
            }
        }

        private fun finishSuccess(baseUrl: String) {
            if (finished) return
            finish {
                result.success(
                    mapOf(
                        "schema_version" to "data-steward.lan-discovery/v1",
                        "base_url" to baseUrl,
                    ),
                )
            }
        }

        fun finishError(code: String) {
            if (finished) return
            finish { result.error(code, "The paired computer was not safely discovered.", null) }
        }

        private fun finish(deliver: () -> Unit) {
            if (finished) return
            finished = true
            handler.removeCallbacksAndMessages(null)
            if (discoveryStarted) {
                try {
                    nsdManager.stopServiceDiscovery(this)
                } catch (_: RuntimeException) {
                    // Session is already terminal; release our owned resources.
                }
            }
            if (multicastLock.isHeld) multicastLock.release()
            if (active === this) active = null
            deliver()
        }
    }

    companion object {
        private const val SERVICE_TYPE = "_datasteward._tcp."
        private const val MAX_SERVICES = 8
        private const val COLLECTION_WINDOW_MS = 1_200L
        private const val RESOLVE_SETTLE_MS = 200L
        private val REQUIRED_KEYS =
            setOf("hubId", "certFingerprint", "protocolVersion", "timeoutMs")
        private val TXT_KEYS =
            setOf("hub_id", "protocol_version", "cert_fingerprint", "pairing_available")
        private val ULID = Regex("^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val FINGERPRINT = Regex("^[0-9a-f]{64}$")

        private fun normalizeType(value: String): String =
            value.removeSuffix("local.").removeSuffix("local").let {
                if (it.endsWith('.')) it else "$it."
            }

        private fun decodeUtf8(value: ByteArray): String? =
            try {
                Charsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString()
            } catch (_: Exception) {
                null
            }

        private fun privateIpv4(host: String): Boolean {
            val parts = host.split('.').map { it.toIntOrNull() }
            if (parts.size != 4 || parts.any { it == null || it !in 0..255 }) return false
            return parts[0] == 10 ||
                (parts[0] == 172 && parts[1]!! in 16..31) ||
                (parts[0] == 192 && parts[1] == 168)
        }
    }
}
