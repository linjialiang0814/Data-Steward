package io.datasteward.steward_app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private lateinit var safExecutor: SafExecutor
    private lateinit var catalogDirectoryExecutor: CatalogDirectoryExecutor
    private lateinit var catalogOcrExecutor: CatalogOcrExecutor
    private lateinit var securePairingExecutor: SecurePairingExecutor
    private lateinit var lanDiscoveryExecutor: LanDiscoveryExecutor
    private var pendingPickerResult: MethodChannel.Result? = null
    private var pendingPickerKind: DirectoryPickerKind? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        safExecutor = SafExecutor(this)
        catalogDirectoryExecutor = CatalogDirectoryExecutor(this)
        catalogOcrExecutor = CatalogOcrExecutor(this, catalogDirectoryExecutor)
        securePairingExecutor = SecurePairingExecutor(this)
        lanDiscoveryExecutor = LanDiscoveryExecutor(this)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            SAF_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getPermissionState" -> safExecutor.getPermissionState(result)
                "selectDirectory" -> selectDirectory(DirectoryPickerKind.SAF_PROBE, result)
                "writeProbe" -> safExecutor.writeProbe(result)
                "readProbe" -> safExecutor.readProbe(result)
                "deleteProbe" -> safExecutor.deleteProbe(result)
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CATALOG_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getCatalogState" -> catalogDirectoryExecutor.getCatalogState(result)
                "selectCatalogDirectory" ->
                    selectDirectory(DirectoryPickerKind.CATALOG, result)
                "buildCatalogSnapshot" -> catalogDirectoryExecutor.buildCatalogSnapshot(result)
                "setContentAnalysisEnabled" ->
                    catalogDirectoryExecutor.setContentAnalysisEnabled(call.arguments, result)
                "analyzeCatalogImages" -> catalogOcrExecutor.analyze(call.arguments, result)
                "forgetCatalogDirectory" -> catalogDirectoryExecutor.forgetCatalogDirectory(result)
                "saveCatalogOutbox" ->
                    catalogDirectoryExecutor.saveCatalogOutbox(call.arguments, result)
                "loadCatalogOutbox" -> catalogDirectoryExecutor.loadCatalogOutbox(result)
                "clearCatalogOutbox" ->
                    catalogDirectoryExecutor.clearCatalogOutbox(call.arguments, result)
                "saveOcrOutbox" ->
                    catalogDirectoryExecutor.saveOcrOutbox(call.arguments, result)
                "loadOcrOutbox" -> catalogDirectoryExecutor.loadOcrOutbox(result)
                "clearOcrOutbox" ->
                    catalogDirectoryExecutor.clearOcrOutbox(call.arguments, result)
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            SECURE_PAIRING_CHANNEL,
        ).setMethodCallHandler(securePairingExecutor::handle)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            LAN_DISCOVERY_CHANNEL,
        ).setMethodCallHandler(lanDiscoveryExecutor::handle)
    }

    override fun onDestroy() {
        if (::catalogOcrExecutor.isInitialized) {
            catalogOcrExecutor.close()
        }
        if (::lanDiscoveryExecutor.isInitialized) {
            lanDiscoveryExecutor.close()
        }
        super.onDestroy()
    }

    private fun selectDirectory(
        kind: DirectoryPickerKind,
        result: MethodChannel.Result,
    ) {
        if (pendingPickerResult != null) {
            result.error("busy", "A directory selection is already active.", null)
            return
        }

        val intent =
            Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        (if (kind == DirectoryPickerKind.SAF_PROBE) {
                            Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        } else {
                            0
                        }) or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
                )
            }

        pendingPickerResult = result
        pendingPickerKind = kind
        try {
            startActivityForResult(intent, kind.requestCode)
        } catch (_: ActivityNotFoundException) {
            pendingPickerResult = null
            pendingPickerKind = null
            result.error("unsupported", "The system directory picker is unavailable.", null)
        }
    }

    @Deprecated("Required for ACTION_OPEN_DOCUMENT_TREE result delivery")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val kind = DirectoryPickerKind.fromRequestCode(requestCode)
        if (kind == null) {
            super.onActivityResult(requestCode, resultCode, data)
            return
        }

        val result = pendingPickerResult ?: return
        if (pendingPickerKind != kind) {
            pendingPickerResult = null
            pendingPickerKind = null
            result.error("io_error", "The directory selection state is invalid.", null)
            return
        }
        pendingPickerResult = null
        pendingPickerKind = null

        val directoryUri: Uri? = data?.data
        if (resultCode != Activity.RESULT_OK || directoryUri == null) {
            result.error("picker_cancelled", "Directory selection was cancelled.", null)
            return
        }

        when (kind) {
            DirectoryPickerKind.SAF_PROBE ->
                safExecutor.authorizeDirectory(directoryUri, data?.flags ?: 0, result)
            DirectoryPickerKind.CATALOG ->
                catalogDirectoryExecutor.authorizeCatalogDirectory(
                    directoryUri,
                    data?.flags ?: 0,
                    result,
                )
        }
    }

    private enum class DirectoryPickerKind(val requestCode: Int) {
        SAF_PROBE(7301),
        CATALOG(7302),
        ;

        companion object {
            fun fromRequestCode(value: Int): DirectoryPickerKind? =
                entries.firstOrNull { it.requestCode == value }
        }
    }

    companion object {
        private const val SAF_CHANNEL = "io.datasteward.app/saf"
        private const val CATALOG_CHANNEL = "io.datasteward.app/catalog"
        private const val SECURE_PAIRING_CHANNEL = "io.datasteward.app/secure_pairing"
        private const val LAN_DISCOVERY_CHANNEL = "io.datasteward.app/lan_discovery"
    }
}
