package app.aethernext

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import java.util.concurrent.Executors

/** Quick Settings tile to inspect and toggle Aether Next without opening the app. */
class AetherTileService : TileService() {
    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "aether-tile").apply { isDaemon = true }
    }

    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        val controller = SessionController.get(this) { _, _ -> }
        val current = controller.getState().status
        if (current == "connected" || current == "connecting") {
            qsTile?.apply {
                state = Tile.STATE_UNAVAILABLE
                label = getString(R.string.app_name)
                updateTile()
            }
            worker.execute {
                controller.disconnect()
                refreshTile()
            }
            return
        }
        val settings = controller.getSettings()
        if (settings.routingMode == "tun" && VpnService.prepare(this) != null) {
            val open = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivityAndCollapse(open)
            return
        }
        qsTile?.apply {
            state = Tile.STATE_ACTIVE
            label = getString(R.string.app_name)
            updateTile()
        }
        worker.execute {
            controller.connect(settings)
            refreshTile()
        }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun refreshTile() {
        val tile = qsTile ?: return
        val status = SessionController.getOrNull()?.getState()?.status ?: "disconnected"
        tile.label = getString(R.string.app_name)
        tile.state = when (status) {
            "connected", "connecting" -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.updateTile()
    }
}
