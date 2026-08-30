package com.tinyvpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.DatagramSocket
import kotlin.concurrent.thread

class TinyVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    // Store reference to prevent GC from closing socket.
    // Its native FD equivalent is safely decoupled into Rust context later.
    private var udpSocket: DatagramSocket? = null
    
    private var relayThread: Thread? = null

    companion object {
        init {
            System.loadLibrary("tinyvpn")
        }
    }

    private external fun startVpnSession(
        vpnFd: Int,
        udpFd: Int,
        psk: String,
        serverAddress: String
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val serverIp = intent?.getStringExtra("SERVER_IP") ?: return START_NOT_STICKY
        val pskString = intent.getStringExtra("PSK") ?: return START_NOT_STICKY
        
        thread {
            try {
                connect(serverIp, pskString)
            } catch (e: Exception) {
                Log.e("TinyVpn", "Failed to connect", e)
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun connect(serverIp: String, pskString: String) {
        val socket = DatagramSocket()
        udpSocket = socket

        // MANDATORY INVARIANT: Protect the UDP socket from routing loop issues
        if (!protect(socket)) {
            throw IllegalStateException("Cannot protect VPN UDP Socket")
        }

        val builder = Builder()
            .setSession("Tiny VPN")
            .addAddress("10.13.13.1", 24)
            
        // Unconditionally set blocking as minimum API is 29.
        builder.setBlocking(true)

        // Establish the exact Split Tunnel constraints preventing server loops on native android.
        builder.addRoute("0.0.0.0", 1)
        builder.addRoute("128.0.0.0", 1)

        val vpnPfd = builder.establish() ?: throw IllegalStateException("Cannot establish VPN")
        vpnInterface = vpnPfd

        // Duplicate datagram safely. Exclusively safe strictly from standard API 29.
        val udpPfd = ParcelFileDescriptor.fromDatagramSocket(socket)

        // Detach transferring native FD lifetimes to Rust context.
        val vpnFd = vpnPfd.detachFd()
        val udpFd = udpPfd.detachFd()

        relayThread = thread {
            startVpnSession(vpnFd, udpFd, pskString, serverIp)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Thread stops effectively as Rust context realizes the dropped streams gracefully on shutdown.
        relayThread?.interrupt()
        
        // JVM socket references cleanup
        udpSocket?.close()
        vpnInterface?.close()
    }
}
