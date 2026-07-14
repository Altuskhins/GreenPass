package com.example.combinedtunnel

import android.util.Log
import mobilebridge.Mobilebridge

class OlcRTCBridgeExample {
    private var sessionId: String? = null

    fun installCallbacks() {
        Mobilebridge.setListener(object : Mobilebridge.Listener {
            override fun onLog(sessionId: String, level: String, message: String) {
                Log.d("OlcRTC", "[$sessionId][$level] $message")
            }

            override fun onState(sessionId: String, state: String, message: String) {
                Log.i("OlcRTC", "[$sessionId] $state $message")
            }
        })
        Mobilebridge.setLogLevel("info")
    }

    fun start(configJson: String) {
        Mobilebridge.validateConfig(configJson)
        sessionId = Mobilebridge.start(configJson)
    }

    fun stop() {
        sessionId?.let { Mobilebridge.stop(it) }
        sessionId = null
    }

    fun sampleConfigJson(): String = """
        {
          "engine": "olcrtc",
          "carrier": "jitsi",
          "transport": "datachannel",
          "room_id": "room-or-room-url",
          "client_id": "client-id-matching-server",
          "key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "socks_port": 10808,
          "wait_ready_timeout_millis": 30000
        }
    """.trimIndent()
}
