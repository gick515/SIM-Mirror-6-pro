@file:Suppress("DEPRECATION", "ClickableViewAccessibility", "SetTextI18n")

package com.simmirror.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.*
import android.content.*
import android.content.pm.PackageManager
import android.graphics.*
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.media.*
import android.net.*
import android.net.wifi.WifiManager
import android.os.*
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Settings
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.telecom.TelecomManager
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.text.Editable
import android.text.TextUtils
import android.text.TextWatcher
import android.util.Base64
import android.util.TypedValue
import android.view.*
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.*
import java.net.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// =========================================================================================
// 1. GLOBAL EVENT BUS & SHARED MODELS
// =========================================================================================

data class HistoryRecord(
    val id: String,
    val category: String, // "CALL", "SMS", "ALERT", "USSD"
    val title: String,
    val numberOrPkg: String,
    val body: String,
    val timestamp: Long
)

data class ContactItem(
    val name: String,
    val number: String
)

object MirrorHubBus {
    interface UiListener {
        fun onConnectionStateChanged(state: Int, detail: String) // 0=Red, 1=Orange, 2=Green
        fun onBatteryOrSimUpdated(batteryPct: Int, isCharging: Boolean, activeSimLabel: String)
        fun onOtpCaptured(otpCode: String, fullMessage: String, sender: String)
        fun onHistoryUpdated()
        fun onHostContactsReceived(contacts: List<ContactItem>)
        fun onUssdResponseReceived(response: String)
        fun onConnectedDevicesPingResult(devices: List<String>)
        fun onAudioStreamStateChanged(isStreaming: Boolean)
        fun onToastMessage(msgEn: String, msgAr: String)
    }

    val listeners = CopyOnWriteArrayList<UiListener>()
    var currentConnectionState: Int = 0
    var currentConnectionDetail: String = "Offline"
    var hostBatteryPct: Int = 100
    var hostCharging: Boolean = false
    var activeSimInfo: String = "SIM 1"
    var lastOtpCode: String = ""
    var lastOtpFullSms: String = ""
    var lastOtpSender: String = ""
    var lastUssdResult: String = ""
    var isAudioRelayActive: Boolean = false
    val cachedHostContacts = CopyOnWriteArrayList<ContactItem>()
    val connectedPeers = ConcurrentHashMap<String, Long>()

    private val mainHandler = Handler(Looper.getMainLooper())

    fun notifyConnection(state: Int, detail: String) {
        currentConnectionState = state
        currentConnectionDetail = detail
        mainHandler.post { listeners.forEach { it.onConnectionStateChanged(state, detail) } }
    }

    fun notifyBatterySim(pct: Int, charging: Boolean, sim: String) {
        hostBatteryPct = pct
        hostCharging = charging
        activeSimInfo = sim
        mainHandler.post { listeners.forEach { it.onBatteryOrSimUpdated(pct, charging, sim) } }
    }

    fun notifyOtp(code: String, full: String, sender: String) {
        lastOtpCode = code
        lastOtpFullSms = full
        lastOtpSender = sender
        mainHandler.post { listeners.forEach { it.onOtpCaptured(code, full, sender) } }
    }

    fun notifyHistory() {
        mainHandler.post { listeners.forEach { it.onHistoryUpdated() } }
    }

    fun notifyHostContacts(list: List<ContactItem>) {
        cachedHostContacts.clear()
        cachedHostContacts.addAll(list)
        mainHandler.post { listeners.forEach { it.onHostContactsReceived(list) } }
    }

    fun notifyUssd(resp: String) {
        lastUssdResult = resp
        mainHandler.post { listeners.forEach { it.onUssdResponseReceived(resp) } }
    }

    fun notifyPingDevices(devices: List<String>) {
        mainHandler.post { listeners.forEach { it.onConnectedDevicesPingResult(devices) } }
    }

    fun notifyAudioStream(active: Boolean) {
        isAudioRelayActive = active
        mainHandler.post { listeners.forEach { it.onAudioStreamStateChanged(active) } }
    }

    fun postToast(en: String, ar: String) {
        mainHandler.post { listeners.forEach { it.onToastMessage(en, ar) } }
    }
}

// =========================================================================================
// 2. AES-256 ENCRYPTION & OTP REGEX ENGINE
// =========================================================================================

object CryptoAndParserEngine {
    fun deriveRoomTopic(rawRoomCode: String): String {
        val clean = rawRoomCode.trim().ifEmpty { "default_sim_hub_v6" }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(("sim_mirror_v6_topic_$clean").toByteArray(StandardCharsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }.take(24)
        return "smh6_$hex"
    }

    private fun deriveAesKey(pin: String): SecretKeySpec {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(("sim_mirror_aes_v6_$pin").toByteArray(StandardCharsets.UTF_8))
        return SecretKeySpec(digest, "AES")
    }

    fun encryptPayload(plainJson: String, pin: String): String {
        if (pin.isBlank()) return plainJson
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val iv = ByteArray(16)
            Random().nextBytes(iv)
            cipher.init(Cipher.ENCRYPT_MODE, deriveAesKey(pin.trim()), IvParameterSpec(iv))
            val encrypted = cipher.doFinal(plainJson.toByteArray(StandardCharsets.UTF_8))
            val combined = iv + encrypted
            "ENCv6:" + Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            plainJson
        }
    }

    fun decryptPayload(wireData: String, pin: String): String {
        if (!wireData.startsWith("ENCv6:")) return wireData
        if (pin.isBlank()) return ""
        return try {
            val raw = Base64.decode(wireData.removePrefix("ENCv6:"), Base64.NO_WRAP)
            if (raw.size <= 16) return ""
            val iv = raw.copyOfRange(0, 16)
            val cipherBytes = raw.copyOfRange(16, raw.size)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, deriveAesKey(pin.trim()), IvParameterSpec(iv))
            String(cipher.doFinal(cipherBytes), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            ""
        }
    }

    fun extractOtpOrDigits(text: String): String {
        val otpRegex = Regex("\\b(\\d{4,8})\\b")
        val match = otpRegex.find(text)
        if (match != null) return match.groupValues[1]
        val anyDigits = Regex("\\d+").findAll(text).map { it.value }.joinToString("")
        return anyDigits
    }
}

// =========================================================================================
// 3. PERSISTENT STORAGE & PROTECTED HISTORY ENGINE (KEEP LAST 15 RULE)
// =========================================================================================

object StorageEngine {
    private const val PREFS_NAME = "sim_mirror_v6_prefs"
    private const val KEY_HISTORY = "permanent_history_v6"

    fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isArabic(ctx: Context): Boolean = prefs(ctx).getBoolean("lang_ar", false)
    fun setArabic(ctx: Context, ar: Boolean) = prefs(ctx).edit().putBoolean("lang_ar", ar).apply()

    fun isDarkTheme(ctx: Context): Boolean = prefs(ctx).getBoolean("theme_dark", true)
    fun setDarkTheme(ctx: Context, dark: Boolean) = prefs(ctx).edit().putBoolean("theme_dark", dark).apply()

    fun isHostMode(ctx: Context): Boolean = prefs(ctx).getBoolean("is_host_mode", true)
    fun setHostMode(ctx: Context, host: Boolean) = prefs(ctx).edit().putBoolean("is_host_mode", host).apply()

    fun getRoomCode(ctx: Context): String = prefs(ctx).getString("room_code", "ULTRA-SIM-7700") ?: "ULTRA-SIM-7700"
    fun setRoomCode(ctx: Context, code: String) = prefs(ctx).edit().putString("room_code", code.trim()).apply()

    fun getEncryptionPin(ctx: Context): String = prefs(ctx).getString("enc_pin", "") ?: ""
    fun setEncryptionPin(ctx: Context, pin: String) = prefs(ctx).edit().putString("enc_pin", pin.trim()).apply()

    fun getManualIp(ctx: Context): String = prefs(ctx).getString("manual_ip", "") ?: ""
    fun setManualIp(ctx: Context, ip: String) = prefs(ctx).edit().putString("manual_ip", ip.trim()).apply()

    fun getSelectedSimSlot(ctx: Context): Int = prefs(ctx).getInt("selected_sim_slot", 0) // 0=SIM1, 1=SIM2
    fun setSelectedSimSlot(ctx: Context, slot: Int) = prefs(ctx).edit().putInt("selected_sim_slot", slot).apply()

    fun getTargetNumber(ctx: Context): String = prefs(ctx).getString("shared_target_number", "") ?: ""
    fun setTargetNumber(ctx: Context, num: String) = prefs(ctx).edit().putString("shared_target_number", num).apply()

    @Synchronized
    fun loadHistory(ctx: Context): MutableList<HistoryRecord> {
        val raw = prefs(ctx).getString(KEY_HISTORY, "[]") ?: "[]"
        val list = mutableListOf<HistoryRecord>()
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(
                    HistoryRecord(
                        id = o.optString("id"),
                        category = o.optString("category", "SMS"),
                        title = o.optString("title", ""),
                        numberOrPkg = o.optString("numberOrPkg", ""),
                        body = o.optString("body", ""),
                        timestamp = o.optLong("timestamp", System.currentTimeMillis())
                    )
                )
            }
        } catch (_: Exception) {}
        list.sortByDescending { it.timestamp }
        return list
    }

    @Synchronized
    private fun saveHistoryList(ctx: Context, list: List<HistoryRecord>) {
        val arr = JSONArray()
        list.sortedByDescending { it.timestamp }.take(600).forEach { item ->
            val o = JSONObject()
            o.put("id", item.id)
            o.put("category", item.category)
            o.put("title", item.title)
            o.put("numberOrPkg", item.numberOrPkg)
            o.put("body", item.body)
            o.put("timestamp", item.timestamp)
            arr.put(o)
        }
        prefs(ctx).edit().putString(KEY_HISTORY, arr.toString()).apply()
    }

    @Synchronized
    fun addHistoryRecord(ctx: Context, record: HistoryRecord): Boolean {
        val current = loadHistory(ctx)
        val exists = current.any {
            it.id == record.id || (it.category == record.category &&
                it.numberOrPkg == record.numberOrPkg &&
                it.body == record.body &&
                Math.abs(it.timestamp - record.timestamp) < 3500L)
        }
        if (exists) return false
        current.add(0, record)
        saveHistoryList(ctx, current)
        MirrorHubBus.notifyHistory()
        return true
    }

    @Synchronized
    fun addHistoryBatch(ctx: Context, records: List<HistoryRecord>) {
        val current = loadHistory(ctx)
        var changed = false
        for (record in records) {
            val exists = current.any {
                it.id == record.id || (it.category == record.category &&
                    it.numberOrPkg == record.numberOrPkg &&
                    it.body == record.body &&
                    Math.abs(it.timestamp - record.timestamp) < 5000L)
            }
            if (!exists) {
                current.add(record)
                changed = true
            }
        }
        if (changed) {
            current.sortByDescending { it.timestamp }
            saveHistoryList(ctx, current)
            MirrorHubBus.notifyHistory()
        }
    }

    // Protected Deletion Rule: Never allow deleting if total <= 15
    @Synchronized
    fun deleteSingleRecordProtected(ctx: Context, recordId: String): Boolean {
        val current = loadHistory(ctx)
        if (current.size <= 15) {
            return false
        }
        val removed = current.removeAll { it.id == recordId }
        if (removed) {
            saveHistoryList(ctx, current)
            MirrorHubBus.notifyHistory()
        }
        return removed
    }

    // Clear All but strictly keep the latest 15 items
    @Synchronized
    fun clearAllKeepLast15(ctx: Context): Int {
        val current = loadHistory(ctx).sortedByDescending { it.timestamp }
        if (current.size <= 15) return 0
        val removedCount = current.size - 15
        val kept = current.take(15)
        saveHistoryList(ctx, kept)
        MirrorHubBus.notifyHistory()
        return removedCount
    }
}

// =========================================================================================
// 4. PERSISTENT 24/7 BACKGROUND SERVICE (CLOUD + LAN + TELEPHONY + SPEAKER FIX + OVERLAY)
// =========================================================================================

class MirrorBackgroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "sim_mirror_v6_channel"
        private const val NOTIF_ID = 6001
        const val TCP_PORT = 49660
        const val UDP_DISCOVERY_PORT = 49661
        const val UDP_AUDIO_PORT = 49662

        @Volatile
        var instance: MirrorBackgroundService? = null

        fun startOrEnsureRunning(context: Context) {
            val intent = Intent(context.applicationContext, MirrorBackgroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.applicationContext.startForegroundService(intent)
            } else {
                context.applicationContext.startService(intent)
            }
        }
    }

    private val executor = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val isServiceAlive = AtomicBoolean(false)
    private val cloudReconnectTrigger = AtomicBoolean(false)
    private val processedPacketIds = Collections.synchronizedSet(LinkedHashSet<String>())

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var activeCloudConnection: HttpURLConnection? = null
    private var tcpServerSocket: ServerSocket? = null
    private var udpDiscoverySocket: DatagramSocket? = null

    private val isAudioStreaming = AtomicBoolean(false)
    private var audioSocket: DatagramSocket? = null
    private var alarmRingtone: Ringtone? = null
    private var floatingBannerView: View? = null

    private val deviceName: String
        get() = "${Build.MANUFACTURER.uppercase()} ${Build.MODEL}"

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            triggerCloudReconnect()
            broadcastBatteryAndSimStatus()
        }

        override fun onLost(network: Network) {
            MirrorHubBus.notifyConnection(1, "Reconnecting...")
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        isServiceAlive.set(true)
        acquirePowerAndWifiLocks()
        startForegroundNotification("SIM Mirror Hub v6.0 Active 24/7")
        registerNetworkMonitor()
        startCloudStreamLoop()
        startLocalTcpServerLoop()
        startUdpDiscoveryLoop()
        startPeriodicHeartbeatLoop()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.getStringExtra("SERVICE_ACTION")
        if (action == "RECONNECT_NOW") {
            triggerCloudReconnect()
        } else if (action == "INCOMING_CALL_EVENT") {
            val number = intent.getStringExtra("CALL_NUMBER") ?: "Unknown"
            val state = intent.getStringExtra("CALL_STATE") ?: ""
            handleHostCallStateChange(state, number)
        } else if (action == "INCOMING_SMS_EVENT") {
            val sender = intent.getStringExtra("SMS_SENDER") ?: "Unknown"
            val body = intent.getStringExtra("SMS_BODY") ?: ""
            handleHostIncomingSms(sender, body)
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isServiceAlive.set(false)
        stopLiveAudioRelay()
        dismissFloatingCallBanner()
        try { activeCloudConnection?.disconnect() } catch (_: Exception) {}
        try { tcpServerSocket?.close() } catch (_: Exception) {}
        try { udpDiscoverySocket?.close() } catch (_: Exception) {}
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {}
        releaseLocks()
        instance = null
        super.onDestroy()
    }

    private fun acquirePowerAndWifiLocks() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SIMMirrorHub::CoreWakeLock").apply {
                setReferenceCounted(false)
                acquire()
            }
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "SIMMirrorHub::CoreWifiLock").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (_: Exception) {}
    }

    private fun releaseLocks() {
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Exception) {}
    }

    private fun startForegroundNotification(statusText: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SIM Mirror Hub 24/7 Engine",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps SIM Mirror Hub connected in background"
                setShowBadge(false)
            }
            nm.createNotificationChannel(channel)
        }
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val pendingIntent = PendingIntent.getActivity(this, 0, openIntent, pendingFlags)
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("SIM Mirror Hub v6.0 Ultra-Pro")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.stat_sys_phone_call)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notification)
    }

    private fun registerNetworkMonitor() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.registerDefaultNetworkCallback(networkCallback)
        } catch (_: Exception) {}
    }

    fun triggerCloudReconnect() {
        cloudReconnectTrigger.set(true)
        executor.execute {
            try { activeCloudConnection?.disconnect() } catch (_: Exception) {}
        }
    }

    // -------------------------------------------------------------------------------------
    // CLOUD STREAM ENGINE (NTFY JSON STREAM + PACKET DEDUPLICATION)
    // -------------------------------------------------------------------------------------

    private fun startCloudStreamLoop() {
        executor.execute {
            while (isServiceAlive.get()) {
                cloudReconnectTrigger.set(false)
                val roomCode = StorageEngine.getRoomCode(this)
                val topic = CryptoAndParserEngine.deriveRoomTopic(roomCode)
                MirrorHubBus.notifyConnection(1, "Connecting Cloud ($roomCode)...")
                var reader: BufferedReader? = null
                try {
                    val url = URL("https://ntfy.sh/$topic/json")
                    val conn = (url.openConnection() as HttpURLConnection).apply {
                        requestMethod = "GET"
                        connectTimeout = 12000
                        readTimeout = 0 // Infinite stream read timeout for persistent connection
                        setRequestProperty("Accept", "application/x-ndjson")
                        setRequestProperty("Cache-Control", "no-cache")
                    }
                    activeCloudConnection = conn
                    val code = conn.responseCode
                    if (code == 200) {
                        MirrorHubBus.notifyConnection(2, "Cloud Active ($roomCode)")
                        sendPacket("PING_ANNOUNCE", JSONObject().apply {
                            put("device", deviceName)
                            put("role", if (StorageEngine.isHostMode(this@MirrorBackgroundService)) "HOST" else "REMOTE")
                        })
                        reader = BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8))
                        var line: String?
                        while (isServiceAlive.get() && !cloudReconnectTrigger.get()) {
                            line = reader.readLine() ?: break
                            handleRawNtfyLine(line)
                        }
                    } else {
                        MirrorHubBus.notifyConnection(0, "Cloud HTTP $code")
                    }
                } catch (e: Exception) {
                    if (!cloudReconnectTrigger.get()) {
                        MirrorHubBus.notifyConnection(0, "Offline / Retrying...")
                    }
                } finally {
                    try { reader?.close() } catch (_: Exception) {}
                    try { activeCloudConnection?.disconnect() } catch (_: Exception) {}
                }
                if (isServiceAlive.get() && !cloudReconnectTrigger.get()) {
                    try { Thread.sleep(2500) } catch (_: Exception) {}
                }
            }
        }
    }

    private fun handleRawNtfyLine(line: String) {
        if (line.isBlank()) return
        try {
            val outer = JSONObject(line)
            val eventType = outer.optString("event", "")
            if (eventType != "message") return
            val rawMessage = outer.optString("message", "")
            if (rawMessage.isBlank()) return
            processIncomingWireMessage(rawMessage)
        } catch (_: Exception) {}
    }

    // -------------------------------------------------------------------------------------
    // LOCAL TCP SERVER & UDP AUTO-DISCOVERY ENGINE
    // -------------------------------------------------------------------------------------

    private fun startLocalTcpServerLoop() {
        executor.execute {
            while (isServiceAlive.get()) {
                try {
                    tcpServerSocket = ServerSocket(TCP_PORT)
                    while (isServiceAlive.get()) {
                        val client = tcpServerSocket?.accept() ?: break
                        executor.execute {
                            try {
                                client.soTimeout = 8000
                                val reader = BufferedReader(InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8))
                                val line = reader.readLine()
                                if (!line.isNullOrBlank()) {
                                    val senderIp = client.inetAddress?.hostAddress ?: ""
                                    if (senderIp.isNotEmpty() && StorageEngine.getManualIp(this).isEmpty()) {
                                        StorageEngine.setManualIp(this, senderIp)
                                    }
                                    MirrorHubBus.notifyConnection(2, "LAN Connected ($senderIp)")
                                    processIncomingWireMessage(line)
                                }
                                client.close()
                            } catch (_: Exception) {}
                        }
                    }
                } catch (_: Exception) {
                    try { Thread.sleep(3000) } catch (_: Exception) {}
                }
            }
        }
    }

    private fun startUdpDiscoveryLoop() {
        executor.execute {
            while (isServiceAlive.get()) {
                try {
                    udpDiscoverySocket = DatagramSocket(null).apply {
                        reuseAddress = true
                        bind(InetSocketAddress(UDP_DISCOVERY_PORT))
                    }
                    val buf = ByteArray(1024)
                    while (isServiceAlive.get()) {
                        val pkt = DatagramPacket(buf, buf.size)
                        udpDiscoverySocket?.receive(pkt) ?: break
                        val msg = String(pkt.data, 0, pkt.length, StandardCharsets.UTF_8)
                        val peerIp = pkt.address.hostAddress ?: continue
                        if (peerIp == getLocalWifiIp()) continue
                        if (msg.startsWith("SMH6_DISCOVER:")) {
                            val reply = "SMH6_HERE:${deviceName}:${if (StorageEngine.isHostMode(this)) "HOST" else "REMOTE"}"
                            val replyBytes = reply.toByteArray(StandardCharsets.UTF_8)
                            udpDiscoverySocket?.send(DatagramPacket(replyBytes, replyBytes.size, pkt.address, UDP_DISCOVERY_PORT))
                            StorageEngine.setManualIp(this, peerIp)
                            MirrorHubBus.notifyConnection(2, "LAN Peer: $peerIp")
                        } else if (msg.startsWith("SMH6_HERE:")) {
                            StorageEngine.setManualIp(this, peerIp)
                            MirrorHubBus.notifyConnection(2, "Found Peer: $peerIp")
                            MirrorHubBus.postToast("LAN Peer Discovered: $peerIp", "تم اكتشاف جهاز محلي: $peerIp")
                        }
                    }
                } catch (_: Exception) {
                    try { Thread.sleep(3000) } catch (_: Exception) {}
                }
            }
        }
    }

    fun sendUdpBroadcastDiscovery() {
        executor.execute {
            try {
                val socket = DatagramSocket().apply { broadcast = true }
                val payload = "SMH6_DISCOVER:$deviceName".toByteArray(StandardCharsets.UTF_8)
                val broadcastAddr = InetAddress.getByName("255.255.255.255")
                socket.send(DatagramPacket(payload, payload.size, broadcastAddr, UDP_DISCOVERY_PORT))
                socket.close()
                MirrorHubBus.postToast("UDP Broadcast sent on LAN/Hotspot", "تم إرسال بحث تلقائي على الشبكة المحلية")
            } catch (_: Exception) {}
        }
    }

    private fun getLocalWifiIp(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val intf = interfaces.nextElement()
                val addrs = intf.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        return addr.hostAddress ?: ""
                    }
                }
            }
        } catch (_: Exception) {}
        return ""
    }

    // -------------------------------------------------------------------------------------
    // UNIFIED PACKET SENDER & DEDUPLICATED RECEIVER
    // -------------------------------------------------------------------------------------

    fun sendPacket(command: String, data: JSONObject = JSONObject()) {
        executor.execute {
            val pktId = UUID.randomUUID().toString().take(12)
            processedPacketIds.add(pktId)
            val envelope = JSONObject().apply {
                put("pktId", pktId)
                put("cmd", command)
                put("sender", deviceName)
                put("role", if (StorageEngine.isHostMode(this@MirrorBackgroundService)) "HOST" else "REMOTE")
                put("ts", System.currentTimeMillis())
                put("data", data)
            }
            val pin = StorageEngine.getEncryptionPin(this)
            val wirePayload = CryptoAndParserEngine.encryptPayload(envelope.toString(), pin)

            // 1. Send via Local LAN TCP if peer IP is configured
            val targetIp = StorageEngine.getManualIp(this)
            if (targetIp.isNotBlank()) {
                executor.execute {
                    try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(targetIp, TCP_PORT), 2500)
                            val out = BufferedWriter(OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8))
                            out.write(wirePayload)
                            out.newLine()
                            out.flush()
                        }
                    } catch (_: Exception) {}
                }
            }

            // 2. Send via Cloud Stream (Ntfy HTTPS POST)
            try {
                val topic = CryptoAndParserEngine.deriveRoomTopic(StorageEngine.getRoomCode(this))
                val url = URL("https://ntfy.sh/$topic")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    connectTimeout = 8000
                    readTimeout = 8000
                    setRequestProperty("Content-Type", "text/plain; charset=utf-8")
                }
                conn.outputStream.use { os ->
                    os.write(wirePayload.toByteArray(StandardCharsets.UTF_8))
                    os.flush()
                }
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) {}
        }
    }

    private fun processIncomingWireMessage(wirePayload: String) {
        val pin = StorageEngine.getEncryptionPin(this)
        val decrypted = CryptoAndParserEngine.decryptPayload(wirePayload, pin)
        if (decrypted.isBlank()) return
        try {
            val env = JSONObject(decrypted)
            val pktId = env.optString("pktId", "")
            if (pktId.isNotEmpty()) {
                if (processedPacketIds.contains(pktId)) return
                processedPacketIds.add(pktId)
                if (processedPacketIds.size > 500) {
                    val it = processedPacketIds.iterator()
                    if (it.hasNext()) {
                        it.next()
                        it.remove()
                    }
                }
            }
            val cmd = env.optString("cmd", "")
            val sender = env.optString("sender", "Peer")
            val role = env.optString("role", "")
            val data = env.optJSONObject("data") ?: JSONObject()

            MirrorHubBus.connectedPeers["$sender ($role)"] = System.currentTimeMillis()
            dispatchCommand(cmd, sender, data)
        } catch (_: Exception) {}
    }

    // -------------------------------------------------------------------------------------
    // COMMAND DISPATCHER (HOST & REMOTE EXECUTION)
    // -------------------------------------------------------------------------------------

    private fun dispatchCommand(cmd: String, sender: String, data: JSONObject) {
        val isHost = StorageEngine.isHostMode(this)
        when (cmd) {
            "PING_ANNOUNCE" -> {
                sendPacket("PING_REPLY", JSONObject().apply {
                    put("device", deviceName)
                    put("battery", getLocalBatteryPct())
                    put("charging", isLocalCharging())
                    put("sim", getLocalActiveSimSummary())
                })
            }
            "PING_REPLY" -> {
                val bat = data.optInt("battery", 100)
                val chg = data.optBoolean("charging", false)
                val sim = data.optString("sim", "SIM 1")
                MirrorHubBus.notifyBatterySim(bat, chg, sim)
                val peers = MirrorHubBus.connectedPeers.keys.toList()
                MirrorHubBus.notifyPingDevices(peers)
            }
            "FIND_HOST_ALARM" -> {
                if (isHost) triggerFindPhoneAlarm()
            }
            // ---------------- CALL COMMANDS ----------------
            "DIAL_CALL" -> {
                if (isHost) {
                    val number = data.optString("number", "")
                    val simSlot = data.optInt("simSlot", 0)
                    val forceSpk = data.optBoolean("speaker", true)
                    placeCallOnHost(number, simSlot, forceSpk)
                }
            }
            "ANSWER_CALL" -> {
                if (isHost) {
                    val forceSpk = data.optBoolean("speaker", true)
                    answerRingingCallWithSpeakerFix(forceSpk)
                }
            }
            "TOGGLE_SPEAKER" -> {
                if (isHost) {
                    toggleHostSpeakerphone()
                }
            }
            "END_CALL" -> {
                if (isHost) {
                    endOrRejectCallOnHost()
                }
                mainHandler.post { dismissFloatingCallBanner() }
            }
            "REJECT_WITH_SMS" -> {
                if (isHost) {
                    val number = data.optString("number", "")
                    val msg = data.optString("message", "I am currently busy, will call you back shortly.")
                    endOrRejectCallOnHost()
                    if (number.isNotBlank()) {
                        sendSmsOnHost(number, msg, StorageEngine.getSelectedSimSlot(this))
                    }
                }
                mainHandler.post { dismissFloatingCallBanner() }
            }
            "SEND_DTMF" -> {
                if (isHost) {
                    val digit = data.optString("digit", "")
                    playLocalDtmfTone(digit)
                }
            }
            // ---------------- CALL LOG SYNC FIX (CRITICAL FIX #2) ----------------
            "SYNC_CALL_LOG" -> {
                if (isHost) {
                    val logsArray = readHostCallLogsJson()
                    sendPacket("CALL_LOG_DATA", JSONObject().apply {
                        put("logs", logsArray)
                    })
                }
            }
            "CALL_LOG_DATA" -> {
                val logsArray = data.optJSONArray("logs") ?: JSONArray()
                val records = mutableListOf<HistoryRecord>()
                for (i in 0 until logsArray.length()) {
                    val o = logsArray.getJSONObject(i)
                    records.add(
                        HistoryRecord(
                            id = o.optString("id"),
                            category = "CALL",
                            title = o.optString("title"),
                            numberOrPkg = o.optString("number"),
                            body = o.optString("body"),
                            timestamp = o.optLong("ts")
                        )
                    )
                }
                StorageEngine.addHistoryBatch(this, records)
                MirrorHubBus.postToast(
                    "Synced ${records.size} Call Logs from Host",
                    "تم جلب ${records.size} سجل مكالمات من الهاتف الأساسي"
                )
            }
            // ---------------- CONTACTS SYNC FIX (CRITICAL FIX #3) ----------------
            "SYNC_CONTACTS" -> {
                if (isHost) {
                    val contactsArray = readHostContactsJson()
                    sendPacket("CONTACTS_DATA", JSONObject().apply {
                        put("contacts", contactsArray)
                    })
                }
            }
            "CONTACTS_DATA" -> {
                val arr = data.optJSONArray("contacts") ?: JSONArray()
                val list = mutableListOf<ContactItem>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(ContactItem(o.optString("name"), o.optString("number")))
                }
                MirrorHubBus.notifyHostContacts(list)
            }
            // ---------------- SMS & USSD COMMANDS ----------------
            "SEND_SMS" -> {
                if (isHost) {
                    val number = data.optString("number", "")
                    val body = data.optString("body", "")
                    val simSlot = data.optInt("simSlot", 0)
                    sendSmsOnHost(number, body, simSlot)
                }
            }
            "SYNC_SMS_INBOX" -> {
                if (isHost) {
                    val smsArray = readHostSmsInboxJson()
                    sendPacket("SMS_INBOX_DATA", JSONObject().apply {
                        put("messages", smsArray)
                    })
                }
            }
            "SMS_INBOX_DATA" -> {
                val arr = data.optJSONArray("messages") ?: JSONArray()
                val records = mutableListOf<HistoryRecord>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val senderNum = o.optString("sender")
                    val bodyText = o.optString("body")
                    val ts = o.optLong("ts")
                    records.add(
                        HistoryRecord(
                            id = o.optString("id"),
                            category = "SMS",
                            title = "SMS: $senderNum",
                            numberOrPkg = senderNum,
                            body = bodyText,
                            timestamp = ts
                        )
                    )
                    if (i == 0) {
                        val otp = CryptoAndParserEngine.extractOtpOrDigits(bodyText)
                        if (otp.length in 4..8) {
                            MirrorHubBus.notifyOtp(otp, bodyText, senderNum)
                        }
                    }
                }
                StorageEngine.addHistoryBatch(this, records)
                MirrorHubBus.postToast(
                    "Synced ${records.size} SMS messages from Host",
                    "تم جلب ${records.size} رسالة نصية من الهاتف الأساسي"
                )
            }
            "RUN_USSD" -> {
                if (isHost) {
                    val code = data.optString("code", "*100#")
                    val simSlot = data.optInt("simSlot", 0)
                    executeUssdOnHost(code, simSlot)
                }
            }
            "USSD_RESULT" -> {
                val resp = data.optString("response", "")
                val code = data.optString("code", "USSD")
                StorageEngine.addHistoryRecord(
                    this,
                    HistoryRecord(
                        id = "ussd_${System.currentTimeMillis()}",
                        category = "USSD",
                        title = "USSD ($code)",
                        numberOrPkg = code,
                        body = resp,
                        timestamp = System.currentTimeMillis()
                    )
                )
                MirrorHubBus.notifyUssd(resp)
            }
            // ---------------- REAL-TIME EVENTS FROM HOST TO REMOTE ----------------
            "HOST_CALL_ALERT" -> {
                val state = data.optString("state", "")
                val number = data.optString("number", "Unknown")
                val name = data.optString("name", number)
                StorageEngine.addHistoryRecord(
                    this,
                    HistoryRecord(
                        id = "call_live_${System.currentTimeMillis()}",
                        category = "CALL",
                        title = "Call ($state): $name",
                        numberOrPkg = number,
                        body = "Incoming/Active Call State: $state ($number)",
                        timestamp = System.currentTimeMillis()
                    )
                )
                if (!isHost) {
                    if (state == "RINGING") {
                        mainHandler.post { showFloatingIncomingCallBanner(name, number) }
                    } else if (state == "IDLE") {
                        mainHandler.post { dismissFloatingCallBanner() }
                    }
                }
            }
            "HOST_SMS_ALERT" -> {
                val senderNum = data.optString("sender", "Unknown")
                val bodyText = data.optString("body", "")
                StorageEngine.addHistoryRecord(
                    this,
                    HistoryRecord(
                        id = "sms_live_${System.currentTimeMillis()}",
                        category = "SMS",
                        title = "SMS: $senderNum",
                        numberOrPkg = senderNum,
                        body = bodyText,
                        timestamp = System.currentTimeMillis()
                    )
                )
                val otp = CryptoAndParserEngine.extractOtpOrDigits(bodyText)
                if (otp.length in 4..8) {
                    copyToClipboardInternal("OTP", otp)
                    MirrorHubBus.notifyOtp(otp, bodyText, senderNum)
                }
            }
            "HOST_APP_NOTIFICATION" -> {
                val pkg = data.optString("pkg", "App")
                val appTitle = data.optString("title", "")
                val text = data.optString("text", "")
                StorageEngine.addHistoryRecord(
                    this,
                    HistoryRecord(
                        id = "alert_${System.currentTimeMillis()}_${pkg.hashCode()}",
                        category = "ALERT",
                        title = "$pkg: $appTitle",
                        numberOrPkg = pkg,
                        body = text,
                        timestamp = System.currentTimeMillis()
                    )
                )
                val otp = CryptoAndParserEngine.extractOtpOrDigits(text)
                if (otp.length in 4..8) {
                    MirrorHubBus.notifyOtp(otp, text, pkg)
                }
            }
            "SYNC_RECENT_ALERTS" -> {
                if (isHost) {
                    val existing = StorageEngine.loadHistory(this).filter { it.category == "ALERT" }.take(40)
                    val arr = JSONArray()
                    existing.forEach { r ->
                        arr.put(JSONObject().apply {
                            put("id", r.id)
                            put("title", r.title)
                            put("pkg", r.numberOrPkg)
                            put("body", r.body)
                            put("ts", r.timestamp)
                        })
                    }
                    sendPacket("RECENT_ALERTS_DATA", JSONObject().apply { put("alerts", arr) })
                }
            }
            "RECENT_ALERTS_DATA" -> {
                val arr = data.optJSONArray("alerts") ?: JSONArray()
                val list = mutableListOf<HistoryRecord>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(
                        HistoryRecord(
                            id = o.optString("id"),
                            category = "ALERT",
                            title = o.optString("title"),
                            numberOrPkg = o.optString("pkg"),
                            body = o.optString("body"),
                            timestamp = o.optLong("ts")
                        )
                    )
                }
                StorageEngine.addHistoryBatch(this, list)
                MirrorHubBus.postToast("Synced ${list.size} App Notifications", "تم جلب ${list.size} إشعار تطبيق")
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // SPEAKERPHONE TRIPLE-STAGE FIX & TELEPHONY ACTIONS (CRITICAL FIX #4)
    // -------------------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    fun answerRingingCallWithSpeakerFix(enableSpeaker: Boolean) {
        try {
            val tm = getSystemService(Context.TELECOM_SERVICE) as TelecomManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                tm.acceptRingingCall()
            }
        } catch (_: Exception) {}

        if (enableSpeaker) {
            // Triple-stage speakerphone enforcement: 500ms, 1200ms, 2500ms
            val delays = longArrayOf(500L, 1200L, 2500L)
            for (delayMs in delays) {
                mainHandler.postDelayed({
                    forceEnableSpeakerphoneHardware()
                }, delayMs)
            }
        }
        MirrorHubBus.postToast("Answered Call + Speakerphone Forced", "تم الرد على المكالمة وتفعيل السبيكر الخارجي")
    }

    fun forceEnableSpeakerphoneHardware() {
        try {
            val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            audioManager.mode = AudioManager.MODE_IN_CALL

            // Boost Voice Call Volume to Max
            val maxVol = audioManager.getStreamMaxVolume(AudioManager.STREAM_VOICE_CALL)
            audioManager.setStreamVolume(AudioManager.STREAM_VOICE_CALL, maxVol, 0)

            // API 31+ Modern Communication Device Routing
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val devices = audioManager.availableCommunicationDevices
                val speakerDevice = devices.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                if (speakerDevice != null) {
                    audioManager.setCommunicationDevice(speakerDevice)
                }
            }
            // Legacy & Universal Fallback
            audioManager.isSpeakerphoneOn = true
        } catch (_: Exception) {}
    }

    fun toggleHostSpeakerphone() {
        try {
            val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            val currentlyOn = audioManager.isSpeakerphoneOn
            if (!currentlyOn) {
                forceEnableSpeakerphoneHardware()
                MirrorHubBus.postToast("Speakerphone Enabled (ON)", "تم تشغيل السماعة الخارجية (Speaker ON)")
            } else {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    audioManager.clearCommunicationDevice()
                }
                audioManager.isSpeakerphoneOn = false
                MirrorHubBus.postToast("Speakerphone Disabled (Earpiece)", "تم إيقاف السبيكر وتحويل الصوت للسماعة الداخلية")
            }
        } catch (_: Exception) {}
    }

    @SuppressLint("MissingPermission")
    fun placeCallOnHost(number: String, simSlot: Int, forceSpeaker: Boolean) {
        if (number.isBlank()) return
        try {
            val uri = Uri.fromParts("tel", number.trim(), null)
            val callIntent = Intent(Intent.ACTION_CALL, uri).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("com.android.phone.force.slot", true)
                putExtra("com.android.phone.extra.slot", simSlot)
                putExtra("slot", simSlot)
            }
            startActivity(callIntent)
            if (forceSpeaker) {
                mainHandler.postDelayed({ forceEnableSpeakerphoneHardware() }, 1000L)
                mainHandler.postDelayed({ forceEnableSpeakerphoneHardware() }, 2500L)
            }
            StorageEngine.addHistoryRecord(
                this,
                HistoryRecord(
                    id = "dial_${System.currentTimeMillis()}",
                    category = "CALL",
                    title = "Outgoing Call (SIM ${simSlot + 1})",
                    numberOrPkg = number,
                    body = "Dialed $number on SIM ${simSlot + 1}",
                    timestamp = System.currentTimeMillis()
                )
            )
        } catch (e: Exception) {
            MirrorHubBus.postToast("Call Error: ${e.message}", "خطأ في الاتصال: ${e.message}")
        }
    }

    @SuppressLint("MissingPermission")
    fun endOrRejectCallOnHost() {
        try {
            val tm = getSystemService(Context.TELECOM_SERVICE) as TelecomManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                tm.endCall()
            }
            val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                audioManager.clearCommunicationDevice()
            }
            audioManager.isSpeakerphoneOn = false
            audioManager.mode = AudioManager.MODE_NORMAL
            MirrorHubBus.postToast("Call Ended / Rejected", "تم إنهاء / رفض المكالمة")
        } catch (_: Exception) {}
    }

    private fun playLocalDtmfTone(digit: String) {
        try {
            val toneType = when (digit) {
                "0" -> ToneGenerator.TONE_DTMF_0
                "1" -> ToneGenerator.TONE_DTMF_1
                "2" -> ToneGenerator.TONE_DTMF_2
                "3" -> ToneGenerator.TONE_DTMF_3
                "4" -> ToneGenerator.TONE_DTMF_4
                "5" -> ToneGenerator.TONE_DTMF_5
                "6" -> ToneGenerator.TONE_DTMF_6
                "7" -> ToneGenerator.TONE_DTMF_7
                "8" -> ToneGenerator.TONE_DTMF_8
                "9" -> ToneGenerator.TONE_DTMF_9
                "*" -> ToneGenerator.TONE_DTMF_S
                "#" -> ToneGenerator.TONE_DTMF_P
                else -> ToneGenerator.TONE_DTMF_1
            }
            val tg = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 95)
            tg.startTone(toneType, 220)
            mainHandler.postDelayed({ tg.release() }, 300L)
        } catch (_: Exception) {}
    }

    // -------------------------------------------------------------------------------------
    // HOST CALL LOGS, CONTACTS, SMS & USSD READERS
    // -------------------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    fun readHostCallLogsJson(): JSONArray {
        val arr = JSONArray()
        try {
            val cursor = contentResolver.query(
                CallLog.Calls.CONTENT_URI,
                arrayOf(
                    CallLog.Calls._ID,
                    CallLog.Calls.NUMBER,
                    CallLog.Calls.CACHED_NAME,
                    CallLog.Calls.TYPE,
                    CallLog.Calls.DATE,
                    CallLog.Calls.DURATION
                ),
                null,
                null,
                "${CallLog.Calls.DATE} DESC"
            )
            cursor?.use { c ->
                var count = 0
                val idIdx = c.getColumnIndex(CallLog.Calls._ID)
                val numIdx = c.getColumnIndex(CallLog.Calls.NUMBER)
                val nameIdx = c.getColumnIndex(CallLog.Calls.CACHED_NAME)
                val typeIdx = c.getColumnIndex(CallLog.Calls.TYPE)
                val dateIdx = c.getColumnIndex(CallLog.Calls.DATE)
                val durIdx = c.getColumnIndex(CallLog.Calls.DURATION)

                while (c.moveToNext() && count < 60) {
                    val id = if (idIdx >= 0) c.getString(idIdx) else "${System.currentTimeMillis()}_$count"
                    val num = if (numIdx >= 0) c.getString(numIdx) ?: "Unknown" else "Unknown"
                    val name = if (nameIdx >= 0) c.getString(nameIdx) ?: "" else ""
                    val typeInt = if (typeIdx >= 0) c.getInt(typeIdx) else 1
                    val dateMs = if (dateIdx >= 0) c.getLong(dateIdx) else System.currentTimeMillis()
                    val durSec = if (durIdx >= 0) c.getLong(durIdx) else 0L

                    val typeLabel = when (typeInt) {
                        CallLog.Calls.INCOMING_TYPE -> "↙️ Incoming"
                        CallLog.Calls.OUTGOING_TYPE -> "↗️ Outgoing"
                        CallLog.Calls.MISSED_TYPE -> "❌ Missed"
                        CallLog.Calls.REJECTED_TYPE -> "⛔ Rejected"
                        else -> "📞 Call"
                    }
                    val displayName = if (name.isNotBlank()) "$name ($num)" else num
                    arr.put(JSONObject().apply {
                        put("id", "calllog_$id")
                        put("title", "$typeLabel: $displayName")
                        put("number", num)
                        put("body", "$typeLabel | Number: $num | Duration: ${durSec}s")
                        put("ts", dateMs)
                    })
                    count++
                }
            }
        } catch (_: Exception) {}
        return arr
    }

    @SuppressLint("MissingPermission")
    fun readHostContactsJson(): JSONArray {
        val arr = JSONArray()
        val seen = HashSet<String>()
        try {
            val cursor = contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER
                ),
                null,
                null,
                "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} ASC"
            )
            cursor?.use { c ->
                val nameIdx = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
                val numIdx = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
                var count = 0
                while (c.moveToNext() && count < 400) {
                    val name = if (nameIdx >= 0) c.getString(nameIdx) ?: "" else ""
                    val rawNum = if (numIdx >= 0) c.getString(numIdx) ?: "" else ""
                    val cleanNum = rawNum.replace(" ", "").replace("-", "")
                    val key = "$name|$cleanNum"
                    if (cleanNum.isNotBlank() && !seen.contains(key)) {
                        seen.add(key)
                        arr.put(JSONObject().apply {
                            put("name", name.ifBlank { cleanNum })
                            put("number", cleanNum)
                        })
                        count++
                    }
                }
            }
        } catch (_: Exception) {}
        return arr
    }

    @SuppressLint("MissingPermission")
    fun sendSmsOnHost(number: String, body: String, simSlot: Int) {
        if (number.isBlank() || body.isBlank()) return
        try {
            val smsManager: SmsManager = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                val subMgr = getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
                val subs = subMgr.activeSubscriptionInfoList
                val targetSub = subs?.firstOrNull { it.simSlotIndex == simSlot } ?: subs?.firstOrNull()
                if (targetSub != null) {
                    SmsManager.getSmsManagerForSubscriptionId(targetSub.subscriptionId)
                } else {
                    SmsManager.getDefault()
                }
            } else {
                SmsManager.getDefault()
            }
            val parts = smsManager.divideMessage(body)
            smsManager.sendMultipartTextMessage(number.trim(), null, parts, null, null)
            StorageEngine.addHistoryRecord(
                this,
                HistoryRecord(
                    id = "sms_sent_${System.currentTimeMillis()}",
                    category = "SMS",
                    title = "↗️ Sent SMS (SIM ${simSlot + 1}) -> $number",
                    numberOrPkg = number,
                    body = body,
                    timestamp = System.currentTimeMillis()
                )
            )
            MirrorHubBus.postToast("SMS Sent to $number via SIM ${simSlot + 1}", "تم إرسال الرسالة إلى $number عبر شريحة ${simSlot + 1}")
        } catch (e: Exception) {
            MirrorHubBus.postToast("SMS Send Failed: ${e.message}", "فشل إرسال الرسالة: ${e.message}")
        }
    }

    @SuppressLint("MissingPermission")
    fun readHostSmsInboxJson(): JSONArray {
        val arr = JSONArray()
        try {
            val cursor = contentResolver.query(
                Telephony.Sms.CONTENT_URI,
                arrayOf(Telephony.Sms._ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
                null,
                null,
                "${Telephony.Sms.DATE} DESC"
            )
            cursor?.use { c ->
                val idIdx = c.getColumnIndex(Telephony.Sms._ID)
                val addrIdx = c.getColumnIndex(Telephony.Sms.ADDRESS)
                val bodyIdx = c.getColumnIndex(Telephony.Sms.BODY)
                val dateIdx = c.getColumnIndex(Telephony.Sms.DATE)
                var count = 0
                while (c.moveToNext() && count < 60) {
                    val id = if (idIdx >= 0) c.getString(idIdx) else "$count"
                    val addr = if (addrIdx >= 0) c.getString(addrIdx) ?: "Unknown" else "Unknown"
                    val body = if (bodyIdx >= 0) c.getString(bodyIdx) ?: "" else ""
                    val dateMs = if (dateIdx >= 0) c.getLong(dateIdx) else System.currentTimeMillis()
                    arr.put(JSONObject().apply {
                        put("id", "smsinbox_$id")
                        put("sender", addr)
                        put("body", body)
                        put("ts", dateMs)
                    })
                    count++
                }
            }
        } catch (_: Exception) {}
        return arr
    }

    @SuppressLint("MissingPermission")
    fun executeUssdOnHost(ussdCode: String, simSlot: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                var tm = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
                val subMgr = getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
                val subs = subMgr.activeSubscriptionInfoList
                val targetSub = subs?.firstOrNull { it.simSlotIndex == simSlot } ?: subs?.firstOrNull()
                if (targetSub != null) {
                    tm = tm.createForSubscriptionId(targetSub.subscriptionId)
                }
                tm.sendUssdRequest(ussdCode, object : TelephonyManager.UssdResponseCallback() {
                    override fun onReceiveUssdResponse(telephonyManager: TelephonyManager?, request: String?, response: CharSequence?) {
                        val respText = response?.toString() ?: "OK"
                        MirrorHubBus.notifyUssd(respText)
                        sendPacket("USSD_RESULT", JSONObject().apply {
                            put("code", ussdCode)
                            put("response", respText)
                        })
                    }

                    override fun onReceiveUssdResponseFailed(telephonyManager: TelephonyManager?, request: String?, failureCode: Int) {
                        val errText = "USSD Failed (Code $failureCode) for $ussdCode"
                        MirrorHubBus.notifyUssd(errText)
                        sendPacket("USSD_RESULT", JSONObject().apply {
                            put("code", ussdCode)
                            put("response", errText)
                        })
                    }
                }, mainHandler)
            } catch (e: Exception) {
                MirrorHubBus.notifyUssd("USSD Exception: ${e.message}")
            }
        }
    }

    private fun handleHostCallStateChange(state: String, number: String) {
        if (state == TelephonyManager.EXTRA_STATE_OFFHOOK) {
            forceEnableSpeakerphoneHardware()
        }
        sendPacket("HOST_CALL_ALERT", JSONObject().apply {
            put("state", state)
            put("number", number)
            put("name", number)
        })
    }

    private fun handleHostIncomingSms(sender: String, body: String) {
        StorageEngine.addHistoryRecord(
            this,
            HistoryRecord(
                id = "sms_host_${System.currentTimeMillis()}",
                category = "SMS",
                title = "↙️ SMS: $sender",
                numberOrPkg = sender,
                body = body,
                timestamp = System.currentTimeMillis()
            )
        )
        val otp = CryptoAndParserEngine.extractOtpOrDigits(body)
        if (otp.length in 4..8) {
            copyToClipboardInternal("OTP", otp)
            MirrorHubBus.notifyOtp(otp, body, sender)
        }
        sendPacket("HOST_SMS_ALERT", JSONObject().apply {
            put("sender", sender)
            put("body", body)
        })
    }

    // -------------------------------------------------------------------------------------
    // LIVE TWO-WAY WI-FI PCM AUDIO RELAY ENGINE (TAB 2)
    // -------------------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    fun toggleLiveAudioRelay() {
        if (isAudioStreaming.get()) {
            stopLiveAudioRelay()
        } else {
            val peerIp = StorageEngine.getManualIp(this)
            if (peerIp.isBlank()) {
                MirrorHubBus.postToast(
                    "Set or Auto-Discover Local Peer IP in Tab 1 first",
                    "يرجى تحديد أو اكتشاف IP الجهاز المحلي في التبويب 1 أولاً"
                )
                return
            }
            startLiveAudioRelay(peerIp)
        }
    }

    @SuppressLint("MissingPermission")
    private fun startLiveAudioRelay(peerIp: String) {
        isAudioStreaming.set(true)
        MirrorHubBus.notifyAudioStream(true)
        val sampleRate = 8000
        val bufSize = maxOf(
            AudioRecord.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT),
            1024
        )
        executor.execute {
            try {
                audioSocket = DatagramSocket(UDP_AUDIO_PORT)
                // Sender Thread (Mic -> UDP)
                executor.execute {
                    var recorder: AudioRecord? = null
                    try {
                        recorder = AudioRecord(
                            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                            sampleRate,
                            AudioFormat.CHANNEL_IN_MONO,
                            AudioFormat.ENCODING_PCM_16BIT,
                            bufSize
                        )
                        recorder.startRecording()
                        val targetAddr = InetAddress.getByName(peerIp)
                        val buf = ByteArray(640)
                        while (isAudioStreaming.get() && isServiceAlive.get()) {
                            val read = recorder.read(buf, 0, buf.size)
                            if (read > 0) {
                                audioSocket?.send(DatagramPacket(buf, read, targetAddr, UDP_AUDIO_PORT))
                            }
                        }
                    } catch (_: Exception) {
                    } finally {
                        try { recorder?.stop(); recorder?.release() } catch (_: Exception) {}
                    }
                }

                // Receiver Thread (UDP -> Speaker)
                var player: AudioTrack? = null
                try {
                    player = AudioTrack(
                        AudioManager.STREAM_VOICE_CALL,
                        sampleRate,
                        AudioFormat.CHANNEL_OUT_MONO,
                        AudioFormat.ENCODING_PCM_16BIT,
                        bufSize,
                        AudioTrack.MODE_STREAM
                    )
                    player.play()
                    val rxBuf = ByteArray(1024)
                    while (isAudioStreaming.get() && isServiceAlive.get()) {
                        val pkt = DatagramPacket(rxBuf, rxBuf.size)
                        audioSocket?.receive(pkt) ?: break
                        if (pkt.address.hostAddress != getLocalWifiIp()) {
                            player.write(pkt.data, 0, pkt.length)
                        }
                    }
                } catch (_: Exception) {
                } finally {
                    try { player?.stop(); player?.release() } catch (_: Exception) {}
                }
            } catch (_: Exception) {
                stopLiveAudioRelay()
            }
        }
        MirrorHubBus.postToast("Live Wi-Fi Audio Stream Active", "البث الصوتي المباشر عبر الواي فاي نشط الآن")
    }

    fun stopLiveAudioRelay() {
        isAudioStreaming.set(false)
        MirrorHubBus.notifyAudioStream(false)
        try { audioSocket?.close() } catch (_: Exception) {}
        audioSocket = null
    }

    // -------------------------------------------------------------------------------------
    // FLOATING INCOMING CALL BANNER OVERLAY (SYSTEM_ALERT_WINDOW)
    // -------------------------------------------------------------------------------------

    fun showFloatingIncomingCallBanner(callerName: String, callerNumber: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) return
        dismissFloatingCallBanner()
        try {
            val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val ar = StorageEngine.isArabic(this)
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(36, 30, 36, 30)
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#161B22"))
                    cornerRadius = 38f
                    setStroke(4, Color.parseColor("#10B981"))
                }
                elevation = 24f
            }

            val titleTv = TextView(this).apply {
                text = if (ar) "📲 مكالمة واردة على الهاتف الأساسي" else "📲 Incoming Call on SIM Host"
                setTextColor(Color.parseColor("#10B981"))
                textSize = 15f
                setTypeface(typeface, Typeface.BOLD)
            }
            val numTv = TextView(this).apply {
                text = "$callerName ($callerNumber)"
                setTextColor(Color.WHITE)
                textSize = 18f
                setTypeface(typeface, Typeface.BOLD)
                setPadding(0, 8, 0, 18)
            }

            val btnRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER
            }

            fun makeOverlayBtn(label: String, colorHex: String, onClick: () -> Unit): TextView {
                return TextView(this).apply {
                    text = label
                    setTextColor(Color.WHITE)
                    textSize = 12f
                    setTypeface(typeface, Typeface.BOLD)
                    gravity = Gravity.CENTER
                    setPadding(22, 18, 22, 18)
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor(colorHex))
                        cornerRadius = 22f
                    }
                    val lp = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    lp.setMargins(6, 0, 6, 0)
                    layoutParams = lp
                    setOnClickListener { onClick() }
                }
            }

            btnRow.addView(makeOverlayBtn(if (ar) "🔊 رد سبيكر" else "🔊 Answer Spk", "#10B981") {
                sendPacket("ANSWER_CALL", JSONObject().apply { put("speaker", true) })
                dismissFloatingCallBanner()
            })
            btnRow.addView(makeOverlayBtn(if (ar) "⛔ رفض" else "⛔ Reject", "#EF4444") {
                sendPacket("END_CALL")
                dismissFloatingCallBanner()
            })
            btnRow.addView(makeOverlayBtn(if (ar) "💬 مشغول" else "💬 Busy SMS", "#8B5CF6") {
                sendPacket("REJECT_WITH_SMS", JSONObject().apply {
                    put("number", callerNumber)
                    put("message", if (ar) "أنا مشغول حالياً، سأتصل بك قريباً." else "I am busy right now, will call you back soon.")
                })
                dismissFloatingCallBanner()
            })
            btnRow.addView(makeOverlayBtn("🔇", "#475569") {
                dismissFloatingCallBanner()
            })

            card.addView(titleTv)
            card.addView(numTv)
            card.addView(btnRow)

            val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                WindowManager.LayoutParams.TYPE_PHONE
            }
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                layoutType,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                    WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
                y = 60
            }
            wm.addView(card, params)
            floatingBannerView = card
        } catch (_: Exception) {}
    }

    fun dismissFloatingCallBanner() {
        floatingBannerView?.let { view ->
            try {
                val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
                wm.removeView(view)
            } catch (_: Exception) {}
            floatingBannerView = null
        }
    }

    // -------------------------------------------------------------------------------------
    // BATTERY, SIM & ALARM HELPERS
    // -------------------------------------------------------------------------------------

    private fun startPeriodicHeartbeatLoop() {
        executor.execute {
            while (isServiceAlive.get()) {
                broadcastBatteryAndSimStatus()
                try { Thread.sleep(45000) } catch (_: Exception) {}
            }
        }
    }

    fun broadcastBatteryAndSimStatus() {
        val pct = getLocalBatteryPct()
        val chg = isLocalCharging()
        val sim = getLocalActiveSimSummary()
        MirrorHubBus.notifyBatterySim(pct, chg, sim)
        if (StorageEngine.isHostMode(this)) {
            sendPacket("PING_REPLY", JSONObject().apply {
                put("device", deviceName)
                put("battery", pct)
                put("charging", chg)
                put("sim", sim)
            })
        }
    }

    private fun getLocalBatteryPct(): Int {
        return try {
            val bm = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY).coerceIn(0, 100)
        } catch (_: Exception) { 100 }
    }

    private fun isLocalCharging(): Boolean {
        return try {
            val intent = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val status = intent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
            status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        } catch (_: Exception) { false }
    }

    @SuppressLint("MissingPermission")
    private fun getLocalActiveSimSummary(): String {
        val slot = StorageEngine.getSelectedSimSlot(this)
        return try {
            val subMgr = getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
            val subs = subMgr.activeSubscriptionInfoList
            val match = subs?.firstOrNull { it.simSlotIndex == slot }
            if (match != null) {
                "SIM ${slot + 1} (${match.carrierName})"
            } else {
                "SIM ${slot + 1}"
            }
        } catch (_: Exception) {
            "SIM ${slot + 1}"
        }
    }

    private fun triggerFindPhoneAlarm() {
        try {
            val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            val max = audioManager.getStreamMaxVolume(AudioManager.STREAM_ALARM)
            audioManager.setStreamVolume(AudioManager.STREAM_ALARM, max, 0)
            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
                ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            alarmRingtone?.stop()
            alarmRingtone = RingtoneManager.getRingtone(applicationContext, uri)
            alarmRingtone?.play()
            mainHandler.postDelayed({ alarmRingtone?.stop() }, 10000L)
            MirrorHubBus.postToast("🚨 Find Host Phone Alarm Ringing!", "🚨 رنين العثور على الهاتف الأساسي يعمل الآن!")
        } catch (_: Exception) {}
    }

    private fun copyToClipboardInternal(label: String, value: String) {
        mainHandler.post {
            try {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText(label, value))
            } catch (_: Exception) {}
        }
    }
}

// =========================================================================================
// 5. APP NOTIFICATION LISTENER SERVICE (TAB 4 - WHATSAPP, TELEGRAM, BANKS)
// =========================================================================================

class AppNotificationListenerService : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return
        val pkg = sbn.packageName ?: return
        if (pkg == packageName || pkg == "android" || pkg == "com.android.systemui") return

        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        if (title.isBlank() && text.isBlank()) return

        val friendlyApp = when {
            pkg.contains("whatsapp", true) -> "WhatsApp"
            pkg.contains("telegram", true) || pkg.contains("messenger", true) -> "Telegram/Chat"
            pkg.contains("bank", true) || pkg.contains("pay", true) || pkg.contains("wallet", true) -> "Bank/Finance"
            pkg.contains("gm", true) || pkg.contains("mail", true) -> "Email"
            else -> pkg.substringAfterLast('.')
        }

        val record = HistoryRecord(
            id = "notif_${sbn.postTime}_${pkg.hashCode()}",
            category = "ALERT",
            title = "$friendlyApp: $title",
            numberOrPkg = friendlyApp,
            body = text,
            timestamp = sbn.postTime
        )
        StorageEngine.addHistoryRecord(applicationContext, record)

        if (StorageEngine.isHostMode(applicationContext)) {
            MirrorBackgroundService.instance?.sendPacket("HOST_APP_NOTIFICATION", JSONObject().apply {
                put("pkg", friendlyApp)
                put("title", title)
                put("text", text)
            })
        }
    }
}

// =========================================================================================
// 6. SMS & CALL STATE BROADCAST RECEIVER + BOOT RECEIVER
// =========================================================================================

class SmsBroadcastReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        MirrorBackgroundService.startOrEnsureRunning(context)
        when (intent.action) {
            Telephony.Sms.Intents.SMS_RECEIVED_ACTION -> {
                val msgs = Telephony.Sms.Intents.getMessagesFromIntent(intent)
                if (msgs.isNullOrEmpty()) return
                val sender = msgs[0].originatingAddress ?: "Unknown"
                val fullBody = msgs.joinToString("") { it.messageBody ?: "" }
                val svcIntent = Intent(context, MirrorBackgroundService::class.java).apply {
                    putExtra("SERVICE_ACTION", "INCOMING_SMS_EVENT")
                    putExtra("SMS_SENDER", sender)
                    putExtra("SMS_BODY", fullBody)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(svcIntent)
                } else {
                    context.startService(svcIntent)
                }
            }
            TelephonyManager.ACTION_PHONE_STATE_CHANGED -> {
                val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE) ?: return
                val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER) ?: "Number"
                val svcIntent = Intent(context, MirrorBackgroundService::class.java).apply {
                    putExtra("SERVICE_ACTION", "INCOMING_CALL_EVENT")
                    putExtra("CALL_STATE", state)
                    putExtra("CALL_NUMBER", incomingNumber)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(svcIntent)
                } else {
                    context.startService(svcIntent)
                }
            }
        }
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        MirrorBackgroundService.startOrEnsureRunning(context)
    }
}

// =========================================================================================
// 7. MAIN ACTIVITY: GITHUB MOBILE UI + 3D TACTILE ELEMENTS + 5 TABS + DUAL LANGUAGE
// =========================================================================================

class MainActivity : Activity(), MirrorHubBus.UiListener {

    companion object {
        private const val REQ_PERMISSIONS = 701
        private const val REQ_PICK_CONTACT = 702
    }

    private var activeTabIndex = 0 // 0=Connect, 1=Calls, 2=SMS&USSD, 3=AppAlerts, 4=History
    private var activeAlertFilter = "ALL" // "ALL", "CHATS", "BANKS"

    private lateinit var rootContainer: LinearLayout
    private lateinit var contentScrollView: ScrollView
    private lateinit var contentColumn: LinearLayout
    private lateinit var ledStatusView: View
    private lateinit var statusSubTextView: TextView
    private lateinit var batterySimTextView: TextView

    // Shared synchronized Target Phone Number Input across Tab 2 & Tab 3
    private var activeTargetNumberEdit: EditText? = null
    private var ussdResultTextView: TextView? = null
    private var connectedDevicesTextView: TextView? = null

    // Theme Palette Helpers
    private val isDark: Boolean get() = StorageEngine.isDarkTheme(this)
    private val isAr: Boolean get() = StorageEngine.isArabic(this)

    private val bgCanvasColor: Int get() = Color.parseColor(if (isDark) "#0D1117" else "#F6F8FA")
    private val bgCardColor: Int get() = Color.parseColor(if (isDark) "#161B22" else "#FFFFFF")
    private val bgElevatedColor: Int get() = Color.parseColor(if (isDark) "#21262D" else "#E2E8F0")
    private val borderColor: Int get() = Color.parseColor(if (isDark) "#30363D" else "#CBD5E1")
    private val textPrimaryColor: Int get() = Color.parseColor(if (isDark) "#F0F6FC" else "#0F172A")
    private val textSecondaryColor: Int get() = Color.parseColor(if (isDark) "#8B949E" else "#475569")

    private val tabAccents = arrayOf(
        "#0EA5E9", // Tab 1: Connect (Cyan Blue)
        "#10B981", // Tab 2: Calls (Emerald Green)
        "#8B5CF6", // Tab 3: SMS & USSD (Royal Purple)
        "#EC4899", // Tab 4: App Alerts (Ruby Pink)
        "#F59E0B"  // Tab 5: History (Golden Amber)
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNecessaryPermissions()
        MirrorBackgroundService.startOrEnsureRunning(this)
        seedInitialDemoHistoryIfEmpty()
        rebuildEntireScreen()
    }

    override fun onResume() {
        super.onResume()
        MirrorHubBus.listeners.add(this)
        MirrorBackgroundService.instance?.broadcastBatteryAndSimStatus()
        updateLedIndicator(MirrorHubBus.currentConnectionState, MirrorHubBus.currentConnectionDetail)
    }

    override fun onPause() {
        MirrorHubBus.listeners.remove(this)
        super.onPause()
    }

    private fun seedInitialDemoHistoryIfEmpty() {
        val current = StorageEngine.loadHistory(this)
        if (current.isEmpty()) {
            val now = System.currentTimeMillis()
            val seeds = listOf(
                HistoryRecord("seed_1", "SMS", "SMS: Bank-OTP", "Bank-OTP", "Your verification OTP code is 482910. Valid for 5 minutes.", now - 60000),
                HistoryRecord("seed_2", "CALL", "↙️ Incoming: +201000000001", "+201000000001", "↙️ Incoming | Number: +201000000001 | Duration: 42s", now - 120000),
                HistoryRecord("seed_3", "ALERT", "WhatsApp: Ahmed Ali", "WhatsApp", "Hello! Call me on the SIM Host phone when ready.", now - 180000)
            )
            StorageEngine.addHistoryBatch(this, seeds)
            MirrorHubBus.notifyOtp("482910", seeds[0].body, "Bank-OTP")
        }
    }

    // -------------------------------------------------------------------------------------
    // UI BUILDER: GITHUB MOBILE HEADER + 28dp LED + 3D THEME/LANG + 5 SINGLE-LINE PILL TABS
    // -------------------------------------------------------------------------------------

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    private fun t(en: String, ar: String): String = if (isAr) ar else en

    private fun rebuildEntireScreen() {
        window.statusBarColor = Color.parseColor(if (isDark) "#090D11" else "#E2E8F0")

        rootContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgCanvasColor)
            layoutDirection = if (isAr) View.LAYOUT_DIRECTION_RTL else View.LAYOUT_DIRECTION_LTR
        }

        // 1. TOP PERMANENT HEADER BAR
        rootContainer.addView(buildTopHeaderBar())

        // 2. TOP PILL-HIGHLIGHTED 5-TAB NAVIGATION BAR (SINGLE LINE STRICT)
        rootContainer.addView(buildTopFiveTabsBar())

        // 3. MAIN SCROLLABLE CONTENT AREA
        contentScrollView = ScrollView(this).apply {
            isFillViewport = true
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }
        contentColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(10), dp(12), dp(28))
        }
        contentScrollView.addView(contentColumn)
        rootContainer.addView(contentScrollView)

        setContentView(rootContainer)
        renderActiveTabContent()
        updateLedIndicator(MirrorHubBus.currentConnectionState, MirrorHubBus.currentConnectionDetail)
    }

    private fun buildTopHeaderBar(): View {
        val headerWrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgCardColor)
            setPadding(dp(12), dp(10), dp(12), dp(8))
            elevation = dp(4).toFloat()
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        // App Title & Connection Status Column
        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val appTitleTv = TextView(this).apply {
            text = "SIM Mirror Hub v6.0"
            setTextColor(textPrimaryColor)
            textSize = 16.5f
            setTypeface(typeface, Typeface.BOLD)
            isSingleLine = true
            ellipsize = TextUtils.TruncateAt.END
        }
        statusSubTextView = TextView(this).apply {
            text = MirrorHubBus.currentConnectionDetail
            setTextColor(textSecondaryColor)
            textSize = 11.5f
            isSingleLine = true
            ellipsize = TextUtils.TruncateAt.END
        }
        titleCol.addView(appTitleTv)
        titleCol.addView(statusSubTextView)

        // Toolbar Action Controls: 28dp 3D LED Circle + 3D Theme Button + 3D Language Button
        val controlsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        // Large 28dp 3D Glowing Status LED Circle
        ledStatusView = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(28), dp(28)).apply {
                setMargins(dp(6), 0, dp(8), 0)
            }
            setOnClickListener {
                MirrorBackgroundService.instance?.triggerCloudReconnect()
                Toast.makeText(
                    this@MainActivity,
                    t("Refreshing Cloud & LAN Link...", "جاري تحديث ومزامنة الاتصال..."),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
        controlsRow.addView(ledStatusView)

        // 3D Theme Toggle Button (Takes Opposite Theme Color for High Contrast)
        val themeBtnLabel = if (isDark) "☀️ Light" else "🌙 Dark"
        val themeBtnBg = if (isDark) "#F8FAFC" else "#0F172A"
        val themeBtnBevel = if (isDark) "#94A3B8" else "#020617"
        val themeBtnTextCol = if (isDark) Color.parseColor("#0F172A") else Color.parseColor("#F8FAFC")
        val themeBtn = create3DTactileButton(
            text = themeBtnLabel,
            faceColorHex = themeBtnBg,
            bevelColorHex = themeBtnBevel,
            textColor = themeBtnTextCol,
            textSizeSp = 11.5f,
            paddingH = dp(10),
            paddingV = dp(6)
        ) {
            StorageEngine.setDarkTheme(this, !isDark)
            rebuildEntireScreen()
        }
        val themeLp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        themeLp.setMargins(dp(4), 0, dp(4), 0)
        themeBtn.layoutParams = themeLp
        controlsRow.addView(themeBtn)

        // 3D Language Toggle Button (EN / AR)
        val langLabel = if (isAr) "EN" else "AR"
        val langBtn = create3DTactileButton(
            text = "🌐 $langLabel",
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1",
            textColor = Color.WHITE,
            textSizeSp = 11.5f,
            paddingH = dp(10),
            paddingV = dp(6)
        ) {
            StorageEngine.setArabic(this, !isAr)
            rebuildEntireScreen()
        }
        val langLp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        langLp.setMargins(dp(4), 0, 0, 0)
        langBtn.layoutParams = langLp
        controlsRow.addView(langBtn)

        topRow.addView(titleCol)
        topRow.addView(controlsRow)
        headerWrapper.addView(topRow)

        // Sub-bar: Host Battery %, Charging State & Active SIM Badge
        val roleBadge = if (StorageEngine.isHostMode(this)) {
            t("📡 Mode: SIM HOST", "📡 الوضع: الهاتف الأساسي (SIM Host)")
        } else {
            t("📱 Mode: REMOTE CLIENT", "📱 الوضع: الهاتف الفرعي (Remote)")
        }
        val chgIcon = if (MirrorHubBus.hostCharging) "⚡" else "🔋"
        batterySimTextView = TextView(this).apply {
            text = "$roleBadge  •  $chgIcon ${MirrorHubBus.hostBatteryPct}%  •  💳 ${MirrorHubBus.activeSimInfo}"
            setTextColor(Color.parseColor(tabAccents[activeTabIndex]))
            textSize = 11.5f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(6), 0, dp(2))
            isSingleLine = true
            ellipsize = TextUtils.TruncateAt.END
        }
        headerWrapper.addView(batterySimTextView)

        return headerWrapper
    }

    private fun updateLedIndicator(state: Int, detail: String) {
        val coreColor = when (state) {
            2 -> Color.parseColor("#10B981") // Green Connected
            1 -> Color.parseColor("#F59E0B") // Orange Connecting
            else -> Color.parseColor("#EF4444") // Red Offline
        }
        val glowColor = when (state) {
            2 -> Color.parseColor("#5510B981")
            1 -> Color.parseColor("#55F59E0B")
            else -> Color.parseColor("#55EF4444")
        }
        val outerRing = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(glowColor)
            setStroke(dp(2), Color.WHITE)
        }
        val innerSphere = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            colors = intArrayOf(Color.WHITE, coreColor, coreColor)
            gradientType = GradientDrawable.RADIAL_GRADIENT
            gradientRadius = dp(14).toFloat()
        }
        val layer = LayerDrawable(arrayOf(outerRing, innerSphere))
        layer.setLayerInset(1, dp(4), dp(4), dp(4), dp(4))
        ledStatusView.background = layer
        statusSubTextView.text = detail
    }

    private fun buildTopFiveTabsBar(): View {
        val barContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(bgCardColor)
            setPadding(dp(6), dp(6), dp(6), dp(8))
            elevation = dp(3).toFloat()
        }

        val tabIcons = arrayOf("🔗", "📞", "💬", "🔔", "🗂️")
        val tabTitles = arrayOf(
            t("Connect", "الربط"),
            t("Calls", "المكالمات"),
            t("SMS & USSD", "الرسائل"),
            t("App Alerts", "الإشعارات"),
            t("History", "السجل")
        )

        for (i in 0 until 5) {
            val isSelected = (i == activeTabIndex)
            val accentHex = tabAccents[i]
            val tabCell = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setPadding(dp(4), dp(6), dp(4), dp(6))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(dp(2), 0, dp(2), 0)
                }
                if (isSelected) {
                    background = create3DBevelDrawable(
                        faceColor = Color.parseColor(if (isDark) "#21262D" else "#F1F5F9"),
                        bevelColor = Color.parseColor(accentHex),
                        cornerRadiusDp = 14,
                        strokeColor = Color.parseColor(accentHex)
                    )
                }
                setOnClickListener {
                    it.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                    activeTabIndex = i
                    rebuildEntireScreen()
                }
            }

            // GitHub Mobile Pill-Highlighted Icon Capsule
            val iconPill = TextView(this).apply {
                text = tabIcons[i]
                textSize = 14f
                gravity = Gravity.CENTER
                setPadding(dp(10), dp(2), dp(10), dp(2))
                if (isSelected) {
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor(accentHex))
                        cornerRadius = dp(50).toFloat()
                    }
                }
            }

            // Strict Single-Line Tab Title
            val labelTv = TextView(this).apply {
                text = tabTitles[i]
                textSize = 10.5f
                isSingleLine = true
                maxLines = 1
                ellipsize = TextUtils.TruncateAt.END
                gravity = Gravity.CENTER
                setPadding(0, dp(3), 0, 0)
                setTypeface(typeface, if (isSelected) Typeface.BOLD else Typeface.NORMAL)
                setTextColor(if (isSelected) Color.parseColor(accentHex) else textSecondaryColor)
            }

            tabCell.addView(iconPill)
            tabCell.addView(labelTv)
            barContainer.addView(tabCell)
        }
        return barContainer
    }

    // -------------------------------------------------------------------------------------
    // 3D TACTILE BUTTONS, SQUIRCLE BADGES & INFO DIALOG COMPONENTS
    // -------------------------------------------------------------------------------------

    private fun create3DBevelDrawable(
        faceColor: Int,
        bevelColor: Int,
        cornerRadiusDp: Int = 12,
        strokeColor: Int = Color.TRANSPARENT,
        pressed: Boolean = false
    ): LayerDrawable {
        val radius = dp(cornerRadiusDp).toFloat()
        val bottomBevel = GradientDrawable().apply {
            setColor(bevelColor)
            cornerRadius = radius
        }
        val topFace = GradientDrawable().apply {
            setColor(faceColor)
            cornerRadius = radius
            if (strokeColor != Color.TRANSPARENT) {
                setStroke(dp(1), strokeColor)
            }
        }
        val layers = LayerDrawable(arrayOf(bottomBevel, topFace))
        val bottomInset = if (pressed) dp(1) else dp(4)
        val topInset = if (pressed) dp(3) else 0
        layers.setLayerInset(0, 0, topInset, 0, 0)
        layers.setLayerInset(1, 0, topInset, 0, bottomInset)
        return layers
    }

    private fun create3DTactileButton(
        text: String,
        faceColorHex: String,
        bevelColorHex: String,
        textColor: Int = Color.WHITE,
        textSizeSp: Float = 13f,
        paddingH: Int = dp(14),
        paddingV: Int = dp(11),
        onClick: () -> Unit
    ): TextView {
        val faceCol = Color.parseColor(faceColorHex)
        val bevelCol = Color.parseColor(bevelColorHex)
        return TextView(this).apply {
            this.text = text
            setTextColor(textColor)
            textSize = textSizeSp
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(paddingH, paddingV, paddingH, paddingV + dp(3))
            background = create3DBevelDrawable(faceCol, bevelCol, 12, pressed = false)

            setOnTouchListener { v, event ->
                when (event.action) {
                    MotionEvent.ACTION_DOWN -> {
                        v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
                        v.background = create3DBevelDrawable(faceCol, bevelCol, 12, pressed = true)
                        v.translationY = dp(3).toFloat()
                        true
                    }
                    MotionEvent.ACTION_UP -> {
                        v.background = create3DBevelDrawable(faceCol, bevelCol, 12, pressed = false)
                        v.translationY = 0f
                        onClick()
                        true
                    }
                    MotionEvent.ACTION_CANCEL -> {
                        v.background = create3DBevelDrawable(faceCol, bevelCol, 12, pressed = false)
                        v.translationY = 0f
                        true
                    }
                    else -> false
                }
            }
        }
    }

    private fun createSectionCard(
        badgeIcon: String,
        badgeColorHex: String,
        titleEn: String,
        titleAr: String,
        infoEn: String,
        infoAr: String
    ): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
            background = GradientDrawable().apply {
                setColor(bgCardColor)
                cornerRadius = dp(16).toFloat()
                setStroke(dp(1), borderColor)
            }
            elevation = dp(3).toFloat()
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, dp(12))
            }
        }

        // Card Header Row: GitHub-style Squircle Badge + Section Title + 3D 'i' Info Button
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(10))
        }

        val squircleBadge = TextView(this).apply {
            text = badgeIcon
            textSize = 15f
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                setColor(Color.parseColor(badgeColorHex))
                cornerRadius = dp(10).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(dp(34), dp(34)).apply {
                setMargins(0, 0, dp(10), 0)
            }
        }

        val titleTv = TextView(this).apply {
            text = t(titleEn, titleAr)
            setTextColor(textPrimaryColor)
            textSize = 15f
            setTypeface(typeface, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }

        // 3D Info 'i' Button
        val infoBtn = TextView(this).apply {
            text = "i"
            setTextColor(Color.WHITE)
            textSize = 13f
            setTypeface(Typeface.SERIF, Typeface.BOLD_ITALIC)
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Color.parseColor(badgeColorHex))
                setStroke(dp(2), borderColor)
            }
            layoutParams = LinearLayout.LayoutParams(dp(26), dp(26))
            setOnClickListener {
                it.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("ℹ️ ${t(titleEn, titleAr)}")
                    .setMessage(t(infoEn, infoAr))
                    .setPositiveButton(t("Got It", "حسناً، فهمت"), null)
                    .show()
            }
        }

        headerRow.addView(squircleBadge)
        headerRow.addView(titleTv)
        headerRow.addView(infoBtn)
        card.addView(headerRow)
        return card
    }

    private fun styleEditText(hintStr: String, initialValue: String = ""): EditText {
        return EditText(this).apply {
            hint = hintStr
            setText(initialValue)
            setTextColor(textPrimaryColor)
            setHintTextColor(textSecondaryColor)
            textSize = 14f
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = GradientDrawable().apply {
                setColor(bgElevatedColor)
                cornerRadius = dp(10).toFloat()
                setStroke(dp(1), borderColor)
            }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, dp(4), 0, dp(8))
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // TAB CONTENT ROUTER
    // -------------------------------------------------------------------------------------

    private fun renderActiveTabContent() {
        contentColumn.removeAllViews()
        when (activeTabIndex) {
            0 -> renderTab1Connect()
            1 -> renderTab2Calls()
            2 -> renderTab3SmsAndUssd()
            3 -> renderTab4AppAlerts()
            4 -> renderTab5PermanentHistory()
        }
    }

    // =====================================================================================
    // TAB 1: CONNECT & DEVICES (CYAN BLUE #0EA5E9)
    // =====================================================================================

    private fun renderTab1Connect() {
        // 1. Device Role Selector Card
        val roleCard = createSectionCard(
            badgeIcon = "📱",
            badgeColorHex = "#0EA5E9",
            titleEn = "Device Role (SIM Host vs Remote Client)",
            titleAr = "وضع الجهاز (الهاتف الأساسي أو الفرعي)",
            infoEn = "Choose 'SIM Host' on the phone holding your physical SIM card. Choose 'Remote Client' on one or more secondary phones that will make/receive calls, read SMS/OTPs, and view app notifications remotely.",
            infoAr = "اختر (SIM Host الأساسي) على الهاتف الذي بداخله شريحة الاتصال. واختر (Remote Client الفرعي) على الهاتف أو الهواتف الأخرى للتحكم في المكالمات والرسائل والإشعارات عن بُعد."
        )

        val isHost = StorageEngine.isHostMode(this)
        val roleRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        val hostBtn = create3DTactileButton(
            text = t("📡 SIM Host (Primary)", "📡 الأساسي (SIM Host)"),
            faceColorHex = if (isHost) "#0EA5E9" else "#334155",
            bevelColorHex = if (isHost) "#0369A1" else "#1E293B"
        ) {
            StorageEngine.setHostMode(this, true)
            MirrorBackgroundService.instance?.broadcastBatteryAndSimStatus()
            rebuildEntireScreen()
        }
        val remoteBtn = create3DTactileButton(
            text = t("📲 Remote Client", "📲 الفرعي (Remote)"),
            faceColorHex = if (!isHost) "#10B981" else "#334155",
            bevelColorHex = if (!isHost) "#047857" else "#1E293B"
        ) {
            StorageEngine.setHostMode(this, false)
            MirrorBackgroundService.instance?.broadcastBatteryAndSimStatus()
            rebuildEntireScreen()
        }
        hostBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        remoteBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        roleRow.addView(hostBtn)
        roleRow.addView(remoteBtn)
        roleCard.addView(roleRow)
        contentColumn.addView(roleCard)

        // 2. Multi-Device Cloud Hub & AES-256 Encryption Card
        val cloudCard = createSectionCard(
            badgeIcon = "☁️",
            badgeColorHex = "#8B5CF6",
            titleEn = "Multi-Device Cloud Hub & AES-256 Security",
            titleAr = "الربط السحابي المتعدد والتشفير AES-256",
            infoEn = "Enter the same Secret Room Code on your SIM Host and all Remote Clients to link them over the internet 24/7. Add an optional AES-256 PIN so all phone numbers, SMS, and OTPs are encrypted end-to-end.",
            infoAr = "أدخل نفس كود الغرفة السري في الهاتف الأساسي وجميع الهواتف الفرعية لربطها عبر الإنترنت بدون انقطاع. يمكنك إضافة كلمة سر تشفير AES-256 لتشفير كافة الأرقام والرسائل."
        )

        val roomEdit = styleEditText(
            t("Secret Cloud Room Code (e.g. ULTRA-SIM-7700)", "كود الغرفة السحابي السري"),
            StorageEngine.getRoomCode(this)
        )
        val pinEdit = styleEditText(
            t("Optional AES-256 Encryption PIN", "كلمة سر التشفير الاختيارية AES-256"),
            StorageEngine.getEncryptionPin(this)
        )
        cloudCard.addView(roomEdit)
        cloudCard.addView(pinEdit)

        val connectCloudBtn = create3DTactileButton(
            text = t("☁️ Save & Connect Cloud Stream Now", "☁️ حفظ وربط السحابة الدائمة الآن"),
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1"
        ) {
            StorageEngine.setRoomCode(this, roomEdit.text.toString())
            StorageEngine.setEncryptionPin(this, pinEdit.text.toString())
            MirrorBackgroundService.instance?.triggerCloudReconnect()
            Toast.makeText(this, t("Cloud Room Updated & Reconnecting...", "تم حفظ الغرفة وجاري الاتصال بالسحابة..."), Toast.LENGTH_SHORT).show()
        }
        cloudCard.addView(connectCloudBtn)

        val utilRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, 0)
        }
        val pingBtn = create3DTactileButton(
            text = t("📡 Ping Devices", "📡 الأجهزة المتصلة"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6"
        ) {
            MirrorBackgroundService.instance?.sendPacket("PING_ANNOUNCE")
            Toast.makeText(this, t("Pinging connected devices...", "جاري فحص الأجهزة المتصلة..."), Toast.LENGTH_SHORT).show()
        }
        val findBtn = create3DTactileButton(
            text = t("🚨 Find Host Phone", "🚨 رنين الهاتف الأساسي"),
            faceColorHex = "#F59E0B",
            bevelColorHex = "#B45309"
        ) {
            MirrorBackgroundService.instance?.sendPacket("FIND_HOST_ALARM")
            Toast.makeText(this, t("Sent Ring Alarm to Host Phone!", "تم إرسال أمر الرنين العالي للهاتف الأساسي!"), Toast.LENGTH_SHORT).show()
        }
        pingBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        findBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        utilRow.addView(pingBtn)
        utilRow.addView(findBtn)
        cloudCard.addView(utilRow)

        connectedDevicesTextView = TextView(this).apply {
            val peers = MirrorHubBus.connectedPeers.keys.joinToString(", ").ifEmpty { t("Active Room Ready", "الغرفة جاهزة ومتصلة") }
            text = "🖧 $peers"
            setTextColor(textSecondaryColor)
            textSize = 12f
            setPadding(0, dp(8), 0, 0)
            setTextIsSelectable(true)
        }
        cloudCard.addView(connectedDevicesTextView)
        contentColumn.addView(cloudCard)

        // 3. Offline Local LAN (Wi-Fi / Hotspot / Bluetooth) Card
        val lanCard = createSectionCard(
            badgeIcon = "🔍",
            badgeColorHex = "#10B981",
            titleEn = "Offline Local Link (Wi-Fi / Hotspot / Bluetooth)",
            titleAr = "الربط المحلي الأوفلاين (واي فاي / هوت سبوت / بلوتوث)",
            infoEn = "Connect directly without internet over shared Wi-Fi or Hotspot using UDP Auto-Discovery or manual IP, plus Bluetooth pairing for local audio routing.",
            infoAr = "اتصل محلياً بدون إنترنت عبر الواي فاي أو نقطة الاتصال (Hotspot) باكتشاف تلقائي UDP أو كتابة IP يدوياً، بالإضافة إلى ربط البلوتوث."
        )

        val ipEdit = styleEditText(
            t("Peer Local IP (Auto-filled or Manual e.g. 192.168.43.1)", "عنوان IP المحلي (يملأ تلقائياً أو يدوياً)"),
            StorageEngine.getManualIp(this)
        )
        ipEdit.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                StorageEngine.setManualIp(this@MainActivity, s?.toString() ?: "")
            }
        })
        lanCard.addView(ipEdit)

        val lanBtnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val discoverBtn = create3DTactileButton(
            text = t("🔍 Auto-Discover LAN", "🔍 اكتشاف تلقائي Wi-Fi"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857"
        ) {
            MirrorBackgroundService.instance?.sendUdpBroadcastDiscovery()
        }
        val btPairBtn = create3DTactileButton(
            text = t("🦷 Bluetooth Link", "🦷 ربط بلوتوث"),
            faceColorHex = "#3B82F6",
            bevelColorHex = "#1D4ED8"
        ) {
            try {
                startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
            } catch (_: Exception) {}
        }
        discoverBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        btPairBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        lanBtnRow.addView(discoverBtn)
        lanBtnRow.addView(btPairBtn)
        lanCard.addView(lanBtnRow)
        contentColumn.addView(lanCard)

        // 4. Permanent 24/7 Background Permissions Card
        val permCard = createSectionCard(
            badgeIcon = "🛡️",
            badgeColorHex = "#F59E0B",
            titleEn = "Permanent 24/7 Background & Overlay Permissions",
            titleAr = "أذونات العمل الدائم في الخلفية والظهور فوق التطبيقات",
            infoEn = "Grant Battery Optimization exclusion so Android never kills MirrorBackgroundService, Appear on Top for floating incoming call alerts, and Notification Access to mirror WhatsApp/Telegram/Bank alerts.",
            infoAr = "فعّل استثناء البطارية لضمان عدم توقف الخدمة عند قفل الشاشة، وصلاحية الظهور فوق التطبيقات لإشعارات المكالمات العائمة، وصلاحية قراءة الإشعارات."
        )

        val batBtn = create3DTactileButton(
            text = t("🔋 Ignore Battery Optimization (24/7 Active)", "🔋 تفعيل استثناء البطارية (العمل بالخلفية 100%)"),
            faceColorHex = "#F59E0B",
            bevelColorHex = "#B45309"
        ) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                }
            } catch (_: Exception) {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            }
        }
        val overlayBtn = create3DTactileButton(
            text = t("🪟 Enable Appear on Top (Floating Call Banner)", "🪟 تفعيل الظهور فوق التطبيقات (شاشة المكالمات العائمة)"),
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1"
        ) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
            }
        }
        val notifAccBtn = create3DTactileButton(
            text = t("🔔 Grant App Notification Access (WhatsApp/Banks)", "🔔 تفعيل صلاحية قراءة إشعارات التطبيقات"),
            faceColorHex = "#EC4899",
            bevelColorHex = "#BE185D"
        ) {
            startActivity(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))
        }

        val btnMargin = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            setMargins(0, 0, 0, dp(8))
        }
        batBtn.layoutParams = btnMargin
        overlayBtn.layoutParams = btnMargin
        permCard.addView(batBtn)
        permCard.addView(overlayBtn)
        permCard.addView(notifAccBtn)
        contentColumn.addView(permCard)
    }

    // =====================================================================================
    // TAB 2: CALLS & AUDIO SOLUTIONS (EMERALD GREEN #10B981)
    // =====================================================================================

    private fun renderTab2Calls() {
        // 1. Target Number + Local Contacts + Host Contacts + Call Controls Card
        val callCard = createSectionCard(
            badgeIcon = "📞",
            badgeColorHex = "#10B981",
            titleEn = "Remote Call Control & Speakerphone Force",
            titleAr = "التحكم الكامل بالمكالمات وفتح السبيكر الخارجي",
            infoEn = "Dial any number on the SIM Host phone, pick from Local or Host Contacts, Answer incoming calls with triple-stage Speakerphone enforcement (Android 10-14+), Toggle Speaker anytime, or Reject with Busy SMS.",
            infoAr = "اتصل بأي رقم عبر الهاتف الأساسي، أو اختر اسماً من جهات اتصال هاتفك الحالي أو الهاتف الأساسي، أو رد مع فتح السبيكر الخارجي إجبارياً."
        )

        val numberInput = buildSynchronizedTargetNumberSection(callCard)

        // Call Action Buttons Grid
        val row1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(6), 0, 0) }
        val makeCallBtn = create3DTactileButton(
            text = t("📞 Make Call", "📞 إجراء اتصال"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857"
        ) {
            val num = numberInput.text.toString().trim()
            if (num.isEmpty()) {
                Toast.makeText(this, t("Enter or select a phone number first", "أدخل أو اختر رقماً أولاً"), Toast.LENGTH_SHORT).show()
                return@create3DTactileButton
            }
            val slot = StorageEngine.getSelectedSimSlot(this)
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.placeCallOnHost(num, slot, true)
            } else {
                MirrorBackgroundService.instance?.sendPacket("DIAL_CALL", JSONObject().apply {
                    put("number", num)
                    put("simSlot", slot)
                    put("speaker", true)
                })
                Toast.makeText(this, t("Dialing $num on SIM Host...", "جاري الاتصال بـ $num على الهاتف الأساسي..."), Toast.LENGTH_SHORT).show()
            }
        }

        val answerSpkBtn = create3DTactileButton(
            text = t("🔊 Answer + Force Speaker", "🔊 رد + فتح السبيكر"),
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1"
        ) {
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.answerRingingCallWithSpeakerFix(true)
            } else {
                MirrorBackgroundService.instance?.sendPacket("ANSWER_CALL", JSONObject().apply {
                    put("speaker", true)
                })
                Toast.makeText(this, t("Sent Answer + Force Speaker to Host!", "تم إرسال أمر الرد وفتح السبيكر للهاتف الأساسي!"), Toast.LENGTH_SHORT).show()
            }
        }
        makeCallBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        answerSpkBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        row1.addView(makeCallBtn)
        row1.addView(answerSpkBtn)
        callCard.addView(row1)

        val row2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
        val toggleSpkBtn = create3DTactileButton(
            text = t("🔈 Toggle Speaker", "🔈 تبديل السبيكر"),
            faceColorHex = "#F59E0B",
            bevelColorHex = "#B45309"
        ) {
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.toggleHostSpeakerphone()
            } else {
                MirrorBackgroundService.instance?.sendPacket("TOGGLE_SPEAKER")
                Toast.makeText(this, t("Toggled Host Speakerphone", "تم تبديل حالة السبيكر في الهاتف الأساسي"), Toast.LENGTH_SHORT).show()
            }
        }

        val endCallBtn = create3DTactileButton(
            text = t("⛔ End / Reject Call", "⛔ إنهاء / رفض"),
            faceColorHex = "#EF4444",
            bevelColorHex = "#B91C1C"
        ) {
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.endOrRejectCallOnHost()
            } else {
                MirrorBackgroundService.instance?.sendPacket("END_CALL")
                Toast.makeText(this, t("Sent End/Reject Call to Host", "تم إرسال إنهاء/رفض المكالمة"), Toast.LENGTH_SHORT).show()
            }
        }
        toggleSpkBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        endCallBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        row2.addView(toggleSpkBtn)
        row2.addView(endCallBtn)
        callCard.addView(row2)

        val busySmsBtn = create3DTactileButton(
            text = t("💬 Reject Call with Busy SMS", "💬 رفض المكالمة مع إرسال رسالة انشغال"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6"
        ) {
            val num = numberInput.text.toString().trim()
            val busyMsg = t("I am currently busy, I will call you back soon.", "أنا مشغول حالياً، سأتصل بك قريباً.")
            MirrorBackgroundService.instance?.sendPacket("REJECT_WITH_SMS", JSONObject().apply {
                put("number", num)
                put("message", busyMsg)
            })
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.endOrRejectCallOnHost()
                if (num.isNotBlank()) MirrorBackgroundService.instance?.sendSmsOnHost(num, busyMsg, StorageEngine.getSelectedSimSlot(this))
            }
            Toast.makeText(this, t("Rejected with Busy SMS", "تم رفض المكالمة وإرسال رسالة انشغال"), Toast.LENGTH_SHORT).show()
        }
        busySmsBtn.layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            setMargins(0, dp(8), 0, 0)
        }
        callCard.addView(busySmsBtn)
        contentColumn.addView(callCard)

        // 2. Live Audio Relay & Call Forwarding Solutions Card
        val audioCard = createSectionCard(
            badgeIcon = "🎙️",
            badgeColorHex = "#0EA5E9",
            titleEn = "Live Wi-Fi Audio Stream, Bluetooth HFP & Call Forwarding",
            titleAr = "نقل الصوت المباشر عبر الواي فاي والبلوتوث وتحويل المكالمات",
            infoEn = "Stream two-way PCM voice audio over Local Wi-Fi/Hotspot (ideal when Host speaker is on), route via Bluetooth HFP, or activate cellular Call Forwarding (*21* / ##21#) when traveling.",
            infoAr = "بث صوتي مباشر ثنائي الاتجاه عبر الواي فاي/الهوت سبوت بين الهاتفين، أو توجيه الصوت عبر البلوتوث، أو تفعيل تحويل المكالمات الخلوي (*21* و ##21#)."
        )

        val streamActive = MirrorHubBus.isAudioRelayActive
        val liveAudioBtn = create3DTactileButton(
            text = if (streamActive) {
                t("🛑 Stop Live Wi-Fi Audio Relay (Streaming ON)", "🛑 إيقاف البث الصوتي المباشر (نشط الآن)")
            } else {
                t("🎙️ Start Live Wi-Fi Audio Relay (Two-Way Mic/Speaker)", "🎙️ تشغيل البث الصوتي المباشر (ميكروفون وسماعة)")
            },
            faceColorHex = if (streamActive) "#EF4444" else "#0EA5E9",
            bevelColorHex = if (streamActive) "#B91C1C" else "#0369A1"
        ) {
            MirrorBackgroundService.instance?.toggleLiveAudioRelay()
        }
        audioCard.addView(liveAudioBtn)

        val btAndFwdRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
        val btHfpBtn = create3DTactileButton(
            text = t("🎧 Bluetooth HFP Audio", "🎧 صوت بلوتوث HFP"),
            faceColorHex = "#3B82F6",
            bevelColorHex = "#1D4ED8"
        ) {
            try {
                val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
                am.mode = AudioManager.MODE_IN_COMMUNICATION
                am.startBluetoothSco()
                am.isBluetoothScoOn = true
                Toast.makeText(this, t("Bluetooth SCO/HFP Audio Routed", "تم توجيه الصوت عبر بلوتوث HFP"), Toast.LENGTH_SHORT).show()
            } catch (_: Exception) {}
        }
        val fwdOnBtn = create3DTactileButton(
            text = t("↪️ Forward *21*", "↪️ تحويل *21*"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857"
        ) {
            val num = numberInput.text.toString().trim()
            if (num.isEmpty()) {
                Toast.makeText(this, t("Enter target forwarding number above", "أدخل الرقم المراد التحويل إليه في الخانة أعلاه"), Toast.LENGTH_SHORT).show()
            } else {
                val code = "*21*$num#"
                MirrorBackgroundService.instance?.sendPacket("DIAL_CALL", JSONObject().apply {
                    put("number", code)
                    put("simSlot", StorageEngine.getSelectedSimSlot(this@MainActivity))
                })
                Toast.makeText(this, t("Sent Call Forwarding $code", "تم إرسال كود تحويل المكالمات $code"), Toast.LENGTH_SHORT).show()
            }
        }
        val fwdOffBtn = create3DTactileButton(
            text = t("✖️ Cancel ##21#", "✖️ إلغاء ##21#"),
            faceColorHex = "#64748B",
            bevelColorHex = "#334155"
        ) {
            MirrorBackgroundService.instance?.sendPacket("DIAL_CALL", JSONObject().apply {
                put("number", "##21#")
                put("simSlot", StorageEngine.getSelectedSimSlot(this@MainActivity))
            })
            Toast.makeText(this, t("Sent Cancel Call Forwarding ##21#", "تم إرسال إلغاء تحويل المكالمات ##21#"), Toast.LENGTH_SHORT).show()
        }
        btHfpBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f).apply { setMargins(0, 0, dp(4), 0) }
        fwdOnBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(2), 0, dp(2), 0) }
        fwdOffBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        btAndFwdRow.addView(btHfpBtn)
        btAndFwdRow.addView(fwdOnBtn)
        btAndFwdRow.addView(fwdOffBtn)
        audioCard.addView(btAndFwdRow)
        contentColumn.addView(audioCard)

        // 3. Interactive DTMF Keypad Card
        val dtmfCard = createSectionCard(
            badgeIcon = "🔢",
            badgeColorHex = "#8B5CF6",
            titleEn = "Interactive DTMF Keypad (Customer Service / IVR)",
            titleAr = "لوحة أرقام تفاعلية للرد الآلي وخدمة العملاء (DTMF)",
            infoEn = "Tap keys to append digits to the number box and transmit live DTMF tones during active calls.",
            infoAr = "اضغط على الأرقام لكتابتها أو إرسال نغمات DTMF أثناء المكالمات الجارية مع خدمة العملاء."
        )

        val keys = arrayOf(
            arrayOf("1", "2", "3"),
            arrayOf("4", "5", "6"),
            arrayOf("7", "8", "9"),
            arrayOf("*", "0", "#")
        )
        for (rowKeys in keys) {
            val rLayout = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dp(3), 0, dp(3))
            }
            for (k in rowKeys) {
                val keyBtn = create3DTactileButton(
                    text = k,
                    faceColorHex = if (isDark) "#21262D" else "#E2E8F0",
                    bevelColorHex = if (isDark) "#0D1117" else "#94A3B8",
                    textColor = textPrimaryColor,
                    textSizeSp = 15f,
                    paddingV = dp(8)
                ) {
                    val cur = numberInput.text.toString() + k
                    numberInput.setText(cur)
                    StorageEngine.setTargetNumber(this, cur)
                    MirrorBackgroundService.instance?.sendPacket("SEND_DTMF", JSONObject().apply { put("digit", k) })
                }
                keyBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(dp(4), 0, dp(4), 0)
                }
                rLayout.addView(keyBtn)
            }
            dtmfCard.addView(rLayout)
        }
        contentColumn.addView(dtmfCard)

        // 4. Sync Host Call Logs Card (CRITICAL FIX #2)
        val syncLogsCard = createSectionCard(
            badgeIcon = "🔄",
            badgeColorHex = "#F59E0B",
            titleEn = "Host Call Logs (Remote Sync)",
            titleAr = "سجل مكالمات الهاتف الأساسي (مزامنة عن بُعد)",
            infoEn = "Fetches the Call Log directly from the SIM Host phone (never the local client log when in Remote Mode) and saves every call into Permanent History.",
            infoAr = "يجلب سجل المكالمات الفعلي الخاص بالهاتف الأساسي (SIM Host) عبر حزمة SYNC_CALL_LOG ويحفظه في السجل الدائم."
        )

        val fetchLogsBtn = create3DTactileButton(
            text = t("🔄 Fetch Host Call Logs Now", "🔄 جلب سجل مكالمات الهاتف الأساسي الآن"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857"
        ) {
            if (StorageEngine.isHostMode(this)) {
                val arr = MirrorBackgroundService.instance?.readHostCallLogsJson() ?: JSONArray()
                val list = mutableListOf<HistoryRecord>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(HistoryRecord(o.optString("id"), "CALL", o.optString("title"), o.optString("number"), o.optString("body"), o.optLong("ts")))
                }
                StorageEngine.addHistoryBatch(this, list)
                rebuildEntireScreen()
            } else {
                MirrorBackgroundService.instance?.sendPacket("SYNC_CALL_LOG")
                Toast.makeText(this, t("Requesting Call Logs from SIM Host...", "جاري طلب سجل المكالمات من الهاتف الأساسي..."), Toast.LENGTH_SHORT).show()
            }
        }
        syncLogsCard.addView(fetchLogsBtn)

        val callRecords = StorageEngine.loadHistory(this).filter { it.category == "CALL" }.take(20)
        callRecords.forEach { rec ->
            syncLogsCard.addView(buildInteractiveRecordCard(rec))
        }
        contentColumn.addView(syncLogsCard)
    }

    // =====================================================================================
    // SHARED TARGET NUMBER + LOCAL CONTACTS + HOST CONTACTS DIALOG (CRITICAL FIX #3)
    // =====================================================================================

    private fun buildSynchronizedTargetNumberSection(parentCard: LinearLayout): EditText {
        val numEdit = styleEditText(
            t("Target Phone Number (Synced across Calls & SMS)", "رقم الهاتف المستهدف (متزامن بين المكالمات والرسائل)"),
            StorageEngine.getTargetNumber(this)
        )
        numEdit.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                StorageEngine.setTargetNumber(this@MainActivity, s?.toString() ?: "")
            }
        })
        activeTargetNumberEdit = numEdit
        parentCard.addView(numEdit)

        val contactsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, dp(6))
        }

        // Button 1: Local Contacts Picker
        val localContactsBtn = create3DTactileButton(
            text = t("📱 Local Contacts", "📱 جهات اتصال هاتفي"),
            faceColorHex = "#3B82F6",
            bevelColorHex = "#1D4ED8",
            textSizeSp = 12f
        ) {
            try {
                val pickIntent = Intent(Intent.ACTION_PICK, ContactsContract.CommonDataKinds.Phone.CONTENT_URI)
                startActivityForResult(pickIntent, REQ_PICK_CONTACT)
            } catch (e: Exception) {
                Toast.makeText(this, t("Cannot open local contacts", "تعذر فتح جهات الاتصال المحلية"), Toast.LENGTH_SHORT).show()
            }
        }

        // Button 2: Host Contacts Interactive Search Dialog
        val hostContactsBtn = create3DTactileButton(
            text = t("☁️ Host Contacts", "☁️ جهات اتصال الأساسي"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6",
            textSizeSp = 12f
        ) {
            if (StorageEngine.isHostMode(this)) {
                val arr = MirrorBackgroundService.instance?.readHostContactsJson() ?: JSONArray()
                val list = mutableListOf<ContactItem>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(ContactItem(o.optString("name"), o.optString("number")))
                }
                MirrorHubBus.notifyHostContacts(list)
            } else {
                MirrorBackgroundService.instance?.sendPacket("SYNC_CONTACTS")
                if (MirrorHubBus.cachedHostContacts.isNotEmpty()) {
                    showHostContactsPickerDialog(MirrorHubBus.cachedHostContacts)
                } else {
                    Toast.makeText(
                        this,
                        t("Fetching Host Contacts... Dialog will open automatically!", "جاري جلب أسماء الهاتف الأساسي... ستفتح القائمة فوراً!"),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }

        localContactsBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        hostContactsBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        contactsRow.addView(localContactsBtn)
        contactsRow.addView(hostContactsBtn)
        parentCard.addView(contactsRow)

        return numEdit
    }

    private fun showHostContactsPickerDialog(contacts: List<ContactItem>) {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
            setBackgroundColor(bgCardColor)
        }

        val searchInput = styleEditText(t("🔍 Search Host Contacts by Name or Number...", "🔍 ابحث في أسماء وأرقام الهاتف الأساسي..."))
        dialogLayout.addView(searchInput)

        val listView = ListView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(340))
        }
        dialogLayout.addView(listView)

        val filtered = contacts.toMutableList()
        val adapter = object : BaseAdapter() {
            override fun getCount(): Int = filtered.size
            override fun getItem(position: Int): ContactItem = filtered[position]
            override fun getItemId(position: Int): Long = position.toLong()
            override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
                val item = filtered[position]
                return TextView(this@MainActivity).apply {
                    text = "👤 ${item.name}\n📞 ${item.number}"
                    setTextColor(textPrimaryColor)
                    textSize = 13.5f
                    setPadding(dp(10), dp(10), dp(10), dp(10))
                }
            }
        }
        listView.adapter = adapter

        val dialog = AlertDialog.Builder(this)
            .setTitle(t("☁️ Select Host Contact (${contacts.size})", "☁️ اختر من جهات اتصال الهاتف الأساسي (${contacts.size})"))
            .setView(dialogLayout)
            .setNegativeButton(t("Close", "إغلاق"), null)
            .create()

        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val q = s?.toString()?.trim()?.lowercase() ?: ""
                filtered.clear()
                if (q.isEmpty()) {
                    filtered.addAll(contacts)
                } else {
                    filtered.addAll(contacts.filter { it.name.lowercase().contains(q) || it.number.contains(q) })
                }
                adapter.notifyDataSetChanged()
            }
        })

        listView.setOnItemClickListener { _, _, position, _ ->
            val chosen = filtered[position]
            StorageEngine.setTargetNumber(this, chosen.number)
            activeTargetNumberEdit?.setText(chosen.number)
            Toast.makeText(this, t("Selected: ${chosen.name} (${chosen.number})", "تم اختيار: ${chosen.name} (${chosen.number})"), Toast.LENGTH_SHORT).show()
            dialog.dismiss()
        }

        dialog.show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_PICK_CONTACT && resultCode == RESULT_OK && data?.data != null) {
            try {
                contentResolver.query(
                    data.data!!,
                    arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER, ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME),
                    null,
                    null,
                    null
                )?.use { c ->
                    if (c.moveToFirst()) {
                        val num = c.getString(0)?.replace(" ", "")?.replace("-", "") ?: ""
                        val name = c.getString(1) ?: ""
                        StorageEngine.setTargetNumber(this, num)
                        activeTargetNumberEdit?.setText(num)
                        Toast.makeText(this, t("Picked Local Contact: $name ($num)", "تم اختيار: $name ($num)"), Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (_: Exception) {}
        }
    }

    // =====================================================================================
    // TAB 3: SMS, OTP & USSD (ROYAL PURPLE #8B5CF6)
    // =====================================================================================

    private fun renderTab3SmsAndUssd() {
        // 1. Smart OTP Banner Card
        val otpCard = createSectionCard(
            badgeIcon = "🔐",
            badgeColorHex = "#F59E0B",
            titleEn = "Smart Auto-OTP Capture Banner",
            titleAr = "شريط التقاط ونسخ أكواد التفعيل الذكي (Smart OTP)",
            infoEn = "Automatically detects 4-8 digit verification codes from incoming SMS or banking notifications, copies them to your clipboard, and lets you copy either the code alone or the full message.",
            infoAr = "يلتقط تلقائياً أي كود تفعيل (4 إلى 8 أرقام) من الرسائل النصية أو الإشعارات البنكية وينسخه للحافظة فوراً."
        )

        val currentOtp = MirrorHubBus.lastOtpCode.ifEmpty { "----" }
        val otpMsg = MirrorHubBus.lastOtpFullSms.ifEmpty { t("Waiting for new OTP SMS...", "بانتظار وصول رسالة كود تفعيل...") }

        val otpDisplay = TextView(this).apply {
            text = "🔑 OTP: $currentOtp\n📩 $otpMsg"
            setTextColor(textPrimaryColor)
            textSize = 13.5f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            setTextIsSelectable(true)
            background = GradientDrawable().apply {
                setColor(bgElevatedColor)
                cornerRadius = dp(10).toFloat()
            }
        }
        otpCard.addView(otpDisplay)

        val otpBtnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
        val copyCodeBtn = create3DTactileButton(
            text = t("🔢 Copy OTP Only", "🔢 نسخ الكود فقط"),
            faceColorHex = "#F59E0B",
            bevelColorHex = "#B45309"
        ) {
            copyTextWithToast("OTP", currentOtp)
        }
        val copyFullSmsBtn = create3DTactileButton(
            text = t("📄 Copy Full SMS", "📄 نسخ الرسالة كاملة"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6"
        ) {
            copyTextWithToast("SMS", otpMsg)
        }
        copyCodeBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        copyFullSmsBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        otpBtnRow.addView(copyCodeBtn)
        otpBtnRow.addView(copyFullSmsBtn)
        otpCard.addView(otpBtnRow)
        contentColumn.addView(otpCard)

        // 2. Dual SIM Selector + Send SMS via Host Card
        val smsCard = createSectionCard(
            badgeIcon = "📩",
            badgeColorHex = "#8B5CF6",
            titleEn = "Dual SIM Selector & Remote SMS Sender",
            titleAr = "اختيار الشريحة (SIM 1 / SIM 2) وإرسال رسالة نصية",
            infoEn = "Select SIM 1 or SIM 2 on the Host phone, pick a recipient from Local or Host Contacts, and send SMS directly through the SIM Host carrier.",
            infoAr = "اختر الشريحة (SIM 1 أو SIM 2)، وحدد رقم المستلم من جهات اتصال هاتفك أو الهاتف الأساسي، وأرسل الرسالة النصية عن بُعد."
        )

        val activeSlot = StorageEngine.getSelectedSimSlot(this)
        val simRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, 0, 0, dp(8)) }
        val sim1Btn = create3DTactileButton(
            text = "💳 SIM 1",
            faceColorHex = if (activeSlot == 0) "#8B5CF6" else "#334155",
            bevelColorHex = if (activeSlot == 0) "#5B21B6" else "#1E293B"
        ) {
            StorageEngine.setSelectedSimSlot(this, 0)
            MirrorBackgroundService.instance?.broadcastBatteryAndSimStatus()
            rebuildEntireScreen()
        }
        val sim2Btn = create3DTactileButton(
            text = "💳 SIM 2",
            faceColorHex = if (activeSlot == 1) "#0EA5E9" else "#334155",
            bevelColorHex = if (activeSlot == 1) "#0369A1" else "#1E293B"
        ) {
            StorageEngine.setSelectedSimSlot(this, 1)
            MirrorBackgroundService.instance?.broadcastBatteryAndSimStatus()
            rebuildEntireScreen()
        }
        sim1Btn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(0, 0, dp(4), 0) }
        sim2Btn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(4), 0, 0, 0) }
        simRow.addView(sim1Btn)
        simRow.addView(sim2Btn)
        smsCard.addView(simRow)

        // Synchronized Target Number + Local/Host Contacts Picker
        val smsTargetNumberEdit = buildSynchronizedTargetNumberSection(smsCard)
        val smsBodyEdit = styleEditText(t("Write SMS message content here...", "اكتب نص الرسالة النصية هنا...")).apply {
            minLines = 3
            gravity = Gravity.TOP or Gravity.START
        }
        smsCard.addView(smsBodyEdit)

        val sendSmsBtn = create3DTactileButton(
            text = t("📩 Send SMS via Host (SIM ${activeSlot + 1})", "📩 إرسال الرسالة عبر الهاتف الأساسي (SIM ${activeSlot + 1})"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6"
        ) {
            val num = smsTargetNumberEdit.text.toString().trim()
            val body = smsBodyEdit.text.toString().trim()
            if (num.isEmpty() || body.isEmpty()) {
                Toast.makeText(this, t("Enter recipient number and SMS text", "أدخل رقم المستلم ونص الرسالة"), Toast.LENGTH_SHORT).show()
                return@create3DTactileButton
            }
            if (StorageEngine.isHostMode(this)) {
                MirrorBackgroundService.instance?.sendSmsOnHost(num, body, activeSlot)
            } else {
                MirrorBackgroundService.instance?.sendPacket("SEND_SMS", JSONObject().apply {
                    put("number", num)
                    put("body", body)
                    put("simSlot", activeSlot)
                })
                Toast.makeText(this, t("SMS command sent to Host ($num)", "تم إرسال أمر الرسالة إلى الهاتف الأساسي ($num)"), Toast.LENGTH_SHORT).show()
            }
            smsBodyEdit.setText("")
        }
        smsCard.addView(sendSmsBtn)
        contentColumn.addView(smsCard)

        // 3. USSD Network Code Runner Card
        val ussdCard = createSectionCard(
            badgeIcon = "#️⃣",
            badgeColorHex = "#0EA5E9",
            titleEn = "Remote USSD Code Runner (*100#, Balance, Bundles)",
            titleAr = "مشغل أكواد الشبكة عن بُعد (USSD والرصيد والباقات)",
            infoEn = "Execute carrier USSD codes on the SIM Host phone remotely and read the carrier popup response right here.",
            infoAr = "نفّذ أكواد الشبكة (مثل الاستعلام عن الرصيد أو تجديد الباقة أو معرفة الرقم) على شريحة الهاتف الأساسي واقرأ رد الشبكة فوراً."
        )

        val ussdInput = styleEditText(t("USSD Code (e.g. *100# or *868#)", "كود الشبكة USSD (مثال *100#)"), "*100#")
        ussdCard.addView(ussdInput)

        val quickUssdRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, 0, 0, dp(8)) }
        val presets = listOf(
            Pair(t("💰 Balance", "💰 الرصيد"), "*100#"),
            Pair(t("📦 Bundle", "📦 الباقة"), "*888#"),
            Pair(t("📱 My Number", "📱 رقم الخط"), "*878#")
        )
        for (p in presets) {
            val qBtn = create3DTactileButton(
                text = p.first,
                faceColorHex = "#334155",
                bevelColorHex = "#1E293B",
                textSizeSp = 11.5f
            ) {
                ussdInput.setText(p.second)
            }
            qBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(2), 0, dp(2), 0) }
            quickUssdRow.addView(qBtn)
        }
        ussdCard.addView(quickUssdRow)

        val runUssdBtn = create3DTactileButton(
            text = t("⚡ Run USSD Code on Host", "⚡ تنفيذ كود الشبكة USSD"),
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1"
        ) {
            val code = ussdInput.text.toString().trim()
            if (code.isNotEmpty()) {
                if (StorageEngine.isHostMode(this)) {
                    MirrorBackgroundService.instance?.executeUssdOnHost(code, activeSlot)
                } else {
                    MirrorBackgroundService.instance?.sendPacket("RUN_USSD", JSONObject().apply {
                        put("code", code)
                        put("simSlot", activeSlot)
                    })
                }
                ussdResultTextView?.text = t("Running USSD $code on Host...", "جاري تنفيذ الكود $code على الهاتف الأساسي...")
            }
        }
        ussdCard.addView(runUssdBtn)

        ussdResultTextView = TextView(this).apply {
            text = MirrorHubBus.lastUssdResult.ifEmpty { t("USSD Network Response will appear here (Selectable & Copyable).", "سيظهر رد الشبكة هنا مع إمكانية التحديد والنسخ.") }
            setTextColor(textPrimaryColor)
            textSize = 13f
            setPadding(dp(10), dp(10), dp(10), dp(10))
            setTextIsSelectable(true)
        }
        ussdCard.addView(ussdResultTextView)
        contentColumn.addView(ussdCard)

        // 4. Sync Host SMS Inbox Card
        val inboxCard = createSectionCard(
            badgeIcon = "📥",
            badgeColorHex = "#10B981",
            titleEn = "Host SMS Inbox & Recent Messages",
            titleAr = "صندوق رسائل الهاتف الأساسي (SMS Inbox)",
            infoEn = "Fetches all recent SMS messages stored on the SIM Host phone and saves them permanently.",
            infoAr = "يجلب أحدث الرسائل النصية من صندوق وارد الهاتف الأساسي ويعرضها مع أزرار النسخ السريع."
        )

        val syncSmsBtn = create3DTactileButton(
            text = t("🔄 Fetch Host SMS Inbox Now", "🔄 جلب رسائل الهاتف الأساسي الآن"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857"
        ) {
            if (StorageEngine.isHostMode(this)) {
                val arr = MirrorBackgroundService.instance?.readHostSmsInboxJson() ?: JSONArray()
                val list = mutableListOf<HistoryRecord>()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(HistoryRecord(o.optString("id"), "SMS", "SMS: ${o.optString("sender")}", o.optString("sender"), o.optString("body"), o.optLong("ts")))
                }
                StorageEngine.addHistoryBatch(this, list)
                rebuildEntireScreen()
            } else {
                MirrorBackgroundService.instance?.sendPacket("SYNC_SMS_INBOX")
                Toast.makeText(this, t("Requesting SMS Inbox from Host...", "جاري طلب صندوق الرسائل من الهاتف الأساسي..."), Toast.LENGTH_SHORT).show()
            }
        }
        inboxCard.addView(syncSmsBtn)

        val smsRecords = StorageEngine.loadHistory(this).filter { it.category == "SMS" || it.category == "USSD" }.take(20)
        smsRecords.forEach { rec ->
            inboxCard.addView(buildInteractiveRecordCard(rec))
        }
        contentColumn.addView(inboxCard)
    }

    // =====================================================================================
    // TAB 4: APP ALERTS / NOTIFICATIONS (RUBY PINK #EC4899)
    // =====================================================================================

    private fun renderTab4AppAlerts() {
        val alertCard = createSectionCard(
            badgeIcon = "🔔",
            badgeColorHex = "#EC4899",
            titleEn = "Remote App Notifications (WhatsApp, Telegram, Banks)",
            titleAr = "إشعارات تطبيقات الهاتف الأساسي (واتساب، تلغرام، البنوك)",
            infoEn = "Captures real-time notifications from WhatsApp, Telegram, Banking apps, and Email on the SIM Host via NotificationListenerService and forwards them immediately.",
            infoAr = "يلتقط إشعارات التطبيقات من الهاتف الأساسي (مثل واتساب وتلغرام وتطبيقات البنوك) ويرسلها فوراً للهاتف الفرعي."
        )

        // 3D Filter Buttons: All | Chats | Banks & OTP
        val filterRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, 0, 0, dp(8)) }
        val filters = listOf(
            Pair("ALL", t("🌐 All", "🌐 الكل")),
            Pair("CHATS", t("💬 Chats", "💬 المحادثات")),
            Pair("BANKS", t("🏦 Banks & OTP", "🏦 البنوك والأكواد"))
        )
        for (f in filters) {
            val active = (activeAlertFilter == f.first)
            val fBtn = create3DTactileButton(
                text = f.second,
                faceColorHex = if (active) "#EC4899" else "#334155",
                bevelColorHex = if (active) "#BE185D" else "#1E293B",
                textSizeSp = 11.5f
            ) {
                activeAlertFilter = f.first
                rebuildEntireScreen()
            }
            fBtn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(2), 0, dp(2), 0) }
            filterRow.addView(fBtn)
        }
        alertCard.addView(filterRow)

        val syncAlertsBtn = create3DTactileButton(
            text = t("🔄 Fetch Recent App Notifications", "🔄 جلب أحدث إشعارات التطبيقات"),
            faceColorHex = "#EC4899",
            bevelColorHex = "#BE185D"
        ) {
            MirrorBackgroundService.instance?.sendPacket("SYNC_RECENT_ALERTS")
            Toast.makeText(this, t("Syncing recent app notifications...", "جاري مزامنة إشعارات التطبيقات..."), Toast.LENGTH_SHORT).show()
        }
        alertCard.addView(syncAlertsBtn)

        val allAlerts = StorageEngine.loadHistory(this).filter { it.category == "ALERT" }
        val filteredAlerts = allAlerts.filter { rec ->
            when (activeAlertFilter) {
                "CHATS" -> rec.title.contains("WhatsApp", true) || rec.title.contains("Telegram", true) || rec.title.contains("Chat", true)
                "BANKS" -> rec.title.contains("Bank", true) || rec.body.contains("OTP", true) || CryptoAndParserEngine.extractOtpOrDigits(rec.body).length in 4..8
                else -> true
            }
        }

        if (filteredAlerts.isEmpty()) {
            val emptyTv = TextView(this).apply {
                text = t("No notifications in this filter yet.", "لا توجد إشعارات في هذا التصنيف حالياً.")
                setTextColor(textSecondaryColor)
                setPadding(dp(8), dp(14), dp(8), dp(8))
            }
            alertCard.addView(emptyTv)
        } else {
            filteredAlerts.take(35).forEach { rec ->
                alertCard.addView(buildInteractiveRecordCard(rec))
            }
        }
        contentColumn.addView(alertCard)
    }

    // =====================================================================================
    // TAB 5: PERMANENT HISTORY & PROTECTED DELETION (GOLDEN AMBER #F59E0B)
    // =====================================================================================

    private fun renderTab5PermanentHistory() {
        val allHistory = StorageEngine.loadHistory(this)
        val historyCard = createSectionCard(
            badgeIcon = "🗂️",
            badgeColorHex = "#F59E0B",
            titleEn = "Permanent Vault History (${allHistory.size} Saved Items)",
            titleAr = "السجل المحفوظ الدائم (${allHistory.size} عنصر محفوظ)",
            infoEn = "Stores all synced Calls, SMS messages, USSD responses, and App Notifications permanently without duplicates. Protected Deletion Rule: The latest 15 items are strictly protected from deletion.",
            infoAr = "يحتفظ بجميع المكالمات والرسائل وإشعارات التطبيقات بشكل دائم بدون تكرار. قاعدة الحذف المحمي: آخر 15 عنصراً محميون دائماً ولا يمكن مسحهم."
        )

        val clearProtectedBtn = create3DTactileButton(
            text = t("🗑️ Clear Old History (Strictly Keep Last 15)", "🗑️ مسح السجل القديم (الاحتفاظ بآخر 15 إجبارياً)"),
            faceColorHex = "#EF4444",
            bevelColorHex = "#991B1B"
        ) {
            val removed = StorageEngine.clearAllKeepLast15(this)
            if (removed == 0) {
                Toast.makeText(
                    this,
                    t("🛡️ Protected Rule: Total items are 15 or fewer. Last 15 items cannot be deleted!", "🛡️ حماية السجل: إجمالي العناصر 15 أو أقل. آخر 15 عنصراً محميون من الحذف!"),
                    Toast.LENGTH_LONG
                ).show()
            } else {
                Toast.makeText(
                    this,
                    t("Cleared $removed old items. Kept latest 15 protected items!", "تم مسح $removed عنصر قديم والاحتفاظ بآخر 15 عنصراً محمياً!"),
                    Toast.LENGTH_LONG
                ).show()
                rebuildEntireScreen()
            }
        }
        historyCard.addView(clearProtectedBtn)

        allHistory.forEach { rec ->
            historyCard.addView(buildInteractiveRecordCard(rec))
        }
        contentColumn.addView(historyCard)
    }

    // =====================================================================================
    // INTERACTIVE RECORD CARD (FREE TEXT SELECTION + 4 ACTION BUTTONS + PROTECTED DELETE)
    // =====================================================================================

    private fun buildInteractiveRecordCard(rec: HistoryRecord): View {
        val itemBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = GradientDrawable().apply {
                setColor(bgElevatedColor)
                cornerRadius = dp(12).toFloat()
                setStroke(dp(1), borderColor)
            }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, dp(8), 0, 0)
            }
        }

        val timeFmt = SimpleDateFormat("dd/MM HH:mm:ss", Locale.getDefault()).format(Date(rec.timestamp))
        val badgeEmoji = when (rec.category) {
            "CALL" -> "📞"
            "SMS" -> "💬"
            "USSD" -> "#️⃣"
            else -> "🔔"
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val headerTv = TextView(this).apply {
            text = "$badgeEmoji ${rec.title}  •  $timeFmt"
            setTextColor(textPrimaryColor)
            textSize = 13f
            setTypeface(typeface, Typeface.BOLD)
            setTextIsSelectable(true)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }

        // Individual Delete Button with Protected Last-15 Enforcement
        val delBtn = create3DTactileButton(
            text = "🗑️",
            faceColorHex = "#475569",
            bevelColorHex = "#1E293B",
            textSizeSp = 11f,
            paddingH = dp(8),
            paddingV = dp(4)
        ) {
            val deleted = StorageEngine.deleteSingleRecordProtected(this, rec.id)
            if (!deleted) {
                Toast.makeText(
                    this,
                    t("🛡️ Protected: Cannot delete when 15 or fewer items remain!", "🛡️ عنصر محمي: لا يمكن الحذف لأن آخر 15 عنصراً محميون دائماً!"),
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                rebuildEntireScreen()
            }
        }

        topRow.addView(headerTv)
        topRow.addView(delBtn)
        itemBox.addView(topRow)

        val bodyTv = TextView(this).apply {
            text = rec.body
            setTextColor(textSecondaryColor)
            textSize = 13f
            setPadding(0, dp(4), 0, dp(8))
            setTextIsSelectable(true) // Free finger selection enabled everywhere
        }
        itemBox.addView(bodyTv)

        // 4 Mini 3D Action Buttons underneath every item:
        // [📋 Copy Number] [📄 Copy Text] [🔢 Copy Code] [📞 Use Number]
        val actionsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }

        val btnCopyNum = create3DTactileButton(
            text = t("📋 Copy Num", "📋 نسخ الرقم"),
            faceColorHex = "#0EA5E9",
            bevelColorHex = "#0369A1",
            textSizeSp = 10f,
            paddingH = dp(4),
            paddingV = dp(6)
        ) {
            copyTextWithToast("Number", rec.numberOrPkg)
        }

        val btnCopyText = create3DTactileButton(
            text = t("📄 Copy Text", "📄 نسخ النص"),
            faceColorHex = "#8B5CF6",
            bevelColorHex = "#5B21B6",
            textSizeSp = 10f,
            paddingH = dp(4),
            paddingV = dp(6)
        ) {
            copyTextWithToast("Text", rec.body)
        }

        val btnCopyCode = create3DTactileButton(
            text = t("🔢 Copy Code", "🔢 نسخ الكود"),
            faceColorHex = "#F59E0B",
            bevelColorHex = "#B45309",
            textSizeSp = 10f,
            paddingH = dp(4),
            paddingV = dp(6)
        ) {
            val extracted = CryptoAndParserEngine.extractOtpOrDigits(rec.body).ifEmpty { rec.numberOrPkg }
            copyTextWithToast("Code", extracted)
        }

        val btnUseNum = create3DTactileButton(
            text = t("📞 Use Num", "📞 استخدام الرقم"),
            faceColorHex = "#10B981",
            bevelColorHex = "#047857",
            textSizeSp = 10f,
            paddingH = dp(4),
            paddingV = dp(6)
        ) {
            StorageEngine.setTargetNumber(this, rec.numberOrPkg)
            activeTargetNumberEdit?.setText(rec.numberOrPkg)
            Toast.makeText(
                this,
                t("Placed ${rec.numberOrPkg} in Call & SMS box!", "تم وضع الرقم ${rec.numberOrPkg} في خانة الاتصال والرسائل!"),
                Toast.LENGTH_SHORT
            ).show()
        }

        val lp = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            setMargins(dp(2), 0, dp(2), 0)
        }
        btnCopyNum.layoutParams = lp
        btnCopyText.layoutParams = lp
        btnCopyCode.layoutParams = lp
        btnUseNum.layoutParams = lp

        actionsRow.addView(btnCopyNum)
        actionsRow.addView(btnCopyText)
        actionsRow.addView(btnCopyCode)
        actionsRow.addView(btnUseNum)
        itemBox.addView(actionsRow)

        return itemBox
    }

    private fun copyTextWithToast(label: String, value: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, t("Copied: $value", "تم النسخ: $value"), Toast.LENGTH_SHORT).show()
    }

    private fun requestNecessaryPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val perms = mutableListOf(
                Manifest.permission.CALL_PHONE,
                Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.SEND_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.READ_SMS,
                Manifest.permission.RECORD_AUDIO
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                perms.add(Manifest.permission.ANSWER_PHONE_CALLS)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                perms.add(Manifest.permission.BLUETOOTH_CONNECT)
                perms.add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                perms.add(Manifest.permission.POST_NOTIFICATIONS)
            }
            val missing = perms.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
            if (missing.isNotEmpty()) {
                requestPermissions(missing.toTypedArray(), REQ_PERMISSIONS)
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // EVENT BUS CALLBACKS
    // -------------------------------------------------------------------------------------

    override fun onConnectionStateChanged(state: Int, detail: String) {
        updateLedIndicator(state, detail)
    }

    override fun onBatteryOrSimUpdated(batteryPct: Int, isCharging: Boolean, activeSimLabel: String) {
        val roleBadge = if (StorageEngine.isHostMode(this)) {
            t("📡 Mode: SIM HOST", "📡 الوضع: الهاتف الأساسي (SIM Host)")
        } else {
            t("📱 Mode: REMOTE CLIENT", "📱 الوضع: الهاتف الفرعي (Remote)")
        }
        val chgIcon = if (isCharging) "⚡" else "🔋"
        batterySimTextView.text = "$roleBadge  •  $chgIcon $batteryPct%  •  💳 $activeSimLabel"
    }

    override fun onOtpCaptured(otpCode: String, fullMessage: String, sender: String) {
        Toast.makeText(this, t("🔑 Auto-Copied OTP: $otpCode", "🔑 تم نسخ كود التفعيل تلقائياً: $otpCode"), Toast.LENGTH_LONG).show()
        if (activeTabIndex == 2 || activeTabIndex == 4) {
            renderActiveTabContent()
        }
    }

    override fun onHistoryUpdated() {
        if (activeTabIndex in listOf(1, 2, 3, 4)) {
            renderActiveTabContent()
        }
    }

    override fun onHostContactsReceived(contacts: List<ContactItem>) {
        showHostContactsPickerDialog(contacts)
    }

    override fun onUssdResponseReceived(response: String) {
        ussdResultTextView?.text = response
    }

    override fun onConnectedDevicesPingResult(devices: List<String>) {
        connectedDevicesTextView?.text = "🖧 " + devices.joinToString("  |  ")
    }

    override fun onAudioStreamStateChanged(isStreaming: Boolean) {
        if (activeTabIndex == 1) renderActiveTabContent()
    }

    override fun onToastMessage(msgEn: String, msgAr: String) {
        Toast.makeText(this, t(msgEn, msgAr), Toast.LENGTH_SHORT).show()
    }
}
