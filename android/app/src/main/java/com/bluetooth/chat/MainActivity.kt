package com.bluetooth.chat

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.util.UUID

class MainActivity : AppCompatActivity() {

    companion object {
        val CHAT_SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
        val CHAT_RX_CHAR_UUID: UUID = UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
        val CHAT_TX_CHAR_UUID: UUID = UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var gatt: BluetoothGatt? = null
    private var rxChar: BluetoothGattCharacteristic? = null
    private var txChar: BluetoothGattCharacteristic? = null

    private val discoveredDevices = linkedMapOf<String, BluetoothDevice>()
    private val assembler = FrameAssembler()
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var statusText: TextView
    private lateinit var keyInput: EditText
    private lateinit var encryptSwitch: CheckBox
    private lateinit var deviceListLayout: LinearLayout
    private lateinit var logView: TextView
    private lateinit var msgInput: EditText
    private lateinit var sendBtn: Button
    private lateinit var scanBtn: Button

    private val permLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.all { it }) {
            startBleScan()
        } else {
            appendLog("Sistem: Bluetooth izinleri verilmedi.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val manager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = manager.adapter

        buildUi()
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
            setBackgroundColor(Color.parseColor("#0F172A"))
        }

        val title = TextView(this).apply {
            text = "Bluetooth Chat (Android)"
            textSize = 20f
            setTextColor(Color.WHITE)
        }
        statusText = TextView(this).apply {
            text = "Bağlı cihaz yok"
            textSize = 13f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        encryptSwitch = CheckBox(this).apply {
            text = "AES-256-GCM Şifreli"
            isChecked = true
            setTextColor(Color.WHITE)
        }
        keyInput = EditText(this).apply {
            hint = "PC Oturum Anahtarı (64 hex)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#64748B"))
            textSize = 12f
        }
        scanBtn = Button(this).apply {
            text = "BLE Cihazlarını Tara"
            setOnClickListener { ensurePermissionsAndScan() }
        }
        deviceListLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        val deviceScroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 260
            )
            addView(deviceListLayout)
        }

        logView = TextView(this).apply {
            text = "Hazır. PC'de 'Yayın Başlat (Peripheral)' butonuna basın.\n"
            setTextColor(Color.parseColor("#E2E8F0"))
            textSize = 14f
        }
        val logScroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
            )
            addView(logView)
        }

        val inputRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        msgInput = EditText(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            hint = "Mesaj yazın..."
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#64748B"))
        }
        sendBtn = Button(this).apply {
            text = "Gönder"
            isEnabled = false
            setOnClickListener { sendCurrentMessage() }
        }
        inputRow.addView(msgInput)
        inputRow.addView(sendBtn)

        root.addView(title)
        root.addView(statusText)
        root.addView(encryptSwitch)
        root.addView(keyInput)
        root.addView(scanBtn)
        root.addView(deviceScroll)
        root.addView(logScroll)
        root.addView(inputRow)
        setContentView(root)
    }

    private fun requiredPermissions(): Array<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun ensurePermissionsAndScan() {
        val missing = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            startBleScan()
        } else {
            permLauncher.launch(missing.toTypedArray())
        }
    }

    @SuppressLint("MissingPermission")
    private fun startBleScan() {
        val scanner = bluetoothAdapter?.bluetoothLeScanner
        if (scanner == null) {
            appendLog("Hata: Bluetooth kapalı veya desteklenmiyor.")
            return
        }
        discoveredDevices.clear()
        deviceListLayout.removeAllViews()
        scanBtn.isEnabled = false
        scanBtn.text = "Taranıyor (4s)..."

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val dev = result.device ?: return
                if (!discoveredDevices.containsKey(dev.address)) {
                    discoveredDevices[dev.address] = dev
                    val label = "${dev.name ?: "İsimsiz BLE"} (${dev.address})"
                    mainHandler.post {
                        val btn = Button(this@MainActivity).apply {
                            text = label
                            setOnClickListener {
                                scanner.stopScan(this@MainActivity.activeScanCallback)
                                connectToDevice(dev)
                            }
                        }
                        deviceListLayout.addView(btn)
                    }
                }
            }
        }
        activeScanCallback = callback
        scanner.startScan(callback)
        mainHandler.postDelayed({
            try { scanner.stopScan(callback) } catch (_: Exception) {}
            scanBtn.isEnabled = true
            scanBtn.text = "BLE Cihazlarını Tara"
        }, 4000)
    }

    private var activeScanCallback: ScanCallback? = null

    @SuppressLint("MissingPermission")
    private fun connectToDevice(device: BluetoothDevice) {
        statusText.text = "Bağlanılıyor: ${device.address}..."
        gatt?.close()
        gatt = device.connectGatt(this, false, object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    mainHandler.post { statusText.text = "Bağlı (${device.address}), servisler aranıyor..." }
                    g.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    mainHandler.post {
                        statusText.text = "Bağlantı kesildi"
                        sendBtn.isEnabled = false
                    }
                }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                val chatService = g.getService(CHAT_SERVICE_UUID)
                rxChar = chatService?.getCharacteristic(CHAT_RX_CHAR_UUID)
                txChar = chatService?.getCharacteristic(CHAT_TX_CHAR_UUID)

                if (rxChar == null) {
                    // Fallback: any writable characteristic
                    for (svc in g.services) {
                        for (ch in svc.characteristics) {
                            val props = ch.properties
                            if (rxChar == null && (props and (BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)) != 0) {
                                rxChar = ch
                            }
                            if (txChar == null && (props and BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0) {
                                txChar = ch
                            }
                        }
                    }
                }

                txChar?.let { tx ->
                    g.setCharacteristicNotification(tx, true)
                    tx.getDescriptor(CCCD_UUID)?.let { desc ->
                        desc.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        g.writeDescriptor(desc)
                    }
                }

                mainHandler.post {
                    if (rxChar != null) {
                        statusText.text = "Bağlı ve sohbete hazır: ${device.address}"
                        sendBtn.isEnabled = true
                        appendLog("Sistem: GATT servisine bağlanıldı.")
                    } else {
                        statusText.text = "Yazılabilir karakteristik bulunamadı"
                    }
                }
            }

            override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic) {
                val chunk = ch.value ?: return
                val full = assembler.pushChunk(chunk) ?: return
                val text = try {
                    if (encryptSwitch.isChecked) {
                        val key = CryptoAndFraming.hexToBytes32(keyInput.text.toString())
                        String(CryptoAndFraming.decryptAesGcm(key, full), Charsets.UTF_8)
                    } else {
                        String(full, Charsets.UTF_8)
                    }
                } catch (e: Exception) {
                    "[Çözme hatası: ${e.message}]"
                }
                mainHandler.post { appendLog("Karşı: $text") }
            }
        })
    }

    @SuppressLint("MissingPermission")
    private fun sendCurrentMessage() {
        val text = msgInput.text.toString().trim()
        val target = rxChar ?: return
        val g = gatt ?: return
        if (text.isEmpty()) return

        try {
            val payload = if (encryptSwitch.isChecked) {
                val key = CryptoAndFraming.hexToBytes32(keyInput.text.toString())
                CryptoAndFraming.encryptAesGcm(key, text.toByteArray(Charsets.UTF_8))
            } else {
                text.toByteArray(Charsets.UTF_8)
            }

            val frames = CryptoAndFraming.chunkMessage(payload, 20)
            Thread {
                for (frame in frames) {
                    target.value = frame
                    g.writeCharacteristic(target)
                    Thread.sleep(30)
                }
            }.start()

            msgInput.setText("")
            appendLog("Ben: $text")
        } catch (e: Exception) {
            appendLog("Gönderme hatası: ${e.message}")
        }
    }

    private fun appendLog(line: String) {
        logView.append("$line\n")
    }
}
