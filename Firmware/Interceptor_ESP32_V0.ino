// ============================================================================
// ESP32 Wi-Fi Promiscuous Sniffer (Interceptor_ESP32_V1)
// ----------------------------------------------------------------------------
// Board   : ESP32 (Arduino core)
// Author  : Jean-Martial MARI
// Affil.  : Université de la Polynésie française (UPF)
// Year    : 2025
// License : MIT (see LICENSE file in repository)
//
// Description:
//   Advanced Wi-Fi frame sniffer for ESP32 using the native promiscuous mode.
//   Designed for research and educational use.
//
//   This firmware captures raw 802.11 frames (Management, Control, Data, Misc)
//   and streams them over serial as compact JSON lines compatible with the
//   Python viewer `serial_probe_viewer.py`.
//
//   The capture engine runs in two parts:
//     - **ISR callback** (promisc_cb): ultra-light, just copies the frame header
//       and pushes it to a FreeRTOS queue.
//     - **Worker task** (processorTask): parses the frame, extracts metadata,
//       and prints it as JSON or logs it to LittleFS.
//
// Main features:
//   • Real-time JSON output for Python visualization
//   • Optional binary logging to LittleFS (/capture.bin)
//   • Channel hopping across 2.4 GHz (configurable or manual)
//   • Dynamic filter configuration (MGMT / DATA / CTRL / MISC)
//   • Command interface via serial terminal
//   • Safe concurrent tasks (FreeRTOS + queues + semaphores)
//
// -----------------------------------------------------------------------------
// Default configuration:
//   MONITOR_CHANNEL   = 6
//   BAUD RATE         = 921600
//   MAX FILE SIZE     = 2 MB (LittleFS)
//   HOP DELAY         = 350 ms (default)
//   FILTER            = all except DATA
//
// -----------------------------------------------------------------------------
// Serial Commands (case-insensitive):
//
//   🛰 Channel control
//     HOP ON | HOP OFF             → Enable/disable channel hopping
//     SET CH 1,6,11 | SET CH ALL   → Define active channels
//     CLEAR CH 6 | CLEAR CH ALL    → Remove one or all channels
//     SET HOP_MS <ms>              → Change hop interval (min 50 ms)
//
//   🧩 Logging
//     LOG ON | LOG OFF             → Toggle JSON serial output
//     LOG FILE ON | OFF            → Record raw frames to LittleFS (/capture.bin)
//     LOG FILE MODE RING | STOP    → Overwrite or stop when full
//     LOG FILE STATUS              → Show file size and limits
//     LOG FILE CLEAR               → Delete capture.bin
//
//   💾 Export / Filesystem
//     DUMP FILE JSON               → Re-export capture.bin as JSON
//     DUMP FILE BIN                → Base64 binary dump
//     FORMAT FS                    → Format LittleFS partition
//
//   📡 Frame filtering
//     SET TYPE MGMT | DATA | CTRL | MISC | ALL
//     CLEAR TYPE MGMT | DATA | CTRL | MISC | ALL
//     SHOW TYPES                   → Display active filters
//
//   ⚙️ Utility
//     SHOW                         → Display current hop settings and status
//     HELP                         → Print command list
//
// -----------------------------------------------------------------------------
// Output format (JSON line example):
//
//   {
//     "ts": 3478746,
//     "ch": 1,
//     "rssi": -73,
//     "type": "Data",
//     "subtype": "Data",
//     "len": 314,
//     "addr1": "42:ED:00:CF:D5:5B",
//     "addr2": "50:E6:36:4A:7A:8F",
//     "addr3": "50:E6:36:4A:7A:8D",
//     "flags": {"toDS":0,"fromDS":1,"retry":1,"protected":1},
//     "ssid": "",
//     "vendor": "0050F2,001B63"
//   }
//
// -----------------------------------------------------------------------------
// Integration with Python tools:
//
//   • `serial_probe_viewer.py` → Live colored table viewer with filters
//   • `acquireWiFiDetections.py` → Continuous capture + JSON logging
//   • `displayWiFiCaptures.py` → Offline replay / display mode
//
// Example usage:
//   - Open Arduino Serial Monitor or use `python serial_probe_viewer.py COM4 921600`
//   - Type commands (e.g. “HOP ON”, “SET CH ALL”, “LOG FILE ON”)
//   - JSON output can be piped into file or processed live.
//
// -----------------------------------------------------------------------------
// Notes:
//   - Only 2.4 GHz channels (1–13) are supported by ESP32 hardware.
//   - This firmware is optimized for continuous use (low latency, stable).
//   - Suitable for classroom demos, network diagnostics, and research tools.
//   - **Not intended for production or intrusive network monitoring.**
// ============================================================================

#include <Arduino.h>
#include "WiFi.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "LittleFS.h"
#include "mbedtls/base64.h"

File logFile;
bool logToFile = false;
bool ringMode = false;
const size_t MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB max (modifiable)

#define MONITOR_CHANNEL 6       // canal à écouter
#define QUEUE_LEN 64
#define MAX_COPY 512            // nb octets à copier du début de la trame (suffit pour header+IE)
#define WORKER_STACK 4096

static const char *TAG = "esp32_sniffer";
portMUX_TYPE param_mux = portMUX_INITIALIZER_UNLOCKED;
SemaphoreHandle_t printMutex;
uint32_t active_filter_mask = WIFI_PROMIS_FILTER_MASK_ALL & ~WIFI_PROMIS_FILTER_MASK_DATA;;  // par défaut: tout

// maximum channels allowed for hopping
#define MAX_HOP_CHANNELS 16

typedef struct {
    wifi_promiscuous_pkt_t rx_pkt; // small header copy (contains rx_ctrl)
    uint16_t len;                  // payload length copied
    uint8_t payload[MAX_COPY];     // copie des premiers octets (802.11 header + IEs)
} PacketItem;

typedef struct {
    char data[MAX_COPY];
} SerialMessage;

static uint8_t hop_channels[MAX_HOP_CHANNELS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13};
static size_t hop_count = 13;
static uint32_t hop_delay_ms = 350;
static bool hop_enabled = true;
static volatile bool serialOutEnabled = true;

// queue handle
static QueueHandle_t pkt_queue = NULL;
QueueHandle_t serialQueue;
//-------------------------------------------------------------------------------------------------------------------
// Promiscuous callback — doit être ultra-court
void IRAM_ATTR promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL && type != WIFI_PKT_MISC) {
        return;
    }
    wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
    if (!p) return;

    // Construire un item minimal, copier rx_ctrl and up to MAX_COPY bytes
    PacketItem item;
    // copy rx_ctrl via assignment
    item.rx_pkt.rx_ctrl = p->rx_ctrl;

    // p->payload is a pointer to raw bytes; p->rx_ctrl.sig_len gives length (approx)
    uint16_t payload_len = p->rx_ctrl.sig_len;
    if (payload_len == 0) payload_len = 0; // safety
    if (payload_len > MAX_COPY) payload_len = MAX_COPY;
    item.len = payload_len;

    // copie sécurisée (memcpy from p->payload)
    if (payload_len > 0 && p->payload) {
        memcpy(item.payload, p->payload, payload_len);
    }

    // push to queue (from ISR)
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(pkt_queue, &item, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) portYIELD_FROM_ISR();
}
//-------------------------------------------------------------------------------------------------------------------
// helper: hex printing to a buffer
static void mac_to_str_buf(const uint8_t *mac, char *out, size_t outlen) {
    if (!mac || !out) { if (outlen) out[0]=0; return; }
    snprintf(out, outlen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
//-------------------------------------------------------------------------------------------------------------------
// Lightweight IE reader in worker task
static String read_ssid_from_ies(const uint8_t *payload, int payload_len) {
    int ie_off = 24;
    if (payload_len <= ie_off) return "";
    int i = ie_off;
    while (i + 2 <= payload_len - 1) {
        uint8_t id = payload[i];
        uint8_t ilen = payload[i+1];
        if (i + 2 + ilen > payload_len) break;
        if (id == 0) { // SSID
            if (ilen == 0) return "<hidden>";
            String s = "";
            for (int j=0;j<ilen && j<32;j++) s += (char)payload[i+2+j];
            return s;
        }
        i += 2 + ilen;
    }
    return "";
}
//-------------------------------------------------------------------------------------------------------------------
// parse vendor OUIs etc (worker)
static String parse_vendor_ouis(const uint8_t *payload, int payload_len) {
    int ie_off = 24;
    if (payload_len <= ie_off) return "";
    int ie_left = payload_len - ie_off;
    const uint8_t *ie = payload + ie_off;
    String vendor = "";
    int max_ies = 50;
    while (ie_left >= 2 && max_ies--) {
        uint8_t id = ie[0];
        uint8_t ilen = ie[1];
        if (2 + ilen > ie_left) break;
        if (id == 221 && ilen >= 3) {
            char ouis[10];
            snprintf(ouis, sizeof(ouis), "%02X%02X%02X", ie[2], ie[3], ie[4]);
            if (vendor.length()) vendor += ",";
            vendor += String(ouis);
        }
        ie += 2 + ilen;
        ie_left -= 2 + ilen;
    }
    return vendor;
}
//-------------------------------------------------------------------------------------------------------------------
void apply_filter_mask() {
    wifi_promiscuous_filter_t filt = { .filter_mask = active_filter_mask };
    esp_wifi_set_promiscuous_filter(&filt);
}
//-------------------------------------------------------------------------------------------------------------------
void add_filter_type(const String &t) {
    String up = t; up.toUpperCase();
    if (up == "MGMT") active_filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    else if (up == "CTRL") active_filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    else if (up == "DATA") active_filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    else if (up == "MISC") active_filter_mask |= WIFI_PROMIS_FILTER_MASK_MISC;
    apply_filter_mask();
}
//-------------------------------------------------------------------------------------------------------------------
void clear_filter_type(const String &t) {
    String up = t; up.toUpperCase();
    if (up == "MGMT") active_filter_mask &= ~WIFI_PROMIS_FILTER_MASK_MGMT;
    else if (up == "CTRL") active_filter_mask &= ~WIFI_PROMIS_FILTER_MASK_CTRL;
    else if (up == "DATA") active_filter_mask &= ~WIFI_PROMIS_FILTER_MASK_DATA;
    else if (up == "MISC") active_filter_mask &= ~WIFI_PROMIS_FILTER_MASK_MISC;
    apply_filter_mask();
}
//-------------------------------------------------------------------------------------------------------------------
void set_filter_all() {
    active_filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    apply_filter_mask();
}
//-------------------------------------------------------------------------------------------------------------------
void clear_filter_all() {
    active_filter_mask = 0;
    apply_filter_mask();
}

//-------------------------------------------------------------------------------------------------------------------
// Worker task: consume queue, parse, print JSON
// Worker task: consume queue, parse, print JSON
void processorTask(void *pvParameters) {
    PacketItem item;
    for (;;) {
        if (xQueueReceive(pkt_queue, &item, portMAX_DELAY) == pdTRUE) {
            if (xSemaphoreTake(printMutex, portMAX_DELAY) == pdTRUE) {
                if (!serialOutEnabled) { xSemaphoreGive(printMutex); continue; }
                if (serialOutEnabled && !logToFile) {
                    const uint8_t *payload = item.payload;
                    int len = item.len;
                    if (len < 2) { xSemaphoreGive(printMutex); continue; }

                    uint8_t fc0 = payload[0];
                    uint8_t fc1 = payload[1];
                    uint8_t type = (fc0 & 0x0C) >> 2;
                    uint8_t subtype = (fc0 & 0xF0) >> 4;

                    bool toDS      = fc1 & 0x01;
                    bool fromDS    = fc1 & 0x02;
                    bool moreFrag  = fc1 & 0x04;
                    bool retry     = fc1 & 0x08;
                    bool pwrMgmt   = fc1 & 0x10;
                    bool moreData  = fc1 & 0x20;
                    bool protectedF= fc1 & 0x40;
                    bool order     = fc1 & 0x80;

                    char addr1[32]="", addr2[32]="", addr3[32]="";
                    if (len >= 16) mac_to_str_buf(payload + 4, addr1, sizeof(addr1));  // dest
                    if (len >= 16) mac_to_str_buf(payload + 10, addr2, sizeof(addr2)); // src
                    if (len >= 24) mac_to_str_buf(payload + 16, addr3, sizeof(addr3)); // bssid

                    int8_t rssi = item.rx_pkt.rx_ctrl.rssi;
                    uint8_t chan = item.rx_pkt.rx_ctrl.channel;
                    uint32_t ts = millis();

                    const char *type_name = "Unknown";
                    const char *subtype_name = "";
                    switch (type) {
                        case 0: type_name = "Management";
                                switch (subtype) {
                                    case 0: subtype_name="AssociationReq"; break;
                                    case 1: subtype_name="AssociationResp"; break;
                                    case 4: subtype_name="ProbeReq"; break;
                                    case 5: subtype_name="ProbeResp"; break;
                                    case 8: subtype_name="Beacon"; break;
                                    case 10: subtype_name="Disassoc"; break;
                                    case 11: subtype_name="Auth"; break;
                                    case 12: subtype_name="Deauth"; break;
                                    default: subtype_name="MgmtOther"; break;
                                } break;
                        case 1: type_name = "Control";
                                switch (subtype) {
                                    case 10: subtype_name="PSPoll"; break;
                                    case 11: subtype_name="RTS"; break;
                                    case 12: subtype_name="CTS"; break;
                                    case 13: subtype_name="ACK"; break;
                                    default: subtype_name="CtrlOther"; break;
                                } break;
                        case 2: type_name = "Data";
                                subtype_name="Data";
                                break;
                        default: type_name="Other"; break;
                    }

                    // SSID et Vendor pour les mgmt frames
                    String ssid = (type == 0) ? read_ssid_from_ies(payload, len) : "";
                    String vendor = (type == 0) ? parse_vendor_ouis(payload, len) : "";

                    String json = "{";
                    json += "\"ts\":" + String(ts) + ",";
                    json += "\"ch\":" + String(chan) + ",";
                    json += "\"rssi\":" + String((int)rssi) + ",";
                    json += "\"type\":\"" + String(type_name) + "\",";
                    json += "\"subtype\":\"" + String(subtype_name) + "\",";
                    json += "\"len\":" + String(len) + ",";
                    json += "\"addr1\":\"" + String(addr1) + "\",";
                    json += "\"addr2\":\"" + String(addr2) + "\",";
                    json += "\"addr3\":\"" + String(addr3) + "\",";
                    json += "\"flags\":{";
                    json += "\"toDS\":" + String(toDS) + ",";
                    json += "\"fromDS\":" + String(fromDS) + ",";
                    json += "\"retry\":" + String(retry) + ",";
                    json += "\"moreFrag\":" + String(moreFrag) + ",";
                    json += "\"pwrMgmt\":" + String(pwrMgmt) + ",";
                    json += "\"moreData\":" + String(moreData) + ",";
                    json += "\"protected\":" + String(protectedF);
                    json += "},";
                    json += "\"ssid\":\"" + ssid + "\",";
                    json += "\"vendor\":\"" + vendor + "\"";
                    json += "}";
                    sendToSerial(json);
                }

                else if (logToFile) {
                    // Ton bloc binaire inchangé
                    if (!logFile) {
                        logFile = LittleFS.open("/capture.bin", ringMode ? "r+b" : "a+b");
                        if (!logFile) sendToSerial("ERR: cannot open capture.bin");
                    }
                    if (logFile) {
                        uint16_t plen = item.len;
                        uint8_t hdr[8];
                        int8_t rssi = item.rx_pkt.rx_ctrl.rssi;
                        uint8_t ch = item.rx_pkt.rx_ctrl.channel;
                        uint32_t ts = millis();
                        memcpy(hdr, &plen, 2);
                        memcpy(hdr + 2, &rssi, 1);
                        memcpy(hdr + 3, &ch, 1);
                        memcpy(hdr + 4, &ts, 4);
                        logFile.write(hdr, 8);
                        logFile.write(item.payload, plen);
                        logFile.flush();
                        if (logFile.size() > MAX_FILE_SIZE) {
                            if (ringMode) logFile.seek(0);
                            else {
                                logFile.close();
                                logToFile = false;
                                sendToSerial("LOG FILE STOPPED (full)");
                            }
                        }
                    }
                }

                xSemaphoreGive(printMutex);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void SerialTxTask(void *pvParameters) {
    SerialMessage msg;
    for (;;) {
        if (xQueueReceive(serialQueue, &msg, portMAX_DELAY) == pdTRUE) {
            /*size_t n = strnlen(msg.data, sizeof(msg.data));
            if (n > 0) {
                Serial.write((uint8_t*)msg.data, n);
                Serial.write('\n');
                Serial.flush();   // sécurise le buffer matériel
                vTaskDelay(pdMS_TO_TICKS(2));  // ralentit légèrement
            }*/
            Serial.println((msg.data));
            Serial.flush();  // ensure line leaves UART buffer
            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }
}


//-------------------------------------------------------------------------------------------------------------------
void sendToSerial(const char *text) {
    if (!serialQueue) return;

    SerialMessage msg;
    strncpy(msg.data, text, sizeof(msg.data) - 1);
    msg.data[sizeof(msg.data) - 1] = '\0';

    // si la queue est pleine, on enlève le plus ancien message
    if (uxQueueSpacesAvailable(serialQueue) == 0) {
        SerialMessage dummy;
        xQueueReceive(serialQueue, &dummy, 0);
    }

    // envoie non bloquant
    xQueueSend(serialQueue, &msg, 0);
}

void sendToSerial(const String &s) {
    sendToSerial(s.c_str());
}

//-------------------------------------------------------------------------------------------------------------------
void setup() {
    Serial.begin(921600);
    delay(200);

    serialQueue = xQueueCreate(64, sizeof(SerialMessage));
    if (!serialQueue) {
        Serial.println("Failed to create serialQueue");
        while(1) delay(1000);
    }

    // Init Wi-Fi for promiscuous mode
    WiFi.mode(WIFI_MODE_NULL);
    esp_wifi_stop();
    esp_wifi_deinit();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    // Optional filter: all types but DATA
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
    apply_filter_mask();   // <-- applique le bon masque
    esp_wifi_set_channel(MONITOR_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    Serial.printf("Promiscuous ON, filter mask=0x%X\n", active_filter_mask);


    printMutex = xSemaphoreCreateMutex();

    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS mount failed");
    } else {
        Serial.println("LittleFS ready");
    }

    pkt_queue = xQueueCreate(QUEUE_LEN, sizeof(PacketItem));
    if (!pkt_queue) {
        Serial.println("Failed to create queue");
        while(1) delay(1000);
    }

    xTaskCreatePinnedToCore(processorTask, "processorTask", WORKER_STACK, NULL, 2, NULL, 1);
    xTaskCreatePinnedToCore(channelHopTask, "ch_hop", 2048, NULL, 1, NULL, 1);
    xTaskCreatePinnedToCore(SerialTxTask, "SerialTx", 4096, NULL, 2, NULL, 1);
    xTaskCreatePinnedToCore(serialCommandTask, "serialCmd", 4096, NULL, 1, NULL, 1);
}

//-------------------------------------------------------------------------------------------------------------------
void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000)); // rien d’utile ici
}
//-------------------------------------------------------------------------------------------------------------------
void set_hop_channels(const uint8_t *channels, size_t count) {
    portENTER_CRITICAL(&param_mux);
    hop_count = (count > MAX_HOP_CHANNELS) ? MAX_HOP_CHANNELS : count;
    for (size_t i = 0; i < hop_count; i++) {
        hop_channels[i] = channels[i];
    }
    portEXIT_CRITICAL(&param_mux);
}
//-------------------------------------------------------------------------------------------------------------------
static void set_hop_channels_from_string(const char* s) {
    // s is something like "1,6,11"
    portENTER_CRITICAL(&param_mux);
    hop_count = 0;
    const char *p = s;
    while (*p && hop_count < MAX_HOP_CHANNELS) {
        // skip spaces
        while (*p == ' ' || *p == '\t') ++p;
        int val = 0;
        bool got = false;
        while (*p >= '0' && *p <= '9') {
            val = val*10 + (*p - '0');
            p++;
            got = true;
        }
        if (got && val >= 1 && val <= 14) {
            hop_channels[hop_count++] = (uint8_t)val;
        }
        // skip separators
        while (*p && (*p == ',' || *p == ' ' || *p == '\t')) ++p;
    }
    if (hop_count == 0) {
        // fallback to common triad
        hop_channels[0]=1; hop_channels[1]=6; hop_channels[2]=11; hop_count = 3;
    }
    portEXIT_CRITICAL(&param_mux);
}
//-------------------------------------------------------------------------------------------------------------------
static void set_hop_delay_ms(uint32_t ms) {
    portENTER_CRITICAL(&param_mux);
    hop_delay_ms = ms;
    portEXIT_CRITICAL(&param_mux);
}
//-------------------------------------------------------------------------------------------------------------------
static void set_hop_enabled(bool en) {
    portENTER_CRITICAL(&param_mux);
    hop_enabled = en;
    portEXIT_CRITICAL(&param_mux);
}
//-------------------------------------------------------------------------------------------------------------------
// channel hop task reads the protected variables before each sleep
void channelHopTask(void *pv) {
    size_t idx = 0;
    for (;;) {
        // snapshot protected params
        uint8_t ch=1;
        size_t count=1;
        uint32_t delay_ms=350;
        bool enabled=true;
        portENTER_CRITICAL(&param_mux);
        count = hop_count;
        delay_ms = hop_delay_ms;
        enabled = hop_enabled;
        if (count == 0) { count = 1; hop_channels[0]=1; }
        ch = hop_channels[idx % count];
        portEXIT_CRITICAL(&param_mux);

        if (enabled) {
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            // optional light debug:
            // Serial.printf("HOP -> ch %u\n", ch);
            idx = (idx + 1) % count;
        }
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}
//-------------------------------------------------------------------------------------------------------------------
// --- Petit utilitaire pour trim ---
static String trimStr(const String &s) {
    int i = 0, j = (int)s.length() - 1;
    while (i <= j && isspace(s[i])) i++;
    while (j >= i && isspace(s[j])) j--;
    if (i == 0 && j == (int)s.length() - 1) return s;
    return s.substring(i, j + 1);
}
// Wait until the SerialTx queue is empty (with small timeout)
void waitSerialDrain(uint32_t timeout_ms = 500) {
    uint32_t start = millis();
    while ((uxQueueMessagesWaiting(serialQueue) > 0) &&
           (millis() - start < timeout_ms)) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    // ensure hardware UART buffer flushed too
    Serial.flush();
}

//-------------------------------------------------------------------------------------------------------------------
// --- Handler de commandes ---
void handleSerialCommand(String cmd) {
    Serial.flush();                          // termine tout TX
    while (Serial.available()) Serial.read(); // vide le RX
    SerialMessage dummy;
    while (xQueueReceive(serialQueue, &dummy, 0)) {
        // vide les messages précédents (évite les doublons)
    }
    cmd = trimStr(cmd);
    if (cmd.length() == 0) return;

    String up = cmd;
    up.toUpperCase();

    if (up == "HOP ON") {
        set_hop_enabled(true);
        sendToSerial("OK: HOP ON");
    }
    else if (up == "HOP OFF") {
        set_hop_enabled(false);
        sendToSerial("OK: HOP OFF");
    }
    else if (up == "SET CH ALL") {
        uint8_t all_ch[13];
        for (uint8_t i = 0; i < 13; i++) all_ch[i] = i + 1;
        portENTER_CRITICAL(&param_mux);
        memcpy(hop_channels, all_ch, sizeof(all_ch));
        hop_count = 13;
        portEXIT_CRITICAL(&param_mux);
        sendToSerial("OK: CHANNELS=ALL");
    }

    else if (up.startsWith("SET CH ")) {
        // Exemple: "SET CH 1,6,11" ou "SET CH 6"
        String rest = cmd.substring(7);
        rest.trim();
        if (rest.length() == 0) {
            sendToSerial("ERR: missing channel list");
        } else {
            set_hop_channels_from_string(rest.c_str());
            String out = "OK: CHANNELS=";
            portENTER_CRITICAL(&param_mux);
            for (size_t i = 0; i < hop_count; i++) {
                if (i) out += ",";
                out += String(hop_channels[i]);
            }
            portEXIT_CRITICAL(&param_mux);
            sendToSerial(out);
        }
    }

    else if (up.startsWith("CLEAR CH ALL")) {
        portENTER_CRITICAL(&param_mux);
        hop_count = 0;
        portEXIT_CRITICAL(&param_mux);
        sendToSerial("OK: CHANNELS CLEARED");
    }

    else if (up.startsWith("CLEAR CH ")) {
        // Exemple: "CLEAR CH 6"
        int ch = cmd.substring(10).toInt();
        bool found = false;
        portENTER_CRITICAL(&param_mux);
        for (size_t i = 0; i < hop_count; i++) {
            if (hop_channels[i] == ch) {
                // supprime ce canal
                for (size_t j = i; j < hop_count - 1; j++)
                    hop_channels[j] = hop_channels[j + 1];
                hop_count--;
                found = true;
                break;
            }
        }
        portEXIT_CRITICAL(&param_mux);
        if (found) sendToSerial("OK: CHANNEL " + String(ch) + " REMOVED");
        else sendToSerial("WARN: CHANNEL NOT FOUND");
    }


    else if (up.startsWith("SET HOP_MS ")) {
        uint32_t val = (uint32_t) cmd.substring(11).toInt();
        if (val < 50) val = 50;
        set_hop_delay_ms(val);
        sendToSerial("OK: HOP_MS=" + String(val));
    }
    else if (up == "SHOW") {
        String out;
        portENTER_CRITICAL(&param_mux);
        out  = "SHOW: Hop Enabled=";
        out += hop_enabled ? "1" : "0";
        out += " Delay=" + String(hop_delay_ms);
        out += " Channels=";
        for (size_t i = 0; i < hop_count; i++) {
            if (i) out += ",";
            out += String(hop_channels[i]);
        }
        out += " LogToFile=" + String(logToFile ? 1 : 0);
        out += " RingMode=" + String(ringMode ? 1 : 0);

        portEXIT_CRITICAL(&param_mux);
        sendToSerial(out);
    }
    else if (up == "HELP") {
        // clear any old queued messages
        SerialMessage dummy;
        while (xQueueReceive(serialQueue, &dummy, 0)) { }

        const char *helpLines[] = {
            "Commands:",
            "  HOP ON | HOP OFF",
            "  SET CH 1,6,11 | SET CH ALL",
            "  CLEAR CH 1 | CLEAR CH ALL",
            "  SET HOP_MS <ms>",
            "  SHOW | HELP",
            "  LOG ON | LOG OFF",
            "  LOG FILE ON | LOG FILE OFF",
            "  LOG FILE STATUS | LOG FILE CLEAR",
            "  LOG FILE MODE RING | LOG FILE MODE STOP",
            "  DUMP FILE JSON | DUMP FILE BIN",
            "  FORMAT FS",
            "  SET TYPE MGMT | SET TYPE DATA | SET TYPE ALL",
            "  CLEAR TYPE MGMT | CLEAR TYPE ALL | SHOW TYPES",
            "Usage:",
            "  LOG FILE ON ........ Start binary recording on LittleFS (/capture.bin)",
            "  LOG FILE OFF ....... Stop file logging and restore Serial output",
            "  LOG FILE MODE RING . Overwrite oldest data when full",
            "  LOG FILE MODE STOP . Stop recording when full",
            "  DUMP FILE JSON ..... Export capture.bin as JSON over Serial",
            "  DUMP FILE BIN ...... Export capture.bin as Base64 (binary dump)",
            "  LOG FILE STATUS .... Show file size and max capacity",
            "  LOG FILE CLEAR ..... Delete capture.bin",
            "  FORMAT FS .......... Format LittleFS (erase all)"
        };

        for (auto &line : helpLines) {
            sendToSerial(line);
            vTaskDelay(pdMS_TO_TICKS(20));  // smooth output
        }

        // ✅ Wait until all lines are really printed before continuing
        waitSerialDrain(800);
    }

    else if (up == "LOG FILE STATUS") {
        if (!LittleFS.exists("/capture.bin")) {
            sendToSerial("NO FILE");
        } else {
            File f = LittleFS.open("/capture.bin", "r");
            size_t size = f.size();
            f.close();
            sendToSerial("FILE SIZE=" + String(size) + "/" + String(MAX_FILE_SIZE));
        }
    }
    else if (up == "LOG FILE CLEAR") {
        LittleFS.remove("/capture.bin");
        sendToSerial("OK: FILE CLEARED");
    }
    else if (up == "LOG OFF") {
        sendToSerial("OK: LOG OFF");
        xSemaphoreTake(printMutex, portMAX_DELAY);
        serialOutEnabled = false;
        xSemaphoreGive(printMutex);

        // purge toute la file série
        SerialMessage dummy;
        while (xQueueReceive(serialQueue, &dummy, 0)) { }

        // attendre que processorTask ait fini son tour
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    else if (up == "LOG ON") {
        sendToSerial("OK: LOG ON\n");
        xSemaphoreTake(printMutex, portMAX_DELAY);
        serialOutEnabled = true;
        xSemaphoreGive(printMutex);
    }
    else if (up == "LOG FILE ON") {
        xSemaphoreTake(printMutex, portMAX_DELAY);
        serialOutEnabled = false;
        logToFile = true;
        if (logFile) logFile.close();
        logFile = LittleFS.open("/capture.bin", ringMode ? "r+b" : "w+b");
        xSemaphoreGive(printMutex);
        sendToSerial("OK: LOG FILE ON");
    }

    else if (up == "LOG FILE OFF") {
        xSemaphoreTake(printMutex, portMAX_DELAY);
        if (logFile) logFile.close();
        logToFile = false;
        serialOutEnabled = true;
        xSemaphoreGive(printMutex);
        sendToSerial("OK: LOG FILE OFF (serial restored)");
    }

    else if (up == "LOG FILE MODE RING") {
        ringMode = true;
        sendToSerial("OK: LOG MODE=RING (overwrite when full)");
    }

    else if (up == "LOG FILE MODE STOP") {
        ringMode = false;
        sendToSerial("OK: LOG MODE=STOP (stop when full)");
    }
    else if (up == "DUMP FILE JSON") {
        sendToSerial("OK: DUMPING FILE AS JSON");
        xSemaphoreTake(printMutex, portMAX_DELAY);
        dumpFileAsJSON();
        sendToSerial("OK: JSON DUMP COMPLETE");
        xSemaphoreGive(printMutex);
    }
    else if (up == "DUMP FILE BIN") {
        sendToSerial("OK: DUMPING FILE AS BASE64");
        if (!LittleFS.exists("/capture.bin")) {
            sendToSerial("ERR: capture.bin not found");
            return;
        }

        File f = LittleFS.open("/capture.bin", "r");
        if (!f) {
            sendToSerial("ERR: cannot open capture.bin");
            return;
        }

        sendToSerial("BEGIN BIN DUMP");

        uint8_t buf[256];
        unsigned char encoded[512];
        size_t n, olen;

        while ((n = f.read(buf, sizeof(buf))) > 0) {
            mbedtls_base64_encode(encoded, sizeof(encoded), &olen, buf, n);
            encoded[olen] = 0;
            sendToSerial((const char*)encoded);
            vTaskDelay(pdMS_TO_TICKS(2)); // pour lisser le flux série
        }

        f.close();
        sendToSerial("END BIN DUMP");
    }
    else if (up == "FORMAT FS") {
        LittleFS.format();
        sendToSerial("OK: FILESYSTEM FORMATTED");
    }
    else if (up.startsWith("SET TYPE ALL")) {
        set_filter_all();
        sendToSerial("OK: TYPES=ALL");
    }

    else if (up.startsWith("CLEAR TYPE ALL")) {
        clear_filter_all();
        sendToSerial("OK: TYPES CLEARED");
    }

    else if (up.startsWith("SET TYPE ")) {
        String rest = cmd.substring(9);
        rest.trim();
        add_filter_type(rest);
        sendToSerial("OK: TYPE " + rest + " ADDED");
    }

    else if (up.startsWith("CLEAR TYPE ")) {
        String rest = cmd.substring(11);
        rest.trim();
        clear_filter_type(rest);
        sendToSerial("OK: TYPE " + rest + " REMOVED");
    }

    else if (up == "SHOW TYPES") {
        String out = "SHOW: TYPES=";
        if (active_filter_mask & WIFI_PROMIS_FILTER_MASK_MGMT) out += "MGMT ";
        if (active_filter_mask & WIFI_PROMIS_FILTER_MASK_CTRL) out += "CTRL ";
        if (active_filter_mask & WIFI_PROMIS_FILTER_MASK_DATA) out += "DATA ";
        if (active_filter_mask & WIFI_PROMIS_FILTER_MASK_MISC) out += "MISC ";
        sendToSerial(out);
    }

    else {
        sendToSerial("ERR: unknown command -> " + cmd);
    }
}
//------------------------------------------------------------------------------------------------------------------
void dumpFileAsJSON() {
    if (!LittleFS.exists("/capture.bin")) {
        sendToSerial("ERR: capture.bin not found");
        return;
    }

    File f = LittleFS.open("/capture.bin", "r");
    if (!f) {
        sendToSerial("ERR: cannot open capture.bin");
        return;
    }

    sendToSerial("BEGIN JSON DUMP");

    while (f.available()) {
        uint8_t hdr[8];
        if (f.read(hdr, 8) != 8) break;

        uint16_t len;
        memcpy(&len, hdr, 2);
        int8_t rssi = hdr[2];
        uint8_t ch = hdr[3];
        uint32_t ts;
        memcpy(&ts, hdr + 4, 4);

        uint8_t payload[MAX_COPY];
        if (len > MAX_COPY) len = MAX_COPY;
        if (f.read(payload, len) != len) break;

        char mac_src[32] = "";
        if (len >= 16) mac_to_str_buf(payload + 10, mac_src, sizeof(mac_src));

        uint8_t type = 0xFF, subtype = 0xFF;
        if (len >= 1) {
            uint8_t fc0 = payload[0];
            type = (fc0 & 0x0C) >> 2;
            subtype = (fc0 & 0xF0) >> 4;
        }

        uint16_t seq_ctrl = 0;
        if (len >= 24) seq_ctrl = payload[22] | (payload[23] << 8);
        uint16_t seq_num = seq_ctrl >> 4;
        uint8_t frag = seq_ctrl & 0x0F;

        String ssid = read_ssid_from_ies(payload, len);
        String vendor = parse_vendor_ouis(payload, len);

        String json = "{";
        json += "\"ts\":" + String(ts) + ",";
        json += "\"mac\":\"" + String(mac_src) + "\",";
        json += "\"rssi\":" + String((int)rssi) + ",";
        json += "\"hdr_ch\":" + String(ch) + ",";
        json += "\"type\":" + String(type) + ",";
        json += "\"subtype\":" + String(subtype) + ",";
        json += "\"seq\":" + String(seq_num) + ",";
        json += "\"frag\":" + String(frag) + ",";
        json += "\"ssid\":\"" + ssid + "\",";
        json += "\"vendor\":\"" + vendor + "\"";
        json += "}";
        sendToSerial(json);
        vTaskDelay(pdMS_TO_TICKS(1));  // éviter de saturer le port série
    }

    f.close();
    sendToSerial("END JSON DUMP");
}
//-------------------------------------------------------------------------------------------------------------------
// --- Callback de réception série ---
void onSerialData() {
    static String buffer;
    while (Serial.available()) {
        char c = (char) Serial.read();
        if (c == '\r') continue;
        if (c == '\n') {
            handleSerialCommand(buffer);
            buffer = "";
        } else {
            buffer += c;
            if (buffer.length() > 200)
                buffer.remove(0, buffer.length() - 200);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void serialCommandTask(void *pv) {
    for (;;) {
        onSerialData();     // essaie de lire les données série
        vTaskDelay(pdMS_TO_TICKS(10)); // 10 ms de pause
    }
}
