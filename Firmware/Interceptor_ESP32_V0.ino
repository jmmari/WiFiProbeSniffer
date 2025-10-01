// ============================================================================
// ESP32 Promiscuous Sniffer
// Board   : ESP32 (Arduino core)
// Author  : Jean Martial MARI
// Affil.  : Université de la Polynésie française (UPF)
// Year    : 2025
// License : MIT (see LICENSE file in repository)
//
// Description:
//   Minimal ESP32 Wi-Fi sniffer using promiscuous mode. 
//   - Interrupt Service Routine (ISR) keeps work minimal (just queueing).
//   - Worker FreeRTOS task parses and prints captured packets as JSON.
//   - Extracts RSSI, channel, MAC addresses, sequence numbers, SSID,
//     and vendor OUIs from management/data/control frames.
//
// Usage:
//   - Configure MONITOR_CHANNEL to the Wi-Fi channel of interest.
//   - Connect ESP32 via USB, open serial monitor at 115200 baud.
//   - Packets are output as JSON lines for further processing
//     (e.g., Python script `serial_probe_viewer.py`).
//
// Notes:
//   - This is a research/educational tool, not for production use.
//   - MIT licensed: free to use, copy, modify, and distribute.
// ============================================================================

#include <Arduino.h>
#include "WiFi.h"
#include "esp_wifi.h"

#define MONITOR_CHANNEL 6       // canal à écouter
#define QUEUE_LEN 64
#define MAX_COPY 256            // nb octets à copier du début de la trame (suffit pour header+IE)
#define WORKER_STACK 4096

static const char *TAG = "esp32_sniffer";

typedef struct {
    wifi_promiscuous_pkt_t rx_pkt; // small header copy (contains rx_ctrl)
    uint16_t len;                  // payload length copied
    uint8_t payload[MAX_COPY];     // copie des premiers octets (802.11 header + IEs)
} PacketItem;

// queue handle
static QueueHandle_t pkt_queue = NULL;

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

// helper: hex printing to a buffer
static void mac_to_str_buf(const uint8_t *mac, char *out, size_t outlen) {
    if (!mac || !out) { if (outlen) out[0]=0; return; }
    snprintf(out, outlen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

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

// Worker task: consume queue, parse, print JSON
void processorTask(void *pvParameters) {
    PacketItem item;
    for (;;) {
        if (xQueueReceive(pkt_queue, &item, portMAX_DELAY) == pdTRUE) {
            // basic safety: ensure there's at least header
            int payload_len = item.len;
            const uint8_t *payload = item.payload;

            // compute type/subtype if we have at least 1 byte
            uint8_t type = 0xff, subtype = 0xff;
            if (payload_len >= 1) {
                uint8_t fc0 = payload[0];
                type = (fc0 & 0x0C) >> 2;
                subtype = (fc0 & 0xF0) >> 4;
            }

            // mac addresses: addr1 @ offset 4, addr2 @ 10, addr3 @ 16 (in most mgmt/data frames)
            char mac_src[32] = "";
            if (payload_len >= 16) {
                mac_to_str_buf(payload + 10, mac_src, sizeof(mac_src));
            }

            // seq/frag
            uint16_t seq_ctrl = 0;
            if (payload_len >= 24) seq_ctrl = payload[22] | (payload[23] << 8);
            uint16_t seq_num = seq_ctrl >> 4;
            uint8_t frag = seq_ctrl & 0x0F;

            int8_t rssi = item.rx_pkt.rx_ctrl.rssi;
            int hdr_chan = item.rx_pkt.rx_ctrl.channel;

            // parse some IEs (SSID, DS channel, vendor OUIs)
            String ssid = read_ssid_from_ies(payload, payload_len);
            String vendor = parse_vendor_ouis(payload, payload_len);

            // Build JSON (safe, not huge)
            String json = "{";
            json += "\"ts\":" + String(millis()) + ",";
            json += "\"mac\":\"" + String(mac_src) + "\",";
            json += "\"rssi\":" + String((int)rssi) + ",";
            json += "\"hdr_ch\":" + String(hdr_chan) + ",";
            json += "\"type\":" + String(type) + ",";
            json += "\"subtype\":" + String(subtype) + ",";
            json += "\"seq\":" + String(seq_num) + ",";
            json += "\"frag\":" + String(frag) + ",";
            json += "\"ssid\":\"" + ssid + "\",";
            json += "\"vendor\":\"" + vendor + "\"";
            json += "}";

            // print
            Serial.println(json);
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(200);

    // create queue
    pkt_queue = xQueueCreate(QUEUE_LEN, sizeof(PacketItem));
    if (!pkt_queue) {
        Serial.println("Failed to create queue");
        while(1) delay(1000);
    }

    // start worker task
    xTaskCreatePinnedToCore(processorTask, "processorTask", WORKER_STACK, NULL, 2, NULL, 1);

    // init WiFi in null mode and enable promiscuous
    WiFi.mode(WIFI_MODE_NULL);
    esp_wifi_stop(); // ensure clean state
    esp_wifi_deinit();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    // optional filter: only management frames to reduce load
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL }; // change MASK_MGMT if you want only mgmt
    esp_wifi_set_promiscuous_filter(&filt);

    // set channel and callback
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
    esp_wifi_set_channel(MONITOR_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);

    Serial.printf("Promiscuous started on channel %d\n", MONITOR_CHANNEL);
}

void loop() {
    // nothing heavy here
    delay(1000);
}
