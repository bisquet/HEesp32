#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <nvs_flash.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// Definición de estados de la máquina
enum SystemState {
  IDLE,
  SCAN,
  LOCK
};

SystemState current_state = IDLE;

// Tarea y variables de control
TaskHandle_t hopper_task_handle = NULL;
uint8_t target_mac[6] = {0};
uint8_t target_channel = 1;

void channel_hopper_task(void *pvParameter) {
  uint8_t channel = 1;
  while (1) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    channel++;
    if (channel > 13) channel = 1;
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void stop_hopper() {
  if (hopper_task_handle != NULL) {
    vTaskDelete(hopper_task_handle);
    hopper_task_handle = NULL;
  }
}

void start_hopper() {
  if (hopper_task_handle == NULL) {
    xTaskCreate(&channel_hopper_task, "channel_hopper", 2048, NULL, 5, &hopper_task_handle);
  }
}

void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (current_state == IDLE) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  uint16_t sig_len = pkt->rx_ctrl.sig_len;

  if (current_state == SCAN) {
    // Modo SCAN: Imprimir Beacons (filtrado original)
    if (type != WIFI_PKT_MGMT) return;
    if (payload[0] != 0x80) return; // Beacons frame control
    if (sig_len < 36) return;

    uint8_t *bssid = payload + 10; // BSSID position (Address 3)
    // El offset anterior era para extraer BSSID, Address 3 en beacon
    uint8_t current_channel = pkt->rx_ctrl.channel;
    
    int offset = 36;
    String ssid = "<oculto>";
    
    while (offset < sig_len) {
      uint8_t tag_num = payload[offset];
      if (offset + 1 >= sig_len) break;
      uint8_t tag_len = payload[offset + 1];
      
      if (tag_num == 0) {
        if (tag_len > 0 && (offset + 2 + tag_len) <= sig_len) {
          char ssid_buf[33];
          memcpy(ssid_buf, payload + offset + 2, tag_len);
          ssid_buf[tag_len] = '\0';
          ssid = String(ssid_buf);
        }
        break;
      }
      offset += 2 + tag_len;
    }
    
    Serial.printf("[BEACON] CH: %2d | BSSID: %02x:%02x:%02x:%02x:%02x:%02x | SSID: %s\n",
                  current_channel, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ssid.c_str());
                  
  } else if (current_state == LOCK) {
    // Modo LOCK: Filtrar paquetes donde la MAC origen (addr2) o destino (addr1) coincidan
    if (sig_len < 24) return;
    
    uint8_t *addr1 = payload + 4;  // Destination Address
    uint8_t *addr2 = payload + 10; // Source Address
    
    bool match_addr1 = (memcmp(addr1, target_mac, 6) == 0);
    bool match_addr2 = (memcmp(addr2, target_mac, 6) == 0);
    
    if (match_addr1 || match_addr2) {
      // Filtrar solo tramas de Datos (Frame Control Type 0x02) o QoS Data (Subtype 0x08)
      // FC: [Protocol Version: 2 bits] [Type: 2 bits] [Subtype: 4 bits]
      uint8_t frame_control = payload[0];
      uint8_t fc_type = (frame_control >> 2) & 0x03;
      uint8_t fc_subtype = (frame_control >> 4) & 0x0F;

      if (fc_type == 0x02 || payload[0] == 0x80) { // Data frame or Beacon
        // Enviar RAW hexadecimal. Procesar la longitud total
        uint16_t send_len = sig_len;
        
        char *hex_str = (char *)malloc((send_len * 2) + 1); 
        if (hex_str) {
          for (uint16_t i = 0; i < send_len; i++) {
            sprintf(&hex_str[i * 2], "%02x", payload[i]);
          }
          hex_str[send_len * 2] = '\0';

          Serial.printf("[RAW] %s\n", hex_str);
          free(hex_str);
        }
      }
    }
  }
}

void parse_lock_command(String cmd) {
  // Expected format: CMD:LOCK:AA:BB:CC:DD:EE:FF:11
  // Length: 10 chars "CMD:LOCK:" + 17 chars MAC + 1 char ":" + 1-2 chars channel
  cmd.trim();
  int last_colon = cmd.lastIndexOf(':');
  if (last_colon == -1 || last_colon <= 9) return;
  
  String mac_str = cmd.substring(9, last_colon);
  String ch_str = cmd.substring(last_colon + 1);
  
  target_channel = ch_str.toInt();
  
  // Parse MAC
  int hex_vals[6];
  if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", 
             &hex_vals[0], &hex_vals[1], &hex_vals[2], 
             &hex_vals[3], &hex_vals[4], &hex_vals[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      target_mac[i] = (uint8_t)hex_vals[i];
    }
    
    // Cambiar estado a LOCK
    current_state = LOCK;
    stop_hopper();
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("LOCK: Target MAC=%s, CH=%d\n", mac_str.c_str(), target_channel);
  } else {
    Serial.println("Error parsing MAC address.");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    err = nvs_flash_init();
  }

  esp_netif_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);
  esp_wifi_set_promiscuous(true);
  
  // Estado inicial
  current_state = IDLE;
  Serial.println("HEesp32 Iniciado. Estado: IDLE. Esperando comandos...");
}

void loop() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    
    if (cmd == "CMD:IDLE") {
      current_state = IDLE;
      stop_hopper();
      Serial.println("IDLE: Detenido.");
    } 
    else if (cmd == "CMD:SCAN") {
      current_state = SCAN;
      start_hopper();
      Serial.println("SCAN: Iniciado.");
    }
    else if (cmd.startsWith("CMD:LOCK:")) {
      parse_lock_command(cmd);
    }
  }
  
  vTaskDelay(pdMS_TO_TICKS(10)); // Yield to allow other tasks
}
