## ⚖️ AVISO LEGAL Y ÉTICO (LEER ANTES DE USAR)

🔒 **Propósito exclusivo:** Esta herramienta ha sido desarrollada **únicamente con fines educativos y de investigación en ciberseguridad**. Está diseñada para su uso en entornos de laboratorio controlados, redes propias o sistemas sobre los que se posea **autorización expresa y por escrito** del propietario.

⚠️ **Responsabilidad del usuario:** El uso de este software contra redes, dispositivos o sistemas sin autorización explícita es **ilegal**. El autor y los colaboradores del proyecto **no asumen responsabilidad alguna** por el mal uso, daños, interrupciones de servicio o consecuencias legales derivadas de su utilización fuera de un contexto ético y autorizado. Cada usuario asume la **total responsabilidad civil y penal** de sus actos.

🇪🇸 **Marco normativo (España):** La realización de ataques de desautenticación, captura de handshakes o fuerza bruta sobre redes ajenas sin consentimiento constituye delito tipificado en los artículos 197, 197ter y 264 del **Código Penal**, así como infracciones graves bajo la **LOPDGDD (LO 3/2018)**. Consulta siempre la legislación vigente de tu jurisdicción.

✅ **Uso correcto recomendado:**
- Redes de laboratorio aisladas.
- Equipos y routers de tu propiedad.
- Entornos de formación con supervisión docente.
- Auditorías con contrato/pacto de confidencialidad firmado.

> 📜 *Al clonar, compilar o ejecutar este proyecto, declaras haber leído, comprendido y aceptado estos términos. Si no estás de acuerdo, no utilices el software.*

# 📡 HEesp32 - Plataforma de Auditoría 802.11 Bare-Metal

**Entorno de Laboratorio:** Práctica de Ciberseguridad y Redes Inalámbricas (ASIR y ciberseguridad).

> **Objetivo:** Desplegar una arquitectura asimétrica de captura pasiva (Sniffing EAPOL) mediante hardware dedicado (ESP32) y orquestación de fuerza bruta local (Hashcat/RTX).

---

## 🛠️ Fase 1: Permisos del Kernel y Dependencias (Ubuntu 22.04)

Antes de operar, el sistema operativo necesita los binarios criptográficos y acceso de bajo nivel a las interfaces USB. 

Instala los entornos de Python y las herramientas de auditoría de red:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip hashcat hcxtools
```

El kernel de Linux bloquea por defecto el acceso a los puertos seriales (`/dev/ttyUSB0`). Para que PlatformIO pueda flashear el ESP32, debes otorgar permisos a tu usuario añadiéndolo al grupo `dialout`:

```bash
sudo usermod -aG dialout $USER
```

> [!WARNING]  
> **ALERTA CRÍTICA:** Debes **CERRAR SESIÓN** y volver a entrar (o reiniciar el equipo) para que la inclusión en el grupo `dialout` surta efecto. De lo contrario, la compilación fallará.

## 🐍 Fase 2: Ignición del Entorno Virtual (Host)

Para mantener la integridad termodinámica del sistema operativo, todas las dependencias de Python y PlatformIO operarán encapsuladas. 

Dentro de la raíz del proyecto clonado, ejecuta la siguiente secuencia:

```bash
# 1. Crear el entorno virtual
python3 -m venv venv

# 2. Activar el entorno virtual
source venv/bin/activate

# 3. Instalar la matriz de dependencias
pip install -r requirements.txt
```

## ⚡ Fase 3: Flasheo de Silicio y Control C2

Con el ESP32 conectado por USB al equipo, inyectaremos el firmware bare-metal (C++) y levantaremos el puente de mando (Python).

Compila el código fuente e inyecta el firmware en el microcontrolador:

```bash
pio run -t upload
```

Inicia la consola interactiva C2 (Command & Control):

```bash
python host/monitor.py
```

## 📖 Flujo Básico de Operación (Comandos C2)

Una vez dentro de la consola `HEesp32>`, el flujo táctico es el siguiente:

* `scan`: Inicia el *Channel Hopper* para mapear el espectro.
* `stop`: Detiene cualquier operación activa.
* `lock&cap <MAC> <CANAL>`: Fija la antena en el objetivo y captura tráfico. (Alias temporal: `lock` funciona con warning)
* `crack dict <pcap> <diccionario>`: Extrae el *Handshake* y lanza ataque por diccionario. *(Para este laboratorio utilizaremos un diccionario extraído directamente de la base de datos europea de credenciales, lo que proporcionará un escenario de colisión de hashes totalmente realista).*
* `crack brute <pcap> <máscara>`: Lanza el ataque de fuerza bruta pura y pone a prueba el límite térmico de la GPU (ej: `?d?d?d?d?d?d?d?d`).
* `crack hybrid <pcap> <diccionario> <máscara>`: Híbrido diccionario + máscara.
* `crack raw <pcap> <args...>`: Modo experto: pasar flags crudos a hashcat.

**Opciones comunes de crack:**
* `--rules <archivo.rule>`: Aplicar reglas hashcat (ej: `--rules best64.rule`).
* `--gpu-temp <N>`: Límite temperatura GPU en °C (ej: `--gpu-temp 65`).
* `--show`: Mostrar contraseñas crackeadas previamente.
* `--restore`: Reanudar sesión hashcat interrumpida.

**Ejemplos pedagógicos:**
```bash
crack dict captura.pcap rockyou.txt
crack dict captura.pcap rockyou.txt --rules best64.rule
crack brute captura.pcap '?d?d?d?d?d?d?d?d'
crack hybrid captura.pcap rockyou.txt '?d?d?d?d'
```

---

## 🎯 Módulo DEAUTH - Guía Pedagógica

### ¿Qué es un frame Deauth?

Un frame de **Deauthentication** (802.11 Management, subtype `0xC0`) es el mecanismo que usa un AP o un cliente para cerrar una asociación WiFi. Es un frame **no autenticado**: cualquiera puede enviarlo suplantando la MAC del AP, y el cliente lo obedecerá sin verificar. Esta es la vulnerabilidad fundamental de 802.11.

### Estructura del frame (26 bytes)

| Offset | Campo | Valor | Descripción |
|--------|-------|-------|-------------|
| 0-1 | Frame Control | `0xC0 0x00` | Management, Deauth |
| 2-3 | Duration | `0x00 0x00` | No usado |
| 4-9 | Address 1 | MAC destino | Cliente o `FF:FF:FF:FF:FF:FF` (broadcast) |
| 10-15 | Address 2 | MAC origen | MAC del AP (BSSID) |
| 16-21 | Address 3 | BSSID | MAC del AP |
| 22-23 | Sequence Ctrl | Variable | Counter propio (evita replay detection) |
| 24 | Reason Code | 1-255 | Motivo de la desconexión |
| 25 | Padding | `0x00` | Alineamiento |

### Reason Codes comunes

| Code | Significado | Uso pedagógico |
|------|-------------|----------------|
| 1 | Unspecified reason | Genérico, menos sospechoso |
| 2 | Previous authentication invalid | Simula fallo de autenticación |
| 7 | Class 3 frame from nonassociated STA | **Más creíble** para demos, parece error de red |

### Sintaxis del comando

```bash
# En monitor.py:
deauth <AP_MAC> --client <MAC>|--broadcast --reason <1-255> [--count N] [--delay ms] [--method direct|rogue]

# Ejemplos:
deauth AA:BB:CC:DD:EE:FF --broadcast --reason 7 --count 10 --delay 100
deauth AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66 --reason 1 --count 5
deauth AA:BB:CC:DD:EE:FF --broadcast --reason 7 --method rogue
```

### Métodos disponibles

| Método | Descripción | Ventaja | Limitación |
|--------|-------------|--------|------------|
| `direct` | Inyección directa de frames deauth | Efectivo cuando funciona | Requiere bypass o modo monitor |
| `rogue` | AP duplicado que fuerza desconexión natural | No requiere bypass, más educativo | Requiere que el cliente esté activo |

### Detección defensiva (WIDS/IDS)

Un IDS empresarial (Cisco ISE, Aruba ClearPass, WIDS) detecta ráfagas de deauth por:
1. **Rate anomaly**: >5 deauth/segundo desde una MAC no asociada
2. **Sequence gap**: Saltos en el sequence number del frame
3. **RSSI mismatch**: El frame deauth llega con potencia diferente al AP legítimo

**Ciclo completo de laboratorio**: Ataque → Captura Wireshark → Análisis IDS → Configuración de reglas de detección.

> ⚖️ **MARCO LEGAL**: Este módulo es exclusivamente para entornos de laboratorio con autorización. El uso no autorizado de frames de deauth contra redes de terceros constituye un delito tipificado en la **Ley Orgánica 10/2022** de ciberseguridad y el **Código Penal Art. 197ter**.

---

### ⚠️ Limitación de Hardware: ESP32 DEAUTH

El módulo DEAUTH en HEesp32 tiene una **limitación técnica del hardware ESP32** que impide la inyección de frames 802.11 raw cuando el dispositivo no está asociado a un AP.

**Problema:** `esp_wifi_80211_tx()` en ESP32 vanilla rechaza frames management (como deauth, subtype 0xC0) con error `ESP_ERR_WIFI_MODE (0x102)` y mensaje `unsupport frame type: 0c0`. El driver WiFi no permite spoofing de BSSID cuando no hay asociación activa.

**Solución A (experimental): WSL Bypasser**  
El componente `wsl_bypasser` de risinek permite inyectar frames management evadiendo `ieee80211_raw_frame_sanity_check()` mediante link-time symbol override. Esta técnica requiere:

1. **Framework IDF puro** (no Arduino): Cambiar `framework = arduino` → `framework = espidf` en `platformio.ini`
2. **CMakeLists.txt nativo**: PlatformIO en modo espidf usa estructura CMake de IDF
3. **IDF 4.1-4.4 compatible**: El bypass fue diseñado para estas versiones

```bash
# Estructura requerida para WSL bypass:
components/
  wsl_bypasser/
    wsl_bypasser.c    # Link-time override de ieee80211_raw_frame_sanity_check()
    CMakeLists.txt    # target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)
```

**Solución B (disponible): Rogue AP**  
Método por defecto en HEesp32. Configura ESP32 como AP falso con misma MAC/SSID que el objetivo. Cuando el cliente intenta conectar, el stack 802.11 responde naturalmente causando desconexión.

**Solución C (herramientas del host):**  
Usar herramientas del host (aireplay-ng, mdk3) en lugar del ESP32 para envío de frames deauth.

```bash
# Poner interfaz WiFi del host en modo monitor
sudo airmon-ng start wlan0 11

# Enviar frames deauth
sudo aireplay-ng --deauth 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon
```

### Tabla comparativa de métodos DEAUTH

| Método | Requisito | Efectividad | Complejidad |
|--------|-----------|--------------|--------------|
| `direct` (vanilla) | Ninguno | ❌ No funciona en ESP32 | Mínima |
| `direct` (WSL bypass) | IDF puro + CMake | ✅ Experimental | Alta |
| `rogue` (AP duplicado) | Ninguno | ⚠️ Requiere cliente activo | Media |
| Host tools (aireplay) | Adaptador WiFi con monitor | ✅ Funciona | Media |

El ESP32 sigue siendo operativo para:
- ✅ `scan`: Escaneo de APs con RSSI
- ✅ `lock&cap`: Captura de tráfico en canal específico
- ✅ `clients`: Detección de clientes asociados
- ✅ Captura de handshakes para hashcat
- ❌ `deauth`: Requiere host con monitor mode (por ahora)

---

### 🔓 Módulo CRACK - Fuerza Bruta Inteligente

HEesp32 integra `hashcat` nativamente para crackear handshakes capturados.

**Sintaxis básica:**
```bash
crack dict <pcap> <diccionario> [--rules <archivo>]
crack brute <pcap> "<máscara>"
crack hybrid <pcap> <diccionario> "<máscara>"
crack raw <pcap> <flags_hashcat...>
```

**Ejemplo pedagógico completo:**
```bash
# 1. Capturar handshake (ya hecho con lock&cap)
# 2. Crackear con diccionario + reglas:
crack dict handshake.pcap rockyou.txt --rules best64.rule --gpu-temp 65

# 3. Si falla, probar fuerza bruta para PINs de 8 dígitos:
crack brute handshake.pcap "?d?d?d?d?d?d?d?d"

# 4. Ver resultado:
crack dict handshake.pcap rockyou.txt --show
```

**Reglas hashcat (avanzado):**
Las reglas transforman palabras del diccionario (ej: "password" → "Password123!").
- `best64.rule`: 64 transformaciones comunes (añadir números, capitalizar, etc.)
- Crea las tuyas en `rules/mis_reglas.rule` y usa `--rules mis_reglas.rule`.

> 🎓 **Para clase**: Demostrar cómo una regla simple (`$1` = añadir "1" al final) multiplica x1000 el espacio de búsqueda. Enseñar que "inteligente" ≠ "mágico": es matemática aplicada.

**Charset y máscaras hashcat:**
| Carácter | Significado | Ejemplo |
|----------|-------------|---------|
| `?d` | Dígito (0-9) | `?d?d?d?d` = 4 dígitos |
| `?l` | Minúscula (a-z) | `?l?l?l` = 3 letras min |
| `?u` | Mayúscula (A-Z) | `?u?u?u` = 3 letras may |
| `?a` | Todos los caracteres | `?a?a?a` = 3 cualquier tipo |
| `?s` | Símbolos | `?s?s` = 2 símbolos |
| `?b` | Bytes (0x00-0xff) | Avanzado |

**Carátulas de progreso hashcat (para entender ETA):**
```
Speed.#1     1234.5 kH/s (12.4 MH/s) [Time: 00:12:34]  Keys: 456M/2.1B  (21.7%)  ETF: 2h 14m
```
- **kH/s**: Kilo-hashes por segundo (miles)
- **MH/s**: Mega-hashes por segundo (millones)
- **Keys**: Claves probadas / Espacio total
- **ETA**: Tiempo estimado hasta finalización
