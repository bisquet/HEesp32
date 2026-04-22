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
* `lock <target>`: Fija la antena en el objetivo para iniciar la captura pasiva.
* `verify dict <diccionario.txt>`: Extrae el *Handshake* y lanza el ataque por diccionario. *(Para este laboratorio utilizaremos un diccionario extraído directamente de la base de datos europea de credenciales, lo que proporcionará un escenario de colisión de hashes totalmente realista).*
* `verify brute <mask>`: Lanza el ataque de fuerza bruta pura y pone a prueba el límite térmico de la GPU (ej: `?d?d?d?d?d?d?d?d`).
* `verify dict <pcap> <diccionario.txt>`: Extrae el Handshake y lanza el ataque por diccionario. Para este laboratorio utilizaremos un diccionario extraído directamente de la base de datos europea de credenciales, lo que nos proporcionará un escenario de colisión de hashes totalmente realista para nuestro entorno.
* `verify brute <pcap> <mascara>`: Lanza el ataque de fuerza bruta pura y pone a prueba el límite térmico de la GPU (ej: ?d?d?d?d?d?d?d?d).

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

**Solución implementada:** Para demo pedagógica de deauth, usar las **herramientas del host** (aireplay-ng, mdk3) en lugar del ESP32:
```bash
# Poner interfaz WiFi del host en modo monitor
sudo airmon-ng start wlan0 11

# Enviar frames deauth
sudo aireplay-ng --deauth 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon
```

El ESP32 sigue siendo operativo para:
- ✅ `scan`: Escaneo de APs con RSSI
- ✅ `lock`: Captura de tráfico en canal específico
- ✅ `clients`: Detección de clientes asociados
- ✅ Captura de handshakes para hashcat
- ❌ `deauth`: Requiere host con monitor mode (por ahora)
