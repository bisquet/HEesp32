# 📡 HEesp32 - Plataforma de Auditoría 802.11 Bare-Metal

**Entorno de Laboratorio:** Práctica de Ciberseguridad y Redes Inalámbricas (ASIR).

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
