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
from prompt_toolkit.completion import WordCompleter
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
COMMAND_LIST = ["scan", "stop", "lock", "deauth", "clients", "verify", "help", "status", "capture", "clear", "port", "ls", "exit"]

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
    global FRAME_COUNT
    buffer = bytearray()
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

def print_help() -> None:
    """Muestra la ayuda completa de comandos."""
    print("=== HEesp32 C2 - Comandos Disponibles ===")
    print("scan                    - Escanear redes WiFi (channel hopping)")
    print("stop                    - Detener operación actual")
    print("lock <MAC> <CANAL>      - Fijar canal y capturar tráfico de un AP")
    print("deauth <MAC> <CANAL> <COUNT> - Enviar frames de deauthentication (educativo)")
    print("clients <MAC>                - Detectar clientes asociados a un AP")
    print("verify <modo> <pcap> <target> - Verificar handshake (dict/brute/raw)")
    print("status                  - Mostrar estado actual del dispositivo")
    print("capture [nombre]        - Configurar archivo de captura PCAP")
    print("capture ls              - Listar capturas PCAP disponibles")
    print("capture rm <archivo>    - Eliminar captura PCAP")
    print("capture new             - Crear nueva captura con sufijo automático")
    print("port <puerto>           - Cambiar puerto serie (ej: /dev/ttyUSB1)")
    print("ls                      - Listar capturas PCAP (atajo)")
    print("clear                   - Limpiar pantalla")
    print("help                    - Mostrar esta ayuda")
    print("exit                    - Salir del programa")

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
    elif cmd_input.startswith("lock"):
        # Expected: lock A1:B2:C3:D4:E5:F6 6
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
            print("[!] Uso: lock <MAC> <CANAL>  (ejemplo: lock AA:BB:CC:DD:EE:FF 6)")
    elif cmd_input.startswith("deauth"):
        # deauth AA:BB:CC:DD:EE:FF 6 10
        match = re.match(r"deauth\s+([0-9a-fA-F:]+)\s+(\d+)\s+(\d+)", cmd_input)
        if match:
            mac = match.group(1).upper()
            channel = match.group(2)
            count = match.group(3)
            # Validar MAC (6 octetos)
            if len(mac.split(':')) == 6:
                # Validar canal 1-14
                if 1 <= int(channel) <= 14:
                    # Validar count 1-100
                    if 1 <= int(count) <= 100:
                        formatted_cmd = f"CMD:DEAUTH:{mac}:{channel}:{count}\n"
                        print("[*] Enviando frames de deauthentication (vulnerabilidad 802.11)")
                        ser.write(formatted_cmd.encode('utf-8'))
                    else:
                        print("[!] Count debe estar entre 1 y 100")
                else:
                    print("[!] Canal debe estar entre 1 y 14")
            else:
                print("[!] MAC inválida. Formato esperado: AA:BB:CC:DD:EE:FF (6 octetos separados por ':')")
        else:
            print("[!] Uso: deauth <MAC> <CANAL> <COUNT>  (ejemplo: deauth AA:BB:CC:DD:EE:FF 6 10)")
    elif cmd_input.startswith("clients"):
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
    elif cmd_input.startswith("verify"):
        parts = cmd_input.split()
        if len(parts) >= 3:
            mode = parts[1].lower()
            pcap_file = parts[2]
            
            if mode not in ["dict", "brute", "raw"]:
                print("[!] Modo inválido. Modos válidos: dict, brute, raw. Ejemplo: verify dict captura.pcap wordlist.txt")
                print_command_banner()
                return True
                
            if mode in ["dict", "brute"] and len(parts) < 4:
                print(f"[!] Uso: verify {mode} <archivo_pcap> <objetivo>  (ejemplo: verify {mode} captura.pcap wordlist.txt)")
                print_command_banner()
                return True
                
            print(f"[*] Extrayendo hashes de {pcap_file}...")
            try:
                subprocess.run(["hcxpcapngtool", "-o", "hash.hc22000", pcap_file], check=False)
            except FileNotFoundError:
                print("[!] hcxpcapngtool no encontrado en el PATH.")
                print_command_banner()
                return True
            except Exception as e:
                print(f"[!] Error al extraer hashes: {e}")
                print_command_banner()
                return True
                
            if not os.path.exists("hash.hc22000") or os.path.getsize("hash.hc22000") == 0:
                print("[!] Error: No se encontró un Handshake completo y válido en el archivo PCAP.")
                print_command_banner()
                return True
                
            print("[*] Hashcat iniciado...")
            try:
                if mode == "dict":
                    target = parts[3]
                    subprocess.run(["hashcat", "-a", "0", "-m", "22000", "hash.hc22000", target])
                elif mode == "brute":
                    target = parts[3]
                    subprocess.run(["hashcat", "-a", "3", "-m", "22000", "hash.hc22000", target])
                elif mode == "raw":
                    raw_args = parts[3:]
                    subprocess.run(["hashcat", "-m", "22000", "hash.hc22000"] + raw_args)
            except FileNotFoundError:
                print("[!] hashcat no encontrado en el PATH.")
            except Exception as e:
                print(f"[!] Error ejecutando hashcat: {e}")
        else:
            print("[!] Uso: verify dict <archivo_pcap> <diccionario_txt>")
            print("         verify brute <archivo_pcap> <mascara>")
            print("         verify raw <archivo_pcap> <argumentos_hashcat...>")
            print("         Ejemplo: verify dict captura.pcap rockyou.txt")
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
            import re
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

    completer = WordCompleter(COMMAND_LIST, ignore_case=True)
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

if __name__ == "__main__":
    main()
