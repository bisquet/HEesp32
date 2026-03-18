import serial
import threading
import sys
import time
import re
import subprocess
import os
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

SERIAL_PORT = '/dev/ttyUSB0'  # Adjust if needed
BAUD_RATE = 115200

# Evento para manejar el cierre limpio de los hilos
exit_event = threading.Event()

def listener_thread(ser: serial.Serial) -> None:
    """Hilo encargado de escuchar el puerto serie e imprimir."""
    try:
        while not exit_event.is_set():
            if ser.in_waiting > 0:
                # Leer y decodificar, eliminando retornos de carro y saltos de línea al final
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    if line.startswith("[RAW] "):
                        hex_str = line[6:].strip()
                        try:
                            # Convertir hex string a bytes
                            buffer_bytes = bytes.fromhex(hex_str)
                            # Inyectar bytes en Scapy (RadioTap + Dot11 / Buffer)
                            from scapy.all import RadioTap, Dot11, wrpcap
                            # Nota: asumiendo captura pasiva en Dot11
                            pkt = RadioTap()/Dot11(buffer_bytes)
                            # Escribir a pcap (append mode)
                            wrpcap("captura_laboratorio.pcap", pkt, append=True)
                            print("[+] Trama registrada en PCAP.")
                        except Exception as e:
                            print(f"[!] Error procesando trama RAW: {e}")
                    else:
                        # Con patch_stdout en el main thread, podemos usar print() normal
                        print(f"[ESP32] {line}")
            else:
                time.sleep(0.01)
    except serial.SerialException:
        if not exit_event.is_set():
            print("\n[!] Error de lectura serial o dispositivo desconectado.")
    except Exception:
        pass # Handle exit cleanly

def parse_and_send_cmd(cmd_input: str, ser: serial.Serial) -> bool:
    """
    Parsea el comando humano y lo envía formateado al ESP32.
    Retorna False si el usuario quiere salir, True en caso contrario.
    """
    cmd_input = cmd_input.strip().lower()
    
    if cmd_input == "scan":
        ser.write(b"CMD:SCAN\n")
    elif cmd_input == "stop":
        ser.write(b"CMD:IDLE\n")
    elif cmd_input.startswith("lock"):
        # Expected: lock A1:B2:C3:D4:E5:F6 6
        match = re.match(r"lock\s+([0-9a-fA-F:]+)\s+(\d+)", cmd_input)
        if match:
            mac = match.group(1).upper()
            channel = match.group(2)
            # Validar MAC rudimentario (6 octetos)
            if len(mac.split(':')) == 6:
                formatted_cmd = f"CMD:LOCK:{mac}:{channel}\n"
                ser.write(formatted_cmd.encode('utf-8'))
            else:
                print("[!] MAC inválida. Formato esperado: AA:BB:CC:DD:EE:FF")
        else:
            print("[!] Uso: lock <MAC> <CANAL>")
    elif cmd_input.startswith("verify"):
        parts = cmd_input.split()
        if len(parts) >= 3:
            mode = parts[1].lower()
            pcap_file = parts[2]
            
            if mode not in ["dict", "brute", "raw"]:
                print("[!] Modo inválido. Usa 'dict', 'brute' o 'raw'.")
                return True
                
            if mode in ["dict", "brute"] and len(parts) < 4:
                print(f"[!] Uso: verify {mode} <archivo_pcap> <objetivo>")
                return True
                
            print(f"[*] Extrayendo hashes de {pcap_file}...")
            try:
                subprocess.run(["hcxpcapngtool", "-o", "hash.hc22000", pcap_file], check=False)
            except FileNotFoundError:
                print("[!] hcxpcapngtool no encontrado en el PATH.")
                return True
            except Exception as e:
                print(f"[!] Error al extraer hashes: {e}")
                return True
                
            if not os.path.exists("hash.hc22000") or os.path.getsize("hash.hc22000") == 0:
                print("[!] Error: No se encontró un Handshake completo y válido en el archivo PCAP.")
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
    elif cmd_input in ["exit", "quit"]:
        ser.write(b"CMD:IDLE\n") # Detener primero
        print("Saliendo...")
        return False
    elif cmd_input == "":
        pass
    else:
        print("[!] Comando no reconocido. Disponibles: scan, stop, lock <MAC> <CANAL>, verify <modo> <pcap> <target>, exit")
    
    return True

def main() -> None:
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
        print(f"Conectado a {SERIAL_PORT} a {BAUD_RATE} baudios.")
    except serial.SerialException as e:
        print(f"Error abriendo puerto serie: {e}")
        return

    try:
        from scapy.all import RadioTap, Dot11, wrpcap
    except ImportError:
        print("[!] scapy no está instalado. Instálalo con: pip install scapy")
        sys.exit(1)

    # Iniciar hilo de lectura
    listener = threading.Thread(target=listener_thread, args=(ser,), daemon=True)
    listener.start()

    print("\n--- HEesp32 C2 Consola Interactiva ---")
    print("Comandos: scan, stop, lock <MAC> <CANAL>, verify <modo> <pcap> <target>, exit\n")

    session = PromptSession()

    try:
        while True:
            # patch_stdout() redirige temporalmente stdout/stderr
            # para no romper el prompt asíncrono ni superponer texto
            with patch_stdout():
                cmd = session.prompt('HEesp32> ')
                should_continue = parse_and_send_cmd(cmd, ser)
            
            if not should_continue:
                break
                
    except KeyboardInterrupt:
        print("\n[+] Ctrl+C detectado. Deteniendo ESP32 y saliendo...")
        ser.write(b"CMD:IDLE\n")
        time.sleep(0.5)
    except EOFError:
        print("\n[+] EOF detectado. Saliendo...")
        ser.write(b"CMD:IDLE\n")
        time.sleep(0.5)
    finally:
        exit_event.set()
        ser.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
