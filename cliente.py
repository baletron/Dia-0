# cliente_pivote.py
import socket
import subprocess
import os
import sys
import platform
import threading
import time
import traceback
import ipaddress # Para manejar rangos de IP
# No se necesita netifaces con el enfoque actual de parseo de comandos

# --- Configuración ---
SERVER_HOST = '127.0.0.1'  # IP donde corre servidor_gui_tkinter.py
SERVER_PORT = 65432        # Puerto donde escucha servidor_gui_tkinter.py
SHARED_PASSWORD = "micontrasenasecreta" # Debe coincidir con la del servidor GUI
PORT_CS_DEFAULT = 65433    # Puerto por defecto donde escuchan los Clientes Secundarios
BUFFER_SIZE_CP = 8192      # Buffer para comunicación

# Lista de puertos a probar para encontrar Clientes Secundarios
CS_TARGET_PORTS_TO_SCAN = [
    PORT_CS_DEFAULT, 
    8080,
    9000,
    12345,
    8888
]

# --- Configuración de Escaneo ---
PORT_SCAN_TIMEOUT = 0.5  # Timeout para cada intento de conexión a un puerto (segundos)
MAX_SCAN_THREADS_POTENTIAL = 40 # Hilos para la fase de encontrar IPs con puertos abiertos

# --- Variables Globales del Pivote ---
connected_cs = {}
cs_id_counter = 0
_scan_results_buffer = {"potential_cs_ips": [], "connected_log": [], "failed_log": []}
_scan_results_lock = threading.Lock()


# --- Funciones de Utilidad ---
def get_shell_encoding_cp():
    system = platform.system().lower()
    encoding = 'utf-8'
    if system == "windows":
        try:
            # shell=True es necesario para que chcp funcione sin especificar la ruta completa en algunos sistemas
            result = subprocess.run(['chcp'], shell=True, capture_output=True, text=False, timeout=1)
            output_str = result.stdout.decode('ascii', errors='ignore')
            import re
            match = re.search(r'(\d+)', output_str)
            if match: encoding = f'cp{match.group(1)}'
            else: encoding = 'cp850' # Fallback si la salida de chcp no es parseable
        except Exception: # Incluye TimeoutExpired, FileNotFoundError, etc.
            encoding = 'cp850' # Fallback general para Windows si chcp falla
    return encoding

current_shell_encoding_cp = get_shell_encoding_cp()


# --- Funciones para manejar Clientes Secundarios (CS) ---
def connect_to_cs_multiport(cs_ip, target_ports_list):
    global cs_id_counter
    for port_to_try in target_ports_list:
        try:
            cs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Timeout un poco mayor para la conexión real que para el sondeo
            cs_sock.settimeout(PORT_SCAN_TIMEOUT + 0.3) 
            cs_sock.connect((cs_ip, port_to_try))
            cs_sock.settimeout(None) # Quitar timeout para operaciones normales
            cs_id_counter += 1
            cs_id = f"cs{cs_id_counter}"
            connected_cs[cs_id] = {'socket': cs_sock, 'addr': (cs_ip, port_to_try)}
            success_msg = f"Conectado a CS {cs_id} ({cs_ip} en puerto {port_to_try})"
            print(f"CP: {success_msg}")
            return cs_id, success_msg, port_to_try
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue # Probar el siguiente puerto
        except Exception as e:
            print(f"CP connect_multiport: Error general en {cs_ip}:{port_to_try} - {e}")
            continue # Probar el siguiente puerto
    return None, f"CP Error: No se pudo conectar a CS en {cs_ip} en puertos probados: {target_ports_list}", None

def disconnect_from_cs(cs_id):
    if cs_id in connected_cs:
        cs_data = connected_cs[cs_id]
        try:
            if cs_data['socket'].fileno() != -1: # Comprobar si el socket no está ya cerrado
                cs_data['socket'].sendall(b'cs_salir') # Notificar al CS
                time.sleep(0.05) # Pequeña pausa para que el CS procese
                cs_data['socket'].close()
        except (socket.error, OSError):
            # El socket podría estar ya cerrado o en mal estado
            pass 
        finally:
            # Asegurar que se elimina del diccionario incluso si el close falla
            if cs_id in connected_cs: # Volver a comprobar por si acaso
                 del connected_cs[cs_id]
        print(f"CP: Desconectado de Cliente Secundario {cs_id}")
        return f"Desconectado de CS {cs_id}"
    return f"CP Error: CS ID '{cs_id}' no encontrado o ya desconectado."

def send_command_to_cs(cs_id, command):
    if cs_id not in connected_cs: return f"CP Error: CS ID '{cs_id}' no conectado."
    cs_data = connected_cs[cs_id]
    cs_sock = cs_data['socket']
    response_str = f"[CP: Falla comunicación con CS {cs_id}]" # Default
    try:
        if cs_sock.fileno() == -1: return f"[CP: Socket CS {cs_id} ya está cerrado.]"
        
        cs_sock.sendall(command.encode('utf-8'))
        
        parts = []
        cs_sock.settimeout(60.0) # Timeout para la respuesta del CS
        while True:
            chunk = cs_sock.recv(BUFFER_SIZE_CP)
            if not chunk: 
                response_str = f"[CP: CS {cs_id} cerró conexión o no envió respuesta completa]"
                disconnect_from_cs(cs_id) # Intentar limpiar si el CS cierra
                break
            parts.append(chunk)
            if len(chunk) < BUFFER_SIZE_CP: break # Heurística de fin de mensaje
        cs_sock.settimeout(None) # Restaurar timeout
        
        if parts: response_str = b"".join(parts).decode('utf-8', errors='replace').strip()

    except socket.timeout: response_str = f"[CP: Timeout esperando respuesta de CS {cs_id}]"
    except (socket.error, OSError) as e: # OSError para fileno en socket cerrado
        response_str = f"[CP: Error de socket con CS {cs_id}: {e}]"
        disconnect_from_cs(cs_id) # Limpiar si hay error de socket
    return response_str

def list_connected_cs():
    if not connected_cs: return "CP: No hay Clientes Secundarios conectados."
    cs_list = "CP: Clientes Secundarios Conectados:\n"
    for cs_id_key in list(connected_cs.keys()): # Iterar sobre una copia
        if cs_id_key in connected_cs: # Volver a comprobar por si acaso
            data = connected_cs[cs_id_key]
            cs_list += f"  - {cs_id_key}: {data['addr'][0]}:{data['addr'][1]}\n"
    return cs_list.strip()


# --- Funciones de Escaneo de Red en el Pivote ---
def check_cs_port_availability_detailed(ip, port, timeout=PORT_SCAN_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_check:
            s_check.settimeout(timeout)
            s_check.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError): return False
    except Exception: return False # Otros errores inesperados

def scan_potential_cs_worker_detailed(ip_to_check, ports_to_try_list, local_buffer, local_lock):
    for port in ports_to_try_list:
        if check_cs_port_availability_detailed(str(ip_to_check), port):
            # print(f"CP Worker Escaneo: Puerto {port} ABIERTO en {ip_to_check}.") # Log verboso
            with local_lock:
                if str(ip_to_check) not in local_buffer:
                    local_buffer.append(str(ip_to_check))
            return # Encontró un puerto, suficiente para marcar la IP como potencial

def get_local_subnets_to_scan_cmd():
    subnets = []
    print("CP Detección de Subred (cmd): Intentando obtener IPs locales...")
    try:
        if platform.system().lower() == "windows":
            # Usar errors='ignore' para evitar problemas con codificaciones raras en la salida de ipconfig
            proc = subprocess.run("ipconfig", capture_output=True, text=True, shell=True, timeout=5, errors="ignore")
            current_ip = None
            for line in proc.stdout.splitlines():
                line_lower = line.lower().strip() # strip() para quitar espacios extra
                if "ipv4 address" in line_lower or "dirección ipv4" in line_lower :
                    parts = line.split(':')
                    if len(parts) > 1: current_ip = parts[1].strip()
                elif ("subnet mask" in line_lower or "máscara de subred" in line_lower) and current_ip:
                    parts = line.split(':')
                    if len(parts) > 1:
                        netmask = parts[1].strip()
                        # Validar IPs y máscaras antes de usarlas
                        if current_ip and netmask and not current_ip.startswith("169.254") and current_ip != "0.0.0.0":
                            try:
                                ipaddress.ip_address(current_ip) # Validar IP
                                ipaddress.ip_address(netmask)    # Validar máscara (como IP)
                                iface = ipaddress.ip_interface(f"{current_ip}/{netmask}")
                                network_cidr = str(iface.network)
                                if network_cidr not in subnets and not iface.is_loopback and not iface.is_link_local:
                                    subnets.append(network_cidr)
                                    print(f"CP Detección (ipconfig): Subred {network_cidr} (IP: {current_ip})")
                                current_ip = None # Resetear para la siguiente interfaz
                            except ValueError: # Error al parsear IP, máscara o interfaz
                                print(f"CP Detección (ipconfig): Error parseando {current_ip}/{netmask}")
                                current_ip = None 
        else: # Linux o macOS
            try: # Intentar con 'ip addr'
                proc = subprocess.run("ip addr", capture_output=True, text=True, shell=True, timeout=5, errors="ignore")
                for line in proc.stdout.splitlines():
                    line_strip = line.strip()
                    if line_strip.startswith("inet "):
                        parts = line_strip.split()
                        if len(parts) >= 2 and "/" in parts[1]: # Buscar formato IP/CIDR
                            ip_cidr = parts[1]
                            if not ip_cidr.startswith("127.") and not ip_cidr.startswith("169.254"):
                                try:
                                    iface = ipaddress.ip_interface(ip_cidr)
                                    network_cidr = str(iface.network)
                                    if network_cidr not in subnets and not iface.is_loopback and not iface.is_link_local:
                                        subnets.append(network_cidr)
                                        print(f"CP Detección (ip addr): Subred {network_cidr}")
                                except ValueError: pass # Ignorar si el parseo de ip_interface falla
                if not subnets: raise subprocess.CalledProcessError(1, "ip addr") # Forzar ifconfig si no hay resultados
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("CP Detección (cmd): 'ip addr' falló o no encontrado, intentando 'ifconfig'...")
                try:
                    proc_ifc = subprocess.run("ifconfig", capture_output=True, text=True, shell=True, timeout=5, errors="ignore")
                    current_ip_ifc, current_mask_ifc = None, None
                    for line in proc_ifc.stdout.splitlines():
                        line_s = line.strip().lower()
                        # Lógica de parseo para ifconfig (puede variar mucho entre sistemas)
                        if line_s.startswith("inet ") or "inet addr:" in line_s : # Formatos comunes
                            parts = line_s.split()
                            ip_val, mask_val = None, None
                            try: # Intentar extraer IP y máscara
                                if "inet " in line_s : ip_val = parts[parts.index("inet")+1]
                                elif "inet addr:" in line_s: ip_val = line_s.split("inet addr:")[1].split()[0]
                                
                                if "netmask " in line_s: mask_val = parts[parts.index("netmask")+1]
                                elif "mask " in line_s: mask_val = parts[parts.index("mask")+1] # macOS
                            except (ValueError, IndexError): continue

                            if ip_val and mask_val and not ip_val.startswith("127.") and not ip_val.startswith("169.254"):
                                try:
                                    iface = ipaddress.ip_interface(f"{ip_val}/{mask_val}")
                                    network_cidr = str(iface.network)
                                    if network_cidr not in subnets and not iface.is_loopback and not iface.is_link_local:
                                        subnets.append(network_cidr)
                                        print(f"CP Detección (ifconfig): Subred {network_cidr}")
                                except ValueError: pass
                except Exception as e_nix: print(f"CP Detección (cmd): Nix cmd error: {e_nix}")
    except subprocess.TimeoutExpired: print("CP Detección (cmd): Timeout ejecutando comando de red.")
    except Exception as e_cmd: print(f"CP Detección (cmd): Error inesperado: {e_cmd}"); traceback.print_exc()
    
    if not subnets: # Si todo falla, un default muy común
        default_subnet = "192.168.1.0/24"
        print(f"CP Detección de Subred (cmd): No se detectaron subredes, usando default: {default_subnet}")
        subnets.append(default_subnet)
            
    return list(set(subnets)) # Devolver subredes únicas


def scan_network_and_attempt_cs_connections(ip_range_str_param=None):
    global _scan_results_buffer, _scan_results_lock
    with _scan_results_lock: # Resetear buffer para este escaneo
        _scan_results_buffer = {"potential_cs_ips": [], "connected_log": [], "failed_log": []}

    subnets_to_scan_final = [ip_range_str_param] if ip_range_str_param else get_local_subnets_to_scan_cmd()
    if not subnets_to_scan_final:
        return f"CP Error Escaneo: No se pudieron determinar subredes para escanear.\n{list_connected_cs()}"

    print(f"CP Escaneo: Subredes a escanear: {subnets_to_scan_final}")
    print(f"CP Escaneo: Puertos objetivo para CS: {CS_TARGET_PORTS_TO_SCAN}")

    all_potential_ips_overall = []
    for subnet_cidr in subnets_to_scan_final:
        print(f"CP Escaneo: Procesando subred {subnet_cidr}...")
        try:
            network_to_scan = ipaddress.ip_network(subnet_cidr, strict=False)
        except ValueError:
            with _scan_results_lock: _scan_results_buffer["failed_log"].append(f"{subnet_cidr}: Rango IP inválido.")
            continue

        scan_threads_phase1_subnet = []
        hosts_in_subnet = list(network_to_scan.hosts())
        if not hosts_in_subnet: print(f"CP Escaneo: No hay hosts válidos en {subnet_cidr}."); continue
        print(f"CP Escaneo Fase 1 (Subred {subnet_cidr}): Verificando {len(hosts_in_subnet)} hosts...")

        current_subnet_potential_ips = [] # Buffer local para esta subred
        _current_subnet_potential_lock = threading.Lock() # Lock para el buffer local

        for ip_obj in hosts_in_subnet:
            # Limpiar hilos terminados y controlar el máximo
            scan_threads_phase1_subnet = [t for t in scan_threads_phase1_subnet if t.is_alive()]
            while len(scan_threads_phase1_subnet) >= MAX_SCAN_THREADS_POTENTIAL:
                time.sleep(0.05); scan_threads_phase1_subnet = [t for t in scan_threads_phase1_subnet if t.is_alive()]
            
            thread = threading.Thread(target=scan_potential_cs_worker_detailed, 
                                      args=(str(ip_obj), CS_TARGET_PORTS_TO_SCAN, current_subnet_potential_ips, _current_subnet_potential_lock), 
                                      daemon=True)
            thread.start(); scan_threads_phase1_subnet.append(thread)
            
        # Esperar a que terminen los hilos de la subred actual
        for t_idx, t in enumerate(scan_threads_phase1_subnet):
            t.join(timeout=(PORT_SCAN_TIMEOUT * len(CS_TARGET_PORTS_TO_SCAN)) + 1.5) # Timeout por hilo
            # print(f"CP Escaneo Fase 1 (Subred {subnet_cidr}): Hilo {t_idx+1} completado.") # Log muy verboso
        
        all_potential_ips_overall.extend(current_subnet_potential_ips) # Acumular IPs potenciales
        print(f"CP Escaneo Fase 1 (Subred {subnet_cidr}): {len(current_subnet_potential_ips)} IPs potenciales encontradas en esta subred.")

    unique_overall_potential_ips = sorted(list(set(all_potential_ips_overall)))
    print(f"CP Escaneo Fase 2: Intentando conectar a {len(unique_overall_potential_ips)} CS potenciales únicos en total: {unique_overall_potential_ips}")

    for cs_ip_to_try in unique_overall_potential_ips:
        already_conn = any(data['addr'][0] == cs_ip_to_try for data in connected_cs.values())
        if already_conn:
            # print(f"CP Escaneo Fase 2: CS en IP {cs_ip_to_try} ya está conectado. Omitiendo.")
            continue
        
        # print(f"CP Escaneo Fase 2: Intentando conectar a {cs_ip_to_try} en puertos {CS_TARGET_PORTS_TO_SCAN}...") # Log verboso
        cs_id, msg, _ = connect_to_cs_multiport(cs_ip_to_try, CS_TARGET_PORTS_TO_SCAN)
        with _scan_results_lock:
            if cs_id: _scan_results_buffer["connected_log"].append(f"{cs_id}: {msg}")
            else: _scan_results_buffer["failed_log"].append(f"{cs_ip_to_try}: {msg}")
    
    summary = f"CP Escaneo para subred(es) '{', '.join(subnets_to_scan_final)}' (Puertos: {CS_TARGET_PORTS_TO_SCAN}) Completado.\n"
    with _scan_results_lock:
        if _scan_results_buffer["connected_log"]: summary += "CS Conectados/Verificados:\n" + "\n".join([f"  - {log}" for log in _scan_results_buffer["connected_log"]]) + "\n"
        if _scan_results_buffer["failed_log"]: summary += "Fallos al Conectar CS:\n" + "\n".join([f"  - {log}" for log in _scan_results_buffer["failed_log"]]) + "\n"
        if not _scan_results_buffer["connected_log"] and not _scan_results_buffer["failed_log"]:
            summary += "No se encontraron/conectaron nuevos CS.\n" if unique_overall_potential_ips else "No se encontraron IPs con puertos abiertos.\n"
    
    final_response_to_gui = f"{summary}\n--- INICIO LISTA CS ACTUAL ---\n{list_connected_cs()}\n--- FIN LISTA CS ACTUAL ---"
    print(f"CP Escaneo: Enviando respuesta a GUI (primeros 500 chars):\n{final_response_to_gui[:500]}...")
    return final_response_to_gui


# --- Bucle Principal del Cliente Pivote ---
def start_client_pivote():
    print(f"Cliente Pivote. Codificación shell: {current_shell_encoding_cp}")
    s_to_gui = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s_to_gui.connect((SERVER_HOST, SERVER_PORT))
        print(f"CP: Conectado al Servidor GUI en {SERVER_HOST}:{SERVER_PORT}")
    except ConnectionRefusedError:
        print(f"CP: No se pudo conectar al Servidor GUI en {SERVER_HOST}:{SERVER_PORT}. ¿Está escuchando?")
        return
    except Exception as e:
        print(f"CP: Error conectando al Servidor GUI: {e}"); return

    current_path_cp = os.getcwd()
    try:
        auth_status = s_to_gui.recv(1024).decode('utf-8', errors='ignore').strip()
        if not auth_status: print("CP: Servidor GUI cerró antes de auth."); return
        if auth_status == "AUTH_REQUEST":
            s_to_gui.sendall(SHARED_PASSWORD.encode('utf-8'))
            auth_resp = s_to_gui.recv(1024).decode('utf-8', errors='ignore').strip()
            if not auth_resp: print("CP: Servidor GUI cerró tras enviar pass."); return
            if auth_resp == "AUTH_SUCCESS":
                print("CP: Autorización con Servidor GUI OK.")
                s_to_gui.sendall(platform.system().lower().encode('utf-8'))
            else: print("CP: Fallo de autorización por Servidor GUI."); return
        else: print(f"CP: Protocolo auth GUI inesperado ('{auth_status}')."); return

        while True:
            cmd_bytes = s_to_gui.recv(BUFFER_SIZE_CP)
            if not cmd_bytes: print("CP: Servidor GUI cerró conexión."); break
            cmd_from_gui = cmd_bytes.decode('utf-8', errors='ignore').strip()
            print(f"CP: Recibido del Servidor GUI: '{cmd_from_gui}'")

            if cmd_from_gui.lower() == 'salir': print("CP: Servidor GUI solicitó cierre."); break
            
            response = ""
            if cmd_from_gui.startswith("cp_scan_and_connect_cs"):
                parts = cmd_from_gui.split(" ", 1)
                scan_range_param = parts[1] if len(parts) > 1 else None
                print(f"CP: Iniciando escaneo CS (rango: {scan_range_param or 'auto-detectado por Pivote'})...")
                response = scan_network_and_attempt_cs_connections(scan_range_param)
            elif cmd_from_gui.startswith("cp_connect_cs "):
                parts = cmd_from_gui.split(" ", 2)
                if len(parts) >= 2:
                    ip_param, p_list_param = parts[1], CS_TARGET_PORTS_TO_SCAN
                    if len(parts) == 3: # Si se especifica un puerto, probar solo ese
                        try: p_list_param = [int(parts[2])]
                        except ValueError: response = "CP Error: Puerto CS inválido para conexión directa.";
                    if not response: 
                        _id, msg, _p = connect_to_cs_multiport(ip_param, p_list_param)
                        response = f"{msg}\n\n--- INICIO LISTA CS ACTUAL ---\n{list_connected_cs()}\n--- FIN LISTA CS ACTUAL ---"
                else: response = "CP Error: Uso: cp_connect_cs <ip> [puerto_opc]"
            elif cmd_from_gui.startswith("cp_disconnect_cs "):
                parts = cmd_from_gui.split(" ", 1)
                if len(parts) == 2: 
                    disconnect_msg = disconnect_from_cs(parts[1])
                    response = f"{disconnect_msg}\n\n--- INICIO LISTA CS ACTUAL ---\n{list_connected_cs()}\n--- FIN LISTA CS ACTUAL ---"
                else: response = "CP Error: Uso: cp_disconnect_cs <id>"
            elif cmd_from_gui == "cp_list_cs":
                cs_list_output = list_connected_cs()
                response = f"--- INICIO LISTA CS ACTUAL ---\n{cs_list_output}\n--- FIN LISTA CS ACTUAL ---"
            elif cmd_from_gui.startswith("remote "):
                parts = cmd_from_gui.split(" ", 2)
                if len(parts) == 3: response = send_command_to_cs(parts[1], parts[2])
                else: response = "CP Error: Uso: remote <id_cs> <comando>"
            elif cmd_from_gui.startswith("cd "):
                try:
                    pth_str = cmd_from_gui.split(" ", 1)[1]
                    if pth_str.startswith(('"', "'")) and pth_str.endswith(('"', "'")): pth_str = pth_str[1:-1]
                    os.chdir(pth_str); current_path_cp = os.getcwd()
                    response = f"CP Dir cambiado a: {current_path_cp}"
                except FileNotFoundError: response = f"CP Error: Dir no encontrado '{pth_str}'"
                except Exception as e_cd: response = f"CP Error cd: {str(e_cd)}"
            else: 
                try:
                    res = subprocess.run(cmd_from_gui, shell=True, capture_output=True, cwd=current_path_cp, timeout=60, text=False)
                    o_res = res.stdout.decode(current_shell_encoding_cp, errors='replace').strip()
                    e_res = res.stderr.decode(current_shell_encoding_cp, errors='replace').strip()
                    if o_res: response += o_res
                    if e_res:
                        newline_before_stderr = "\n" if o_res else ""
                        response += f"{newline_before_stderr}[CP_STDERR]\n{e_res}"
                    if not response.strip(): response = "[CP: Sin salida]"
                except subprocess.TimeoutExpired: response = "CP Error: Timeout comando local."
                except Exception as e_sub_proc: response = f"CP Error cmd local: {str(e_sub_proc)}"
            
            if s_to_gui.fileno() != -1: s_to_gui.sendall(response.encode('utf-8', errors='replace'))
            else: print("CP: Socket GUI cerrado, no se envió respuesta."); break
    
    except (socket.error, ConnectionResetError, BrokenPipeError) as e_sock:
        print(f"CP: Conexión/Error socket con Servidor GUI: {e_sock}")
    except Exception as e_main_loop:
        print(f"CP: Error inesperado: {e_main_loop}"); traceback.print_exc()
    finally:
        print("CP: Terminando...")
        for cs_id_key in list(connected_cs.keys()): disconnect_from_cs(cs_id_key)
        if s_to_gui and s_to_gui.fileno() != -1: s_to_gui.close()
        print("CP: Finalizado.")

if __name__ == "__main__":
    start_client_pivote()