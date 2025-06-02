# servidor_gui_tkinter.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import socket
import threading
import time
import queue
import traceback
import sys

# --- Configuración ---
HOST_GUI_SERVER = '0.0.0.0'
PORT_GUI_SERVER = 65432
SHARED_PASSWORD = "micontrasenasecreta"
BUFFER_SIZE = 8192

# --- Variables Globales ---
gui_root = None
log_text_widget = None
status_label_widget = None
pivote_status_label_widget = None
cs_list_widget = None
command_output_widget = None
btn_start_server = None
btn_stop_server = None
scan_ip_range_entry_widget = None # Definir globalmente para que build_gui la cree

pivote_socket_global = None
pivote_address_global = None
pivote_os_type_global = "N/A"
pivote_communication_thread = None

gui_server_socket_listener = None
gui_server_listener_thread = None

stop_event_global = threading.Event()
command_queue_to_pivote = queue.Queue()
response_queue_from_pivote = queue.Queue()
gui_ready_event = threading.Event()

is_pivote_processing_long_command = False # Nueva bandera
pivote_processing_lock = threading.Lock() # Lock para la bandera

# --- Estilos ---
FONT_PRIMARY = ("Segoe UI", 10)
FONT_LOG = ("Courier New", 9)

# --- Funciones de la GUI ---
def log_message_gui(message, tag=None):
    if gui_ready_event.is_set() and log_text_widget:
        timestamp = time.strftime("%H:%M:%S")
        def update_log():
            log_text_widget.config(state=tk.NORMAL)
            log_text_widget.insert(tk.END, f"[{timestamp}] {message}\n", tag)
            log_text_widget.see(tk.END)
            log_text_widget.config(state=tk.DISABLED)
        gui_root.after(0, update_log)
    print(f"LOG GUI: {message}")

def update_status_bar_gui(message):
    if gui_ready_event.is_set() and status_label_widget:
        gui_root.after(0, lambda: status_label_widget.config(text=message))

def update_pivote_status_gui(is_connected=False, address=None, os_type="N/A"):
    global pivote_os_type_global
    if gui_ready_event.is_set() and pivote_status_label_widget:
        if is_connected and address:
            pivote_os_type_global = os_type
            status_text = f"Pivote Conectado: {address[0]}:{address[1]} (OS: {os_type})"
            color = "green"
        else:
            pivote_os_type_global = "N/A"
            status_text = "Pivote Desconectado"
            color = "red"
        gui_root.after(0, lambda: pivote_status_label_widget.config(text=status_text, foreground=color))

def clear_command_output_gui():
    if gui_ready_event.is_set() and command_output_widget:
        def do_clear():
            command_output_widget.config(state=tk.NORMAL)
            command_output_widget.delete(1.0, tk.END)
            command_output_widget.config(state=tk.DISABLED)
        gui_root.after(0, do_clear)

def show_command_output_gui(output_text):
    if gui_ready_event.is_set() and command_output_widget:
        def do_show():
            command_output_widget.config(state=tk.NORMAL)
            command_output_widget.insert(tk.END, output_text + "\n")
            command_output_widget.see(tk.END)
            command_output_widget.config(state=tk.DISABLED)
        gui_root.after(0, do_show)

def update_cs_list_gui(full_response_from_pivote):
    if gui_ready_event.is_set() and cs_list_widget:
        def do_update():
            cs_list_widget.delete(0, tk.END)
            start_marker = "--- inicio lista cs actual ---" # Asegurarse que coincida con el pivote
            # ... (resto de la lógica de update_cs_list_gui como en la respuesta anterior,
            #      la que tenía el parseo mejorado con marcadores)
            end_marker = "--- fin lista cs actual ---"
            response_lower = full_response_from_pivote.lower()
            actual_cs_list_content = ""

            if start_marker in response_lower:
                start_index = response_lower.find(start_marker) + len(start_marker)
                end_index = response_lower.find(end_marker, start_index)
                if end_index != -1:
                    actual_cs_list_content = full_response_from_pivote[start_index:end_index].strip()
                else:
                    actual_cs_list_content = full_response_from_pivote[start_index:].strip()
            else:
                if "cp: clientes secundarios conectados:" in response_lower:
                    actual_cs_list_content = full_response_from_pivote.split("CP: Clientes Secundarios Conectados:", 1)[-1].strip()
                elif "no hay clientes secundarios" in response_lower:
                    actual_cs_list_content = "CP: No hay Clientes Secundarios conectados."

            if actual_cs_list_content:
                if "no hay clientes secundarios" in actual_cs_list_content.lower():
                    cs_list_widget.insert(tk.END, " (No CS reportados) ")
                    return
                lines = actual_cs_list_content.split('\n')
                cs_found = False
                for line in lines:
                    line_strip = line.strip()
                    if line_strip.lower().startswith("- cs") or \
                       (line_strip.lower().startswith("cs") and ":" in line_strip and "conectados" not in line_strip.lower()):
                        cs_list_widget.insert(tk.END, line_strip)
                        cs_found = True
                if not cs_found and actual_cs_list_content.strip():
                    cs_list_widget.insert(tk.END, " (Formato de lista CS no reconocido) ")
            else:
                 cs_list_widget.insert(tk.END, " (Lista de CS no obtenida/vacía) ")
        gui_root.after(0, do_update)


# --- Lógica de Red ---
def process_responses_for_gui():
    # ... (código de process_responses_for_gui como en la respuesta anterior)
    try:
        while not response_queue_from_pivote.empty():
            command_sent, response_data = response_queue_from_pivote.get_nowait()
            show_command_output_gui(f"Respuesta para '{command_sent}':\n{response_data}")
            if command_sent.startswith("cp_scan_and_connect_cs") or \
               command_sent.startswith("cp_connect_cs") or \
               command_sent.startswith("cp_disconnect_cs") or \
               command_sent == "cp_list_cs":
                update_cs_list_gui(response_data)
            response_queue_from_pivote.task_done()
    except queue.Empty: pass
    finally:
        if gui_ready_event.is_set() and not stop_event_global.is_set():
            gui_root.after(100, process_responses_for_gui)

def pivote_command_sender_receiver_thread():
    global pivote_socket_global, is_pivote_processing_long_command
    log_message_gui("Hilo de comunicación con Pivote iniciado.", "info_tag")
    while not stop_event_global.is_set():
        command_to_send_for_log = "N/A"
        response_parts = [] # Definir response_parts al inicio del bucle try
        try:
            if not pivote_socket_global or pivote_socket_global.fileno() == -1:
                with pivote_processing_lock: is_pivote_processing_long_command = False # Asegurar que se libera
                time.sleep(0.1); continue

            command_to_send = command_queue_to_pivote.get(timeout=0.5)
            command_to_send_for_log = command_to_send
            if command_to_send is None: break
            
            with pivote_processing_lock: is_pivote_processing_long_command = True

            log_message_gui(f"Enviando al Pivote: '{command_to_send}'", "send_tag")
            pivote_socket_global.sendall(command_to_send.encode('utf-8'))
            
            receive_timeout = 300.0 if command_to_send.startswith("cp_scan_and_connect_cs") else 60.0
            pivote_socket_global.settimeout(receive_timeout)
            log_message_gui(f"Esperando respuesta del Pivote para '{command_to_send}' (timeout: {receive_timeout}s)...")
            
            while True:
                try:
                    chunk = pivote_socket_global.recv(BUFFER_SIZE)
                    if not chunk:
                        log_message_gui(f"Pivote cerró conexión (0 bytes recv) para '{command_to_send}'.", "error_tag")
                        response_queue_from_pivote.put((command_to_send, f"ERROR: Pivote cerró conexión."))
                        with pivote_processing_lock: is_pivote_processing_long_command = False
                        close_and_cleanup_pivote_connection()
                        command_queue_to_pivote.task_done() # Marcar tarea como hecha (con error)
                        return # Terminar este hilo
                    response_parts.append(chunk)
                except socket.timeout:
                    log_message_gui(f"Timeout parcial recv para '{command_to_send}', fin de datos.", "info_tag")
                    break
            
            pivote_socket_global.settimeout(None)

            if response_parts:
                full_response = b"".join(response_parts).decode('utf-8', errors='replace').strip()
                response_queue_from_pivote.put((command_to_send, full_response))
            elif pivote_socket_global and pivote_socket_global.fileno() != -1:
                response_queue_from_pivote.put((command_to_send, "[Pivote: Sin respuesta significativa]"))
            
            with pivote_processing_lock: is_pivote_processing_long_command = False
            command_queue_to_pivote.task_done()
        except queue.Empty:
            with pivote_processing_lock:
                if not command_queue_to_pivote.qsize() > 0: is_pivote_processing_long_command = False
            continue
        except socket.timeout: # Timeout del get() o del settimeout() global
            log_message_gui(f"Timeout general en comando '{command_to_send_for_log}'.", "error_tag")
            response_queue_from_pivote.put((command_to_send_for_log, f"ERROR: Timeout general Pivote."))
            with pivote_processing_lock: is_pivote_processing_long_command = False
            close_and_cleanup_pivote_connection()
        except (socket.error, ConnectionResetError, BrokenPipeError, OSError) as e:
            if not stop_event_global.is_set():
                log_message_gui(f"Error socket Pivote ('{command_to_send_for_log}'): {e}", "error_tag")
                response_queue_from_pivote.put((command_to_send_for_log, f"ERROR: Socket Pivote - {e}"))
            with pivote_processing_lock: is_pivote_processing_long_command = False
            close_and_cleanup_pivote_connection()
        except Exception as e:
            if not stop_event_global.is_set():
                log_message_gui(f"Error inesperado comm thread ({command_to_send_for_log}): {e}", "error_tag"); traceback.print_exc()
            response_queue_from_pivote.put((command_to_send_for_log, f"ERROR INESPERADO: {e}"))
            with pivote_processing_lock: is_pivote_processing_long_command = False
    log_message_gui("Hilo de comunicación con Pivote terminado.", "info_tag")
    with pivote_processing_lock: is_pivote_processing_long_command = False


def handle_single_pivote_connection(conn, addr):
    # ... (código de handle_single_pivote_connection como en la respuesta anterior)
    global pivote_socket_global, pivote_address_global, pivote_communication_thread
    log_message_gui(f"Intento de conexión del Pivote desde: {addr}")
    temp_pivote_os_type = "N/A"
    is_authenticated_and_active = False
    try:
        conn.sendall(b"AUTH_REQUEST")
        password_bytes = conn.recv(1024)
        if not password_bytes: log_message_gui(f"Pivote {addr} desconectado (pass).", "error_tag"); conn.close(); return
        password = password_bytes.decode('utf-8', errors='ignore').strip()

        if password == SHARED_PASSWORD:
            conn.sendall(b"AUTH_SUCCESS")
            os_type_bytes = conn.recv(1024)
            if not os_type_bytes: log_message_gui(f"Pivote {addr} desconectado (OS).", "error_tag"); conn.close(); return
            
            temp_pivote_os_type = os_type_bytes.decode('utf-8', errors='ignore').strip().capitalize()
            log_message_gui(f"Pivote {addr} autenticado. OS: {temp_pivote_os_type}", "success_tag")
            
            close_and_cleanup_pivote_connection() 
            pivote_socket_global = conn
            pivote_address_global = addr
            update_pivote_status_gui(True, addr, temp_pivote_os_type)
            is_authenticated_and_active = True

            if not pivote_communication_thread or not pivote_communication_thread.is_alive():
                pivote_communication_thread = threading.Thread(target=pivote_command_sender_receiver_thread, daemon=True)
                pivote_communication_thread.start()
            else:
                log_message_gui("Advertencia: Hilo de comunicación ya estaba activo.", "info_tag")

            command_queue_to_pivote.put("cp_list_cs") 
            
            while not stop_event_global.is_set() and pivote_socket_global == conn and conn.fileno() != -1:
                try:
                    conn.settimeout(1.0)
                    data_peek = conn.recv(1, socket.MSG_PEEK) 
                    if not data_peek: 
                        log_message_gui(f"Pivote {addr} desconectado (peek 0 bytes).", "info_tag")
                        break 
                    conn.settimeout(None)
                except socket.timeout: continue
                except (socket.error, OSError): 
                    log_message_gui(f"Socket Pivote {addr} cerrado o error (peek).", "error_tag")
                    break 
                time.sleep(0.5) 
        else: 
            conn.sendall(b"AUTH_FAIL"); log_message_gui(f"Fallo auth Pivote {addr}.", "error_tag"); conn.close()
    except (socket.error, ConnectionResetError, BrokenPipeError) as e:
        if not stop_event_global.is_set(): log_message_gui(f"Conexión Pivote {addr} perdida: {e}", "error_tag")
    except Exception as e:
        if not stop_event_global.is_set(): log_message_gui(f"Error inesperado Pivote {addr}: {e}", "error_tag"); traceback.print_exc()
    finally:
        if is_authenticated_and_active and pivote_socket_global == conn : 
            close_and_cleanup_pivote_connection() 
        elif conn.fileno() != -1 : 
            conn.close()
        log_message_gui(f"Hilo de manejo para {addr} terminado.", "info_tag")


def gui_server_listener_loop():
    # ... (código de gui_server_listener_loop como en la respuesta anterior)
    global gui_server_socket_listener
    temp_listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        temp_listener_socket.bind((HOST_GUI_SERVER, PORT_GUI_SERVER))
        temp_listener_socket.listen(1)
        gui_server_socket_listener = temp_listener_socket
        log_message_gui(f"Servidor GUI escuchando en {HOST_GUI_SERVER}:{PORT_GUI_SERVER}", "info_tag")
        update_status_bar_gui(f"Escuchando en {HOST_GUI_SERVER}:{PORT_GUI_SERVER}")
    except OSError as e:
        log_message_gui(f"No se pudo iniciar servidor GUI: {e}", "error_tag")
        update_status_bar_gui(f"ERROR al iniciar escucha: {e}")
        if gui_ready_event.is_set():
            if btn_start_server: gui_root.after(0, lambda: btn_start_server.config(state=tk.NORMAL))
            if btn_stop_server: gui_root.after(0, lambda: btn_stop_server.config(state=tk.DISABLED))
        return
    while not stop_event_global.is_set():
        try:
            gui_server_socket_listener.settimeout(1.0)
            conn, addr = gui_server_socket_listener.accept()
            gui_server_socket_listener.settimeout(None)
            if pivote_socket_global and pivote_socket_global.fileno() != -1:
                log_message_gui(f"Pivote {addr} rechazado, ya hay uno.", "error_tag")
                conn.sendall(b"ERROR Servidor ocupado.\n"); conn.close()
            else:
                threading.Thread(target=handle_single_pivote_connection, args=(conn, addr), daemon=True).start()
        except socket.timeout: continue
        except OSError: 
            if not stop_event_global.is_set(): log_message_gui("Socket de escucha GUI cerrado.", "error_tag")
            break 
        except Exception as e:
            if not stop_event_global.is_set(): log_message_gui(f"Error aceptando conexión Pivote: {e}", "error_tag")
            time.sleep(0.5)
    if gui_server_socket_listener: gui_server_socket_listener.close(); gui_server_socket_listener = None
    log_message_gui("Hilo de escucha GUI detenido.", "info_tag")
    if gui_ready_event.is_set():
        update_status_bar_gui("Servidor GUI Detenido")
        if btn_start_server: gui_root.after(0, lambda: btn_start_server.config(state=tk.NORMAL))
        if btn_stop_server: gui_root.after(0, lambda: btn_stop_server.config(state=tk.DISABLED))


def close_and_cleanup_pivote_connection():
    # ... (código de close_and_cleanup_pivote_connection como en la respuesta anterior)
    global pivote_socket_global, pivote_address_global, pivote_communication_thread, is_pivote_processing_long_command
    with pivote_processing_lock: is_pivote_processing_long_command = False # Asegurar que se libera el estado
    if pivote_communication_thread and pivote_communication_thread.is_alive():
        command_queue_to_pivote.put(None)
    pivote_communication_thread = None
    if pivote_socket_global:
        log_message_gui(f"Cerrando conexión con Pivote {pivote_address_global or ''}.", "info_tag")
        try:
            if pivote_socket_global.fileno() != -1: pivote_socket_global.close()
        except: pass
    pivote_socket_global = None
    pivote_address_global = None
    if gui_ready_event.is_set():
        update_pivote_status_gui(False)
        update_cs_list_gui("")

# --- Comandos de la GUI ---
# ... (start_gui_server_command, stop_gui_server_command, send_command_from_gui, send_scan_command_to_pivote como en la respuesta anterior)
# ... (Es importante que estas funciones usen 'is_pivote_processing_long_command' y 'pivote_processing_lock')
def start_gui_server_command():
    global gui_server_listener_thread
    if gui_server_listener_thread and gui_server_listener_thread.is_alive():
        messagebox.showinfo("Información", "Servidor GUI ya escuchando.")
        return
    stop_event_global.clear()
    gui_server_listener_thread = threading.Thread(target=gui_server_listener_loop, daemon=True)
    gui_server_listener_thread.start()
    if btn_start_server: btn_start_server.config(state=tk.DISABLED)
    if btn_stop_server: btn_stop_server.config(state=tk.NORMAL)

def stop_gui_server_command():
    log_message_gui("Deteniendo servidor GUI...", "info_tag")
    stop_event_global.set() 
    close_and_cleanup_pivote_connection()
    if gui_server_socket_listener:
        try:
            if sys.platform == "win32" and gui_server_socket_listener.fileno() != -1 :
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dummy_s:
                    dummy_s.settimeout(0.1); 
                    try: dummy_s.connect((HOST_GUI_SERVER if HOST_GUI_SERVER!='0.0.0.0' else '127.0.0.1', PORT_GUI_SERVER))
                    except: pass 
            if gui_server_socket_listener.fileno() != -1: gui_server_socket_listener.close()
        except: pass
    if gui_server_listener_thread and gui_server_listener_thread.is_alive():
        gui_server_listener_thread.join(timeout=1.5)
        if gui_server_listener_thread.is_alive(): log_message_gui("Advertencia: Hilo escucha GUI no terminó.", "error_tag")

def send_command_from_gui(command_entry_widget, is_cs_command=False, cs_target_entry_widget=None):
    global is_pivote_processing_long_command
    with pivote_processing_lock:
        if is_pivote_processing_long_command:
            messagebox.showwarning("Ocupado", "Pivote procesando. Espera.")
            return
    command_text = command_entry_widget.get().strip()
    if not command_text: messagebox.showwarning("Comando Vacío", "Ingresa un comando."); return
    if not pivote_socket_global or pivote_socket_global.fileno() == -1:
        messagebox.showerror("Error", "Pivote no conectado."); return
    final_cmd = command_text
    if is_cs_command:
        cs_id = cs_target_entry_widget.get().strip()
        if not cs_id: messagebox.showwarning("CS ID Vacío", "Ingresa ID del CS."); return
        final_cmd = f"remote {cs_id} {command_text}"
    clear_command_output_gui()
    command_queue_to_pivote.put(final_cmd) 
    command_entry_widget.delete(0, tk.END)
    if cs_target_entry_widget: cs_target_entry_widget.delete(0, tk.END)

def send_scan_command_to_pivote(ip_range_entry_widget):
    global is_pivote_processing_long_command
    with pivote_processing_lock:
        if is_pivote_processing_long_command:
            messagebox.showwarning("Ocupado", "Pivote procesando. Espera.")
            return
    if not pivote_socket_global or pivote_socket_global.fileno() == -1:
        messagebox.showerror("Error", "Pivote no conectado.")
        return
    ip_range = ip_range_entry_widget.get().strip()
    cmd = "cp_scan_and_connect_cs"
    if ip_range: cmd += f" {ip_range}"
    clear_command_output_gui()
    log_message_gui(f"Solicitando escaneo CS al Pivote: '{cmd}'", "info_tag")
    command_queue_to_pivote.put(cmd)

# --- Construcción de la GUI (build_gui) ---
# ... (código de build_gui como en la respuesta anterior, asegurando que scan_ip_range_entry_widget se define como global si se accede desde fuera)
def build_gui(root):
    global log_text_widget, status_label_widget, pivote_status_label_widget, cs_list_widget
    global command_output_widget, btn_start_server, btn_stop_server, scan_ip_range_entry_widget 
    
    root.title("Servidor GUI Monitor para Pivote")
    root.geometry("950x750")

    style = ttk.Style()
    try:
        if sys.platform == "win32": style.theme_use('vista')
        elif sys.platform == "darwin": style.theme_use('aqua')
        else: style.theme_use('clam')
    except tk.TclError: pass 

    menubar = tk.Menu(root)
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Iniciar Escucha GUI", command=start_gui_server_command)
    filemenu.add_command(label="Detener Escucha GUI", command=stop_gui_server_command)
    filemenu.add_separator()
    filemenu.add_command(label="Salir", command=lambda: on_closing_app(root))
    menubar.add_cascade(label="Servidor", menu=filemenu)
    root.config(menu=menubar)

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    server_control_frame = ttk.LabelFrame(main_frame, text="Control del Servidor GUI", padding="10")
    server_control_frame.pack(fill=tk.X, pady=5)
    btn_start_server = ttk.Button(server_control_frame, text="Iniciar Escucha GUI", command=start_gui_server_command)
    btn_start_server.pack(side=tk.LEFT, padx=5)
    btn_stop_server = ttk.Button(server_control_frame, text="Detener Escucha GUI", command=stop_gui_server_command, state=tk.DISABLED)
    btn_stop_server.pack(side=tk.LEFT, padx=5)

    pivote_status_frame = ttk.LabelFrame(main_frame, text="Estado del Pivote", padding="10")
    pivote_status_frame.pack(fill=tk.X, pady=5)
    pivote_status_label_widget = ttk.Label(pivote_status_frame, text="Pivote Desconectado", foreground="red", font=FONT_PRIMARY)
    pivote_status_label_widget.pack(side=tk.LEFT)

    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill=tk.BOTH, expand=True, pady=10)

    commands_tab = ttk.Frame(notebook, padding="10")
    notebook.add(commands_tab, text="Comandos")

    pivote_cmd_frame = ttk.LabelFrame(commands_tab, text="Comando para Pivote (Local o Gestión CS)", padding="5")
    pivote_cmd_frame.pack(fill=tk.X, pady=5)
    pivote_cmd_entry = ttk.Entry(pivote_cmd_frame, width=60, font=FONT_PRIMARY)
    pivote_cmd_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
    pivote_cmd_button = ttk.Button(pivote_cmd_frame, text="Enviar a Pivote", command=lambda: send_command_from_gui(pivote_cmd_entry))
    pivote_cmd_button.pack(side=tk.LEFT, padx=5)

    cs_cmd_frame = ttk.LabelFrame(commands_tab, text="Comando para Cliente Secundario (vía Pivote)", padding="5")
    cs_cmd_frame.pack(fill=tk.X, pady=5)
    ttk.Label(cs_cmd_frame, text="CS ID:").pack(side=tk.LEFT, padx=(0,2))
    cs_target_entry = ttk.Entry(cs_cmd_frame, width=10, font=FONT_PRIMARY)
    cs_target_entry.pack(side=tk.LEFT, padx=(0,5))
    ttk.Label(cs_cmd_frame, text="Comando:").pack(side=tk.LEFT, padx=(0,2))
    cs_cmd_entry_widget = ttk.Entry(cs_cmd_frame, width=40, font=FONT_PRIMARY) # Renombrar para evitar conflicto
    cs_cmd_entry_widget.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
    cs_cmd_button = ttk.Button(cs_cmd_frame, text="Enviar a CS", command=lambda: send_command_from_gui(cs_cmd_entry_widget, True, cs_target_entry))
    cs_cmd_button.pack(side=tk.LEFT, padx=5)
    
    output_frame = ttk.LabelFrame(commands_tab, text="Salida de Comandos", padding="5")
    output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    command_output_widget = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state=tk.DISABLED, font=FONT_LOG, height=10)
    command_output_widget.pack(fill=tk.BOTH, expand=True)

    cs_tab = ttk.Frame(notebook, padding="10")
    notebook.add(cs_tab, text="Clientes Secundarios (CS)")
    cs_list_frame = ttk.LabelFrame(cs_tab, text="CS Conectados (Reportados por Pivote)", padding="5")
    cs_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0,5))
    cs_list_widget = tk.Listbox(cs_list_frame, font=FONT_LOG, height=8) 
    cs_list_widget.pack(fill=tk.BOTH, expand=True)
    
    cs_buttons_frame = ttk.Frame(cs_tab) 
    cs_buttons_frame.pack(fill=tk.X, pady=5)
    refresh_cs_button = ttk.Button(cs_buttons_frame, text="Refrescar Lista de CS", command=lambda: command_queue_to_pivote.put("cp_list_cs"))
    refresh_cs_button.pack(side=tk.LEFT, padx=5)

    scan_cs_frame = ttk.LabelFrame(cs_buttons_frame, text="Escanear y Conectar", padding="5")
    scan_cs_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
    ttk.Label(scan_cs_frame, text="Rango IP (opc.):").pack(side=tk.LEFT, padx=(0,2))
    scan_ip_range_entry_widget = ttk.Entry(scan_cs_frame, width=20, font=FONT_PRIMARY) 
    scan_ip_range_entry_widget.pack(side=tk.LEFT, padx=(0,5))
    scan_cs_button = ttk.Button(scan_cs_frame, text="Escanear en Pivote", command=lambda: send_scan_command_to_pivote(scan_ip_range_entry_widget))
    scan_cs_button.pack(side=tk.LEFT, padx=5)

    log_frame = ttk.LabelFrame(main_frame, text="Log del Servidor GUI", padding="10")
    log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    log_text_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, font=FONT_LOG, height=8)
    log_text_widget.pack(fill=tk.BOTH, expand=True)
    log_text_widget.tag_config("error_tag", foreground="red")
    log_text_widget.tag_config("success_tag", foreground="green")
    log_text_widget.tag_config("info_tag", foreground="blue")
    log_text_widget.tag_config("send_tag", foreground="purple")
    log_text_widget.tag_config("recv_tag", foreground="teal")

    status_bar = ttk.Frame(root, relief=tk.SUNKEN, padding="2 5")
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    status_label_widget = ttk.Label(status_bar, text="Servidor GUI no iniciado.", anchor=tk.W)
    status_label_widget.pack(side=tk.LEFT)

    gui_ready_event.set()
    gui_root.after(100, process_responses_for_gui)


def on_closing_app(root_window):
    # ... (código de on_closing_app como en la respuesta anterior)
    if messagebox.askokcancel("Salir", "¿Seguro que quieres salir y detener el servidor GUI?"):
        log_message_gui("Iniciando cierre de la aplicación...", "info_tag")
        stop_gui_server_command() 
        time.sleep(0.5) 
        root_window.destroy()

# --- Función Principal ---
if __name__ == "__main__":
    gui_root = tk.Tk()
    build_gui(gui_root)
    gui_root.protocol("WM_DELETE_WINDOW", lambda: on_closing_app(gui_root))
    log_message_gui("Servidor GUI listo. Inicia la escucha para el Pivote.", "info_tag")
    try:
        gui_root.mainloop()
    except KeyboardInterrupt:
        log_message_gui("Cierre por Ctrl+C (mainloop).", "info_tag")
        on_closing_app(gui_root)
    finally:
        stop_event_global.set()
        if pivote_communication_thread and pivote_communication_thread.is_alive():
             command_queue_to_pivote.put(None)
             pivote_communication_thread.join(timeout=0.5)
        if gui_server_listener_thread and gui_server_listener_thread.is_alive():
             gui_server_listener_thread.join(timeout=0.5)
        print("Aplicación GUI finalizada.")