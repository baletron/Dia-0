import tkinter as tk # Only for messagebox in a non-web context, will be removed or replaced
from tkinter import messagebox, simpledialog # Placeholder, web will use JS alerts

import socket
import threading
import time
import queue
import traceback
import sys
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS # For handling Cross-Origin Resource Sharing if frontend is served separately

# --- Configuración (Same as original) ---
HOST_GUI_SERVER = '0.0.0.0'
PORT_GUI_SERVER = 65432
SHARED_PASSWORD = "micontrasenasecreta"
BUFFER_SIZE = 8192

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app) # Allow all origins for simplicity in development

# --- Variables Globales (Server-Side State) ---
# We need to store data that the frontend will request
server_logs = []
command_outputs_store = [] # Stores tuples of (command_sent, response_data)
current_cs_list_data = {"text": " (Lista de CS no obtenida/vacía) ", "items": []} # For structured list
pivote_status_data = {"text": "Pivote Desconectado", "color": "red", "os": "N/A"}
gui_server_status_data = {"text": "Servidor GUI no iniciado.", "listening": False}

pivote_socket_global = None
pivote_address_global = None
pivote_os_type_global = "N/A" # Will be part of pivote_status_data
pivote_communication_thread = None

gui_server_socket_listener = None
gui_server_listener_thread = None

stop_event_global = threading.Event()
command_queue_to_pivote = queue.Queue()
# response_queue_from_pivote: We'll process responses directly and update server_state

is_pivote_processing_long_command = False
pivote_processing_lock = threading.Lock()

# --- Utility for logging (to server_logs list) ---
def log_message_server(message, tag="info"): # tag can be 'info', 'error', 'success', 'send', 'recv'
    timestamp = time.strftime("%H:%M:%S")
    log_entry = {"timestamp": timestamp, "message": message, "tag": tag}
    server_logs.append(log_entry)
    # Keep logs to a reasonable size if needed
    if len(server_logs) > 200:
        server_logs.pop(0)
    print(f"LOG SERVER: [{tag.upper()}] {message}")

# --- Functions adapted from GUI logic ---
# These functions will now update the server-side state variables

def update_server_pivote_status(is_connected=False, address=None, os_type="N/A"):
    global pivote_status_data, pivote_os_type_global
    if is_connected and address:
        pivote_os_type_global = os_type
        pivote_status_data["text"] = f"Pivote Conectado: {address[0]}:{address[1]} (OS: {os_type})"
        pivote_status_data["color"] = "green"
        pivote_status_data["os"] = os_type
    else:
        pivote_os_type_global = "N/A"
        pivote_status_data["text"] = "Pivote Desconectado"
        pivote_status_data["color"] = "red"
        pivote_status_data["os"] = "N/A"

def update_server_gui_status(message, listening=None):
    global gui_server_status_data
    gui_server_status_data["text"] = message
    if listening is not None:
        gui_server_status_data["listening"] = listening

def add_command_output_server(command_sent, output_text):
    global command_outputs_store
    command_outputs_store.append({"command": command_sent, "output": output_text})
    if len(command_outputs_store) > 50: # Limit history
        command_outputs_store.pop(0)

def update_cs_list_server(full_response_from_pivote):
    global current_cs_list_data
    cs_items = []
    display_text = ""

    start_marker = "--- inicio lista cs actual ---"
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
        # Fallback if markers are not present (try to parse older format)
        if "cp: clientes secundarios conectados:" in response_lower:
            actual_cs_list_content = full_response_from_pivote.split("CP: Clientes Secundarios Conectados:", 1)[-1].strip()
        elif "no hay clientes secundarios" in response_lower:
            actual_cs_list_content = "CP: No hay Clientes Secundarios conectados."

    if actual_cs_list_content:
        if "no hay clientes secundarios" in actual_cs_list_content.lower():
            display_text = " (No CS reportados) "
        else:
            lines = actual_cs_list_content.split('\n')
            cs_found = False
            for line in lines:
                line_strip = line.strip()
                if line_strip.lower().startswith("- cs") or \
                   (line_strip.lower().startswith("cs") and ":" in line_strip and "conectados" not in line_strip.lower()):
                    cs_items.append(line_strip)
                    cs_found = True
            if not cs_found and actual_cs_list_content.strip():
                display_text = " (Formato de lista CS no reconocido) "
            elif not cs_items: # cs_found was true but no items were added (e.g. only header)
                 display_text = " (No CS reportados / Formato inesperado) "

    else:
        display_text = " (Lista de CS no obtenida/vacía) "

    current_cs_list_data["items"] = cs_items
    current_cs_list_data["text"] = display_text if display_text else "" # if items, text is empty

# --- Lógica de Red (largely the same, but updates server state instead of GUI directly) ---
def pivote_command_sender_receiver_thread():
    global pivote_socket_global, is_pivote_processing_long_command
    log_message_server("Hilo de comunicación con Pivote iniciado.", "info")
    while not stop_event_global.is_set():
        command_to_send_for_log = "N/A"
        response_parts = []
        try:
            if not pivote_socket_global or pivote_socket_global.fileno() == -1:
                with pivote_processing_lock: is_pivote_processing_long_command = False
                time.sleep(0.1); continue

            command_to_send = command_queue_to_pivote.get(timeout=0.5)
            command_to_send_for_log = command_to_send
            if command_to_send is None: break # Signal to exit thread
            
            with pivote_processing_lock: is_pivote_processing_long_command = True

            log_message_server(f"Enviando al Pivote: '{command_to_send}'", "send")
            pivote_socket_global.sendall(command_to_send.encode('utf-8'))
            
            receive_timeout = 300.0 if command_to_send.startswith("cp_scan_and_connect_cs") else 60.0
            pivote_socket_global.settimeout(receive_timeout)
            log_message_server(f"Esperando respuesta del Pivote para '{command_to_send}' (timeout: {receive_timeout}s)...")
            
            while True:
                try:
                    chunk = pivote_socket_global.recv(BUFFER_SIZE)
                    if not chunk:
                        log_message_server(f"Pivote cerró conexión (0 bytes recv) para '{command_to_send}'.", "error")
                        add_command_output_server(command_to_send, f"ERROR: Pivote cerró conexión.")
                        with pivote_processing_lock: is_pivote_processing_long_command = False
                        close_and_cleanup_pivote_connection()
                        command_queue_to_pivote.task_done()
                        return # Terminar este hilo
                    response_parts.append(chunk)
                except socket.timeout:
                    log_message_server(f"Timeout parcial recv para '{command_to_send}', fin de datos.", "info")
                    break # End of data for this command
            
            pivote_socket_global.settimeout(None) # Reset timeout

            if response_parts:
                full_response = b"".join(response_parts).decode('utf-8', errors='replace').strip()
                add_command_output_server(command_to_send, full_response)
                if command_to_send.startswith("cp_scan_and_connect_cs") or \
                   command_to_send.startswith("cp_connect_cs") or \
                   command_to_send.startswith("cp_disconnect_cs") or \
                   command_to_send == "cp_list_cs":
                    update_cs_list_server(full_response)
            elif pivote_socket_global and pivote_socket_global.fileno() != -1: # Socket still valid but no data
                add_command_output_server(command_to_send, "[Pivote: Sin respuesta significativa]")
            
            with pivote_processing_lock: is_pivote_processing_long_command = False
            command_queue_to_pivote.task_done()

        except queue.Empty:
            with pivote_processing_lock:
                if not command_queue_to_pivote.qsize() > 0: is_pivote_processing_long_command = False
            continue
        except socket.timeout:
            log_message_server(f"Timeout general en comando '{command_to_send_for_log}'.", "error")
            add_command_output_server(command_to_send_for_log, f"ERROR: Timeout general Pivote.")
            with pivote_processing_lock: is_pivote_processing_long_command = False
            close_and_cleanup_pivote_connection()
        except (socket.error, ConnectionResetError, BrokenPipeError, OSError) as e:
            if not stop_event_global.is_set():
                log_message_server(f"Error socket Pivote ('{command_to_send_for_log}'): {e}", "error")
                add_command_output_server(command_to_send_for_log, f"ERROR: Socket Pivote - {e}")
            with pivote_processing_lock: is_pivote_processing_long_command = False
            close_and_cleanup_pivote_connection()
        except Exception as e:
            if not stop_event_global.is_set():
                log_message_server(f"Error inesperado comm thread ({command_to_send_for_log}): {e}", "error"); traceback.print_exc()
            add_command_output_server(command_to_send_for_log, f"ERROR INESPERADO: {e}")
            with pivote_processing_lock: is_pivote_processing_long_command = False

    log_message_server("Hilo de comunicación con Pivote terminado.", "info")
    with pivote_processing_lock: is_pivote_processing_long_command = False


def handle_single_pivote_connection(conn, addr):
    global pivote_socket_global, pivote_address_global, pivote_communication_thread
    log_message_server(f"Intento de conexión del Pivote desde: {addr}")
    temp_pivote_os_type = "N/A"
    is_authenticated_and_active = False
    try:
        conn.sendall(b"AUTH_REQUEST")
        password_bytes = conn.recv(1024)
        if not password_bytes:
            log_message_server(f"Pivote {addr} desconectado (esperando pass).", "error"); conn.close(); return
        password = password_bytes.decode('utf-8', errors='ignore').strip()

        if password == SHARED_PASSWORD:
            conn.sendall(b"AUTH_SUCCESS")
            os_type_bytes = conn.recv(1024)
            if not os_type_bytes:
                log_message_server(f"Pivote {addr} desconectado (esperando OS).", "error"); conn.close(); return
            
            temp_pivote_os_type = os_type_bytes.decode('utf-8', errors='ignore').strip().capitalize()
            log_message_server(f"Pivote {addr} autenticado. OS: {temp_pivote_os_type}", "success")
            
            close_and_cleanup_pivote_connection() # Close any existing pivote connection
            pivote_socket_global = conn
            pivote_address_global = addr
            update_server_pivote_status(True, addr, temp_pivote_os_type)
            is_authenticated_and_active = True

            # Start the command sender/receiver thread if not already running
            if not pivote_communication_thread or not pivote_communication_thread.is_alive():
                pivote_communication_thread = threading.Thread(target=pivote_command_sender_receiver_thread, daemon=True)
                pivote_communication_thread.start()
            else:
                log_message_server("Advertencia: Hilo de comunicación con Pivote ya estaba activo.", "info")

            command_queue_to_pivote.put("cp_list_cs") # Initial command to get CS list
            
            # Keep-alive / check loop for this specific connection
            while not stop_event_global.is_set() and pivote_socket_global == conn and conn.fileno() != -1:
                try:
                    conn.settimeout(1.0) # Short timeout to check if socket is still alive
                    data_peek = conn.recv(1, socket.MSG_PEEK) # Try to peek 1 byte without consuming
                    if not data_peek: # Connection closed by pivote
                        log_message_server(f"Pivote {addr} desconectado (peek devolvió 0 bytes).", "info")
                        break # Exit keep-alive loop
                    conn.settimeout(None) # Reset timeout
                except socket.timeout:
                    # This is expected, means no data sent by pivote, but connection is alive
                    continue
                except (socket.error, OSError): # Socket error or closed
                    log_message_server(f"Socket con Pivote {addr} cerrado o con error (durante peek).", "error")
                    break # Exit keep-alive loop
                time.sleep(0.5) # Check periodically
        else: # Auth failed
            conn.sendall(b"AUTH_FAIL")
            log_message_server(f"Fallo de autenticación para Pivote {addr}.", "error")
            conn.close()
    except (socket.error, ConnectionResetError, BrokenPipeError) as e:
        if not stop_event_global.is_set(): # Log only if not shutting down
            log_message_server(f"Conexión con Pivote {addr} perdida: {e}", "error")
    except Exception as e:
        if not stop_event_global.is_set():
            log_message_server(f"Error inesperado con Pivote {addr}: {e}", "error")
            traceback.print_exc()
    finally:
        if is_authenticated_and_active and pivote_socket_global == conn : # If this was the active connection
            close_and_cleanup_pivote_connection() # Clean up
        elif conn.fileno() != -1 : # If conn is still a valid socket but not the active one (shouldn't happen often)
            try: conn.close()
            except: pass
        log_message_server(f"Hilo de manejo para {addr} terminado.", "info")


def gui_server_listener_loop():
    global gui_server_socket_listener
    temp_listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        temp_listener_socket.bind((HOST_GUI_SERVER, PORT_GUI_SERVER))
        temp_listener_socket.listen(1) # Listen for one pivote connection
        gui_server_socket_listener = temp_listener_socket # Assign to global once successfully bound
        log_message_server(f"Servidor GUI escuchando en {HOST_GUI_SERVER}:{PORT_GUI_SERVER}", "info")
        update_server_gui_status(f"Escuchando en {HOST_GUI_SERVER}:{PORT_GUI_SERVER}", listening=True)
    except OSError as e:
        log_message_server(f"No se pudo iniciar servidor GUI: {e}", "error")
        update_server_gui_status(f"ERROR al iniciar escucha: {e}", listening=False)
        return

    while not stop_event_global.is_set():
        try:
            gui_server_socket_listener.settimeout(1.0) # Timeout to allow checking stop_event_global
            conn, addr = gui_server_socket_listener.accept()
            gui_server_socket_listener.settimeout(None) # Reset timeout after accept

            if pivote_socket_global and pivote_socket_global.fileno() != -1:
                log_message_server(f"Conexión de Pivote {addr} rechazada, ya hay un Pivote conectado.", "error")
                try:
                    conn.sendall(b"ERROR: Servidor GUI ocupado con otro Pivote.\n")
                except socket.error: pass # Client might have already disconnected
                conn.close()
            else:
                # Handle the new pivote connection in a new thread
                p_handler_thread = threading.Thread(target=handle_single_pivote_connection, args=(conn, addr), daemon=True)
                p_handler_thread.start()
        except socket.timeout:
            continue # Loop again to check stop_event_global
        except OSError: # Socket closed, likely during shutdown
            if not stop_event_global.is_set():
                 log_message_server("Socket de escucha del Servidor GUI cerrado inesperadamente.", "error")
            break # Exit listener loop
        except Exception as e:
            if not stop_event_global.is_set():
                log_message_server(f"Error aceptando conexión del Pivote: {e}", "error")
            time.sleep(0.5) # Brief pause before retrying accept on other errors

    if gui_server_socket_listener:
        try:
            gui_server_socket_listener.close()
        except: pass
        gui_server_socket_listener = None
    log_message_server("Hilo de escucha del Servidor GUI detenido.", "info")
    update_server_gui_status("Servidor GUI Detenido", listening=False)


def close_and_cleanup_pivote_connection():
    global pivote_socket_global, pivote_address_global, pivote_communication_thread, is_pivote_processing_long_command
    
    with pivote_processing_lock: # Ensure atomicity for is_pivote_processing_long_command
        is_pivote_processing_long_command = False

    if pivote_communication_thread and pivote_communication_thread.is_alive():
        command_queue_to_pivote.put(None) # Signal thread to terminate
        # Don't join here, can cause deadlocks if called from the thread itself.
        # Let it terminate naturally.
    pivote_communication_thread = None # Allow a new one to be created if needed

    if pivote_socket_global:
        log_message_server(f"Cerrando conexión con Pivote {pivote_address_global or '(dirección desconocida)'}.", "info")
        try:
            if pivote_socket_global.fileno() != -1: # Check if socket descriptor is valid
                pivote_socket_global.shutdown(socket.SHUT_RDWR) # Politely close
        except (socket.error, OSError): pass # Ignore errors on shutdown
        finally:
            try:
                if pivote_socket_global.fileno() != -1:
                    pivote_socket_global.close()
            except (socket.error, OSError): pass
    
    pivote_socket_global = None
    pivote_address_global = None
    update_server_pivote_status(False) # Update status to disconnected
    update_cs_list_server("") # Clear CS list

# --- Flask API Endpoints ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start_server', methods=['POST'])
def api_start_server():
    global gui_server_listener_thread
    if gui_server_listener_thread and gui_server_listener_thread.is_alive():
        return jsonify({"status": "error", "message": "Servidor GUI ya está escuchando."}), 400
    
    stop_event_global.clear() # Clear stop event before starting
    gui_server_listener_thread = threading.Thread(target=gui_server_listener_loop, daemon=True)
    gui_server_listener_thread.start()
    log_message_server("Comando Iniciar Escucha GUI recibido.", "info")
    return jsonify({"status": "success", "message": "Iniciando escucha del Servidor GUI..."})

@app.route('/api/stop_server', methods=['POST'])
def api_stop_server():
    global gui_server_listener_thread, gui_server_socket_listener
    log_message_server("Comando Detener Escucha GUI recibido. Deteniendo...", "info")
    stop_event_global.set() # Signal all threads to stop

    close_and_cleanup_pivote_connection() # Disconnect any active pivote

    # Try to unblock the listener accept() call
    if gui_server_socket_listener and gui_server_socket_listener.fileno() != -1:
        try:
            # This is a common trick to break out of accept()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dummy_socket:
                dummy_socket.settimeout(0.1)
                # Connect to '127.0.0.1' if HOST_GUI_SERVER is '0.0.0.0'
                connect_host = HOST_GUI_SERVER if HOST_GUI_SERVER != '0.0.0.0' else '127.0.0.1'
                dummy_socket.connect((connect_host, PORT_GUI_SERVER))
        except:
            pass # Ignore errors, just trying to unblock
        finally: # Close the listener socket itself if still open
            try:
                if gui_server_socket_listener.fileno() != -1:
                    gui_server_socket_listener.close()
            except: pass
            gui_server_socket_listener = None


    if gui_server_listener_thread and gui_server_listener_thread.is_alive():
        gui_server_listener_thread.join(timeout=2.0) # Wait for thread to finish
        if gui_server_listener_thread.is_alive():
            log_message_server("Advertencia: Hilo de escucha del Servidor GUI no terminó limpiamente.", "error")
    
    update_server_gui_status("Servidor GUI Detenido", listening=False)
    return jsonify({"status": "success", "message": "Servidor GUI detenido."})

@app.route('/api/send_command', methods=['POST'])
def api_send_command():
    global is_pivote_processing_long_command
    data = request.json
    command_text = data.get('command', '').strip()
    is_cs_cmd = data.get('is_cs_command', False)
    cs_id = data.get('cs_target_id', '').strip()

    with pivote_processing_lock:
        if is_pivote_processing_long_command:
            return jsonify({"status": "error", "message": "Pivote está procesando un comando largo. Por favor, espera."}), 429 # Too Many Requests
    
    if not command_text:
        return jsonify({"status": "error", "message": "El comando no puede estar vacío."}), 400
    if not pivote_socket_global or pivote_socket_global.fileno() == -1:
        return jsonify({"status": "error", "message": "Pivote no conectado."}), 400

    final_cmd = command_text
    if is_cs_cmd:
        if not cs_id:
            return jsonify({"status": "error", "message": "Se requiere ID del CS para comando remoto."}), 400
        final_cmd = f"remote {cs_id} {command_text}"
    
    command_queue_to_pivote.put(final_cmd)
    log_message_server(f"Comando '{final_cmd}' encolado para Pivote.", "info")
    return jsonify({"status": "success", "message": f"Comando '{final_cmd}' enviado a la cola del Pivote."})

@app.route('/api/scan_cs', methods=['POST'])
def api_scan_cs():
    global is_pivote_processing_long_command
    data = request.json
    ip_range = data.get('ip_range', '').strip()

    with pivote_processing_lock:
        if is_pivote_processing_long_command:
            return jsonify({"status": "error", "message": "Pivote está procesando un comando largo (posiblemente otro escaneo). Por favor, espera."}), 429

    if not pivote_socket_global or pivote_socket_global.fileno() == -1:
        return jsonify({"status": "error", "message": "Pivote no conectado."}), 400

    cmd = "cp_scan_and_connect_cs"
    if ip_range:
        cmd += f" {ip_range}"
    
    command_queue_to_pivote.put(cmd)
    log_message_server(f"Comando de escaneo CS '{cmd}' encolado para Pivote.", "info")
    return jsonify({"status": "success", "message": f"Comando de escaneo '{cmd}' enviado a la cola del Pivote."})

@app.route('/api/refresh_cs_list', methods=['POST'])
def api_refresh_cs_list():
    if not pivote_socket_global or pivote_socket_global.fileno() == -1:
        return jsonify({"status": "error", "message": "Pivote no conectado."}), 400
    
    with pivote_processing_lock:
        if is_pivote_processing_long_command: # Don't queue if busy, list_cs is usually fast
             return jsonify({"status": "warning", "message": "Pivote ocupado, reintenta en breve."}), 429

    command_queue_to_pivote.put("cp_list_cs")
    log_message_server("Comando cp_list_cs encolado para Pivote (refrescar lista).", "info")
    return jsonify({"status": "success", "message": "Solicitud para refrescar lista de CS enviada."})


@app.route('/api/get_updates', methods=['GET'])
def api_get_updates():
    # This endpoint will be polled by the frontend
    global server_logs, command_outputs_store, current_cs_list_data, pivote_status_data, gui_server_status_data, is_pivote_processing_long_command
    
    # Basic check if pivote socket seems dead, even if status hasn't updated yet
    # This is a fallback in case cleanup logic missed something or thread died.
    if pivote_socket_global and pivote_socket_global.fileno() == -1:
        log_message_server("Detectado socket de pivote inválido en get_updates, forzando limpieza.", "warn")
        close_and_cleanup_pivote_connection()

    # Send all current data. Frontend can decide how to display it (e.g., only new logs).
    return jsonify({
        "logs": server_logs,
        "command_outputs": command_outputs_store,
        "cs_list": current_cs_list_data,
        "pivote_status": pivote_status_data,
        "gui_server_status": gui_server_status_data,
        "is_pivote_busy": is_pivote_processing_long_command
    })

def on_shutdown():
    print("Flask app está cerrándose. Intentando detener hilos del servidor GUI...")
    log_message_server("Desconexión de la aplicación Flask. Iniciando limpieza...", "info")
    stop_event_global.set()
    close_and_cleanup_pivote_connection()

    global gui_server_socket_listener
    if gui_server_socket_listener and gui_server_socket_listener.fileno() != -1:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dummy_socket: # Unblock accept
                dummy_socket.settimeout(0.1)
                connect_host = HOST_GUI_SERVER if HOST_GUI_SERVER != '0.0.0.0' else '127.0.0.1'
                dummy_socket.connect((connect_host, PORT_GUI_SERVER))
        except: pass
        finally:
            try: gui_server_socket_listener.close()
            except: pass
    
    if pivote_communication_thread and pivote_communication_thread.is_alive():
        try: command_queue_to_pivote.put(None, timeout=0.1) # Signal to stop
        except queue.Full: pass
        pivote_communication_thread.join(timeout=1.0)
        if pivote_communication_thread.is_alive():
            print("Advertencia: Hilo de comunicación con Pivote no terminó.")

    if gui_server_listener_thread and gui_server_listener_thread.is_alive():
        gui_server_listener_thread.join(timeout=1.0)
        if gui_server_listener_thread.is_alive():
            print("Advertencia: Hilo de escucha del Servidor GUI no terminó.")
    print("Limpieza de cierre completada.")


if __name__ == "__main__":
    log_message_server("Servidor GUI (Web Backend) iniciando...", "info")
    import atexit
    atexit.register(on_shutdown) # Register cleanup function for when Flask exits
    try:
        # For development, use Flask's built-in server.
        # For production, use a WSGI server like Gunicorn or uWSGI.
        # `debug=True` reloads on code changes, but can cause threads to run twice.
        # `use_reloader=False` is important when managing background threads.
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("Cierre por Ctrl+C detectado.")
    finally:
        on_shutdown() # Ensure cleanup runs