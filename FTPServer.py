# Constants defining server configurations and behavior-----------------------------------------------------------------
HEADER = 256  # Fixed header size for receiving commands
FORMAT = 'utf-8'  # Encoding format for communication
DISCONNECT_MESSAGE = "QUIT"  # Message to indicate disconnection
SERVER_IP = "127.0.0.1"  # Server IP address
CONTROL_PORT = 465  # Control port for communication
DATA_PORT = 2121  # Data port for file transfers
BASE_DIRECTORY = 'D:\\network\\FTP\\FTP\\server-folder'  # Default server storage directory



def start_server():
    global ENCRYPTION_MODE
    """
    Starts the FTP server, listens for connections, and spawns client threads.
    """
    control_socket = None
    data_socket = None

    if ENCRYPTION_MODE == "SSL":
        control_socket = SSL_Encryption.ssl_control_connection_server()
        data_socket = SSL_Encryption.ssl_data_connection_server()

    if ENCRYPTION_MODE == "SSL/TLS":
        control_socket = SSL_TLS_Encryption.ssl_tls_control_connection_server()
        data_socket = SSL_TLS_Encryption.ssl_tls_data_connection_server()

    elif ENCRYPTION_MODE == "SSH":  # todo;fix this shit
        pass

    elif ENCRYPTION_MODE == "TLS":
        control_socket = TLS_Encryption.tls_control_connection_server()
        data_socket = TLS_Encryption.tls_data_connection_server()

    else:  # its PLAIN mode without any encryption protocol
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    control_socket.bind((SERVER_IP, CONTROL_PORT))
    data_socket.bind((SERVER_IP, DATA_PORT))
    control_socket.listen()
    data_socket.listen()

    print(
        f"{FTP_TYPE} is listening. Control on {SERVER_IP}:{CONTROL_PORT}, Data on {SERVER_IP}:{DATA_PORT}")

    try:
        while True:
            client_socket, addr = control_socket.accept()
            print(f"[NEW CONNECTION] {addr} connected.")
            thread = threading.Thread(target=handle_client, args=(client_socket, data_socket, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            for thread in list(ZOMBIE_THREADS):  # Copy keys to avoid dictionary modification during iteration
                if not ZOMBIE_THREADS[thread].is_alive():
                    ZOMBIE_THREADS[thread].join()  # Join the finished client thread
                    del ZOMBIE_THREADS[thread]

    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Server is shutting down.")
    finally:
        control_socket.close()
        data_socket.close()