# Constants defining server configurations and behavior-----------------------------------------------------------------
HEADER = 256  # Fixed header size for receiving commands
FORMAT = 'utf-8'  # Encoding format for communication
DISCONNECT_MESSAGE = "QUIT"  # Message to indicate disconnection
SERVER_IP = "127.0.0.1"  # Server IP address
CONTROL_PORT = 465  # Control port for communication
DATA_PORT = 2121  # Data port for file transfers
BASE_DIRECTORY = 'D:\\network\\FTP\\FTP\\server-folder'  # Default server storage directory

#   User levels for role-based access controls--------------------------------------------------------------------------
LEVEL = {
    '1': 'Super-admin',
    '2': 'Admin',
    '3': 'Promoted user',
    '4': 'Normal'
}

# Registered users with associated roles and credentials----------------------------------------------------------------
VALID_USERS = {
    'user1': {'password': 'password1',
              'level': LEVEL['1']},
    'user2': {'password': 'password2', 'level': LEVEL['2']},
    'user3': {'password': 'password3', 'level': LEVEL['3']},
    'user4': {'password': 'password4', 'level': LEVEL['4']},
}



def handle_client(client_socket, data_socket, addr):
    """Manages the lifecycle of a client connection."""
    user_state = {
        'username': None,
        'authenticated': False,
        'status': None,
        'current_directory': BASE_DIRECTORY,
        'level': None
    }

client_socket.sendall(f"220 FTP Server Ready\n".encode(FORMAT))

    connected = True
    while connected:
        try:
            msg_length = client_socket.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                command = client_socket.recv(msg_length).decode(FORMAT)
                print(f"[{addr}] said: {command}\n")
                command_parts = command.split()
                cmd = command_parts[0].upper()

                if cmd == "SIGNUP":
                    user_state = sign_up(command_parts, user_state, client_socket)
                elif cmd == "USER":
                    user_state = handle_user(command_parts, user_state, client_socket)
                elif cmd == "PASS":
                    user_state = handle_pass(command_parts, user_state, client_socket)
                elif cmd == "LIST":
                    handle_list(user_state, command_parts, client_socket, data_socket)
                elif cmd == "RETR":
                    handle_retr(user_state, command_parts, client_socket, data_socket)
                elif cmd == "STOR":
                    handle_stor(user_state, command_parts, client_socket, data_socket)
                elif cmd == "DELE":
                    handle_delete(user_state, command_parts, client_socket)
                elif cmd == "MKD":
                    handle_mkd(user_state, command_parts, client_socket)
                elif cmd == "RMD":
                    handle_rmd(user_state, command_parts, client_socket)
                elif cmd == "PWD":
                    handle_pwd(user_state, client_socket)
                elif cmd == "CWD":
                    handle_cwd(user_state, command_parts, client_socket)
                elif cmd == "CDUP":
                    handle_cdup(user_state, client_socket)
                elif cmd == "SETACL" and user_state['level'] == LEVEL.get('1'):
                    handle_setacl(command_parts, client_socket, user_state)
                elif cmd == "CHANGELEVEL" and user_state['level'] == LEVEL.get('1'):
                    change_user_level(command_parts, user_state, client_socket)
                elif cmd == "HELP":
                    handle_help(user_state, client_socket)
                elif cmd == "QUIT":
                    if IS_TRANSFERRING[client_socket]:
                        client_socket.sendall(f"[WARNING!] Cannot quit during file transfer.\n".encode(FORMAT))
                    else:
                        client_socket.sendall(f"221 Goodbye\n".encode(FORMAT))
                        connected = False
                else:
                    client_socket.sendall(f"502 Command not implemented\n".encode(FORMAT))
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            connected = False



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