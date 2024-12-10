import socket
import threading
import time
from Encryption_Methods import SSL_TLS_Encryption, TLS_Encryption, SSL_Encryption

# Constants defining client configurations and behavior
HEADER = 256  # Fixed header size for sending commands
FORMAT = 'utf-8'  # Encoding format for communication
DISCONNECT_MESSAGE = "QUIT"  # Message to indicate disconnection
SERVER_IP = "127.0.0.1"  # Server IP address
CONTROL_PORT = 465  # Control port for communication
DATA_PORT = 2121  # Data port for file transfers
CURRENT_DIRECTORY = 'D:\\network\\FTP\\FTP\\client-folder'  # Default local storage directory
ENCRYPTION_MODE = "TLS"  # Encryption protocol for connections


# Function to create the control socket---------------------------------------------------------------------------------
def create_control_socket():
    """
        Establishes the control socket connection to the server.
        Depending on the encryption mode, it initializes the socket appropriately.
        """
    control_socket = None
    if ENCRYPTION_MODE == "SSL":
        control_socket = SSL_Encryption.ssl_control_connection_client()
        print("SSL from client")

    if ENCRYPTION_MODE == "SSL/TLS":
        control_socket = SSL_TLS_Encryption.ssl_tls_control_connection_client()
        print("SSL/TLS from client")

    elif ENCRYPTION_MODE == "TLS":
        control_socket = TLS_Encryption.tls_control_connection_client()
        print("TLS from client")

    else:  # its PLAIN mode without any encryption protocol
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Trying to connect to the server...")
    while True:
        try:
            control_socket.connect((SERVER_IP, CONTROL_PORT))
            print("Connected to server.")
            break
        except ConnectionRefusedError:
            print("Server not ready. Retrying in 2 seconds...")
            time.sleep(2)
    return control_socket


# Function to create a data socket for file transfers-------------------------------------------------------------------
def create_data_socket():
    """
    Creates a data socket used for transferring files between client and server.
    Initializes the socket based on the encryption mode.
    """
    data_socket = None
    if ENCRYPTION_MODE == "SSL":
        data_socket = SSL_Encryption.ssl_data_connection_client()

    elif ENCRYPTION_MODE == "TLS":
        data_socket = TLS_Encryption.tls_data_connection_client()
    else:
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    return data_socket


# Shared variables and threading mechanisms for response handling-------------------------------------------------------
response_condition = threading.Condition()  # Condition variable for response synchronization
shared_response = None  # Stores the latest response from the server


# Function to handle user input and send messages-----------------------------------------------------------------------
def send_message(control_socket):
    global CURRENT_DIRECTORY
    """
    Reads user input, processes commands, and sends them to the server.
    Includes command-specific handlers for file operations.
    """
    authentication_help()
    while True:
        try:
            command = input("ftp> ").strip()
            order = command.split(" ")[0]
            if order.upper() == "QUIT":
                send_command(control_socket, DISCONNECT_MESSAGE)
                print("Disconnecting...")
                break
            elif order.upper() == "LIST":
                handle_list(control_socket)
            elif order.upper().startswith("RETR"):
                _, filename = command.split(maxsplit=1)
                handle_retr(control_socket, filename)
            elif order.upper().startswith("STOR"):
                _, filepath, destination = command.split(maxsplit=2)
                handle_stor(control_socket, filepath, destination)
            elif order.upper() == "DELE" or "SIGNUP" or "USER" or "PASS" or "CWD" or "CDUP" or "PWD" or "MKD" or "RMD" or "HELP" or "SETACL" or "CHANGELEVEL":
                if order.upper() == "USER":
                    if CURRENT_DIRECTORY == 'D:\\network\\FTP\\FTP\\client-folder':
                        username = command.split(maxsplit=1)[1]
                        CURRENT_DIRECTORY += f'\\{username}'
                handle_control_socket(control_socket, command)

        except Exception as e:
            print("502 Command not implemented\n")


# # Main client function with threading---------------------------------------------------------------------------------
def client():
    """
    Entry point for the client.
    Initializes control socket and starts threads for sending and receiving messages.
    """
    control_socket = create_control_socket()

    # Threads for receiving and sending
    receive_thread = threading.Thread(target=receive_message, args=(control_socket,))
    send_thread = threading.Thread(target=send_message, args=(control_socket,))

    # Start threads
    receive_thread.start()
    send_thread.start()

    # Wait for threads to finish---------------------------------------------------------
    send_thread.join()
    receive_thread.join()

    # Close the control socket after threads complete------------------------------------
    control_socket.close()


# ----------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    client()
