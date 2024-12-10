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



# # Main client function with threading-----------------------------------------------------------------------------------
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