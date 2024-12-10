import os
import socket
import threading
import time
import utilities
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


# Sends a command to the server and waits for a response----------------------------------------------------------------
def send_command(control_socket, command):
    """
        Sends a command to the server and waits for its response.
        Uses threading condition to synchronize with the response receiver.
        """
    global shared_response
    with response_condition:
        # Send the command
        message = command.encode(FORMAT)
        message_length = len(message)
        control_socket.sendall(f"{message_length:<{HEADER}}".encode(FORMAT))
        control_socket.sendall(message)

        # Wait for the response
        response_condition.wait(timeout=3)  # Wait for notify or timeout

        # Check if a response was set
        if shared_response:
            response = shared_response
            shared_response = None  # Reset shared response
            return response
        else:
            print("Error: No response from server.")
            return None


# Listens for server messages and notifies waiting threads--------------------------------------------------------------
def receive_message(control_socket):
    """
  Continuously listens for messages from the server.
  Updates the shared response variable and notifies waiting threads.
  """
    global shared_response
    while True:
        try:
            response = control_socket.recv(1024).decode(FORMAT)
            if not response:
                print("Server disconnected.")
                break

            # Notify waiting threads
            with response_condition:
                shared_response = response
                response_condition.notify()  # Notify one waiting thread

            # Print response for logging
            print(f"Server: {response}")
        except ConnectionResetError:
            print("Connection lost.")
            break


# Handles the LIST command to retrieve directory listings---------------------------------------------------------------
def handle_list(control_socket):
    """
        Sends the LIST command to the server to get directory listings.
        Opens a data socket to receive the listing data.
        """
    response = send_command(control_socket, "LIST")
    if response:
        if response.startswith("125"):
            data_socket = create_data_socket()  # New socket for data transfer
            data_socket.connect((SERVER_IP, DATA_PORT))
            print("Directory listing:")
            while True:
                data = data_socket.recv(1024).decode(FORMAT)
                if not data:
                    break
                print(data)
            data_socket.close()


# Handles the RETR command to download a file---------------------------------------------------------------------------

def handle_retr(control_socket, filename):
    """
        Sends the RETR command to download a file from the server.
        Saves the downloaded file in the client directory.
        """
    global CURRENT_DIRECTORY
    response = send_command(control_socket, f"RETR {filename}")
    if response:
        if response.startswith("150"):
            data_socket = create_data_socket()  # New socket for data transfer
            data_socket.connect((SERVER_IP, DATA_PORT))
            client_file, dir = utilities.resolve_path(CURRENT_DIRECTORY, filename)
            with open(client_file, 'wb') as file:
                while data := data_socket.recv(1024):
                    file.write(data)
            data_socket.close()
            print(f"File '{filename}' downloaded successfully.")
        else:
            print(f"Error: {response}")


# Handles the STOR command to upload a file-----------------------------------------------------------------------------

def handle_stor(control_socket, origin_path, destination):
    """
    Sends the STOR command to upload a file to the server.
    Ensures the file exists before attempting the upload.
    """
    global CURRENT_DIRECTORY
    origin_path, par = utilities.resolve_path(CURRENT_DIRECTORY, origin_path)
    if not os.path.isfile(origin_path):
        origin_path = par

        if not os.path.isfile(origin_path):
            print(f"File '{origin_path}' does not exist.")
            return

    filename = os.path.basename(origin_path)
    response = send_command(control_socket, f"STOR {filename} {destination}")
    if response:
        if response.startswith("150"):
            data_socket = create_data_socket()  # New socket for data transfer
            data_socket.connect((SERVER_IP, DATA_PORT))
            with open(origin_path, 'rb') as file:
                while chunk := file.read(1024):
                    data_socket.sendall(chunk)
                data_socket.close()
                print(f"File '{filename}' uploaded successfully.")
                CURRENT_DIRECTORY = origin_path
        else:
            print(f"Error: {response}")


# ----------------------------------------------------------------------------------------------------------------------

def handle_control_socket(control_socket, command):
    send_command(control_socket, command)


# Displays help menu for authentication commands------------------------------------------------------------------------


def authentication_help():
    """
    Prints a list of authentication commands supported by the client.
    """
    print(
        "\nSupported commands:"
        "\nSIGNUP <username> <password>                   - sign up"
        "\nUSER <username>                                - Log in with a username"
        "\nPASS <password>                                - Log in with a password"
        "\nQUIT                                           - Disconnect from the server\n")


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


# Main client function with threading-----------------------------------------------------------------------------------
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
