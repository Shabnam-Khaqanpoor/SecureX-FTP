import socket
import FTPServer
import ssl

SERVER_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
SERVER_CONTEXT.load_cert_chain(certfile="Certificate_and_Key/cert.pem", keyfile="Certificate_and_Key/key.pem")
CLIENT_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
SERVER_CONTEXT.set_ciphers("HIGH:!aNULL:!MD5")
CLIENT_CONTEXT.load_verify_locations(cafile='Certificate_and_Key/cert.pem')


# -----------------------------------------------------------------------------------------------------------------------
def tls_control_connection_server():
    raw_control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_socket = SERVER_CONTEXT.wrap_socket(raw_control_socket, server_side=True)
    return control_socket


# -----------------------------------------------------------------------------------------------------------------------
def tls_data_connection_server():
    raw_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket = SERVER_CONTEXT.wrap_socket(raw_data_socket, server_side=True)
    return data_socket


# -----------------------------------------------------------------------------------------------------------------------
def tls_control_connection_client():
    raw_control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_socket = CLIENT_CONTEXT.wrap_socket(raw_control_socket, server_hostname=FTPServer.SERVER_IP)
    return control_socket


# -----------------------------------------------------------------------------------------------------------------------

def tls_data_connection_client():
    raw_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket = CLIENT_CONTEXT.wrap_socket(raw_data_socket, server_hostname=FTPServer.SERVER_IP)
    return data_socket
