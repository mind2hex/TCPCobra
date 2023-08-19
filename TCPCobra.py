#!/usr/bin/env python


import sys
import socket
import threading
import base64
from inspect import currentframe


# translation string to use with str.translate
HEX_FILTER =''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)]
)

def show_banner():
    """ only show an ascii banner """
    text_banner = """
    4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qOA4qGA4qCA4qOA4qCA
    4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKggOKg
    gOKioOKjtOKjvuKhv+Kgv+Kgv+Kgv+Kgt+KgpuKgv+Kgv+KggOKggOKggOKggOKggOKggOKggOKg
    gOKggOKggOKggArioIDioIDioIDioIDioIDioIDioIDioIDioInioYnioJvioqDio77io7fioYDi
    oLDio6bioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIAK4qCA4qCA4qCA4qCA
    4qCA4qCA4qCA4qCA4qC44qCH4qCA4qOI4qOA4qOA4qOA4qOA4qCI4qCC4qCA4qCA4qCA4qCA4qCA
    4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKgsuKjtuKhhOKg
    mOKgm+Kgm+Kgm+Kgm+KggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggAri
    oIDioIDioIDioIDioIDioIDioIDioIDioIDioJniorfioYDioLvio7/ioL/ioL/ioIDioIDioIDi
    oIDioIDioIDioIDioIDioIDioIDioIAK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
    4qCJ4qCA4qCA4qK04qO24qO24qGE4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
    CuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKgieKigeKjpOKj
    pOKhgOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggArioIDioIDioIDioIDioIDioIDioIBU
    Q1BDb2JyYeKggOKggOKgm+Kgi+KjieKjgOKggOKggOKggOKggOKggOKggCBhdXRob3I6IG1pbmQy
    aGV44qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
    gOKggOKggOKggOKguOKjv+Kjv+Kjt+KhgOKggOKggOKggOKggHZlcnNpb2464qCAMS4w4qCA4qCA
    CuKggOKggOKggOKggOKjgOKjoOKjpOKjtuKgtuKgtuKgn+Kgm+Kgm+Kgm+Kgi+KggeKggOKggOKg
    gOKjv+Kjv+Kjv+Kjp+KggOKjgOKhgOKggOKggOKggOKggArioIDioIDioIDioLDio7/io7/ioLfi
    oLbioLbioL/ioL/ioL/ioL/ioL/ioL/ioL/ioL/ioL/iooHio7/io7/io7/io7/ioIDioL/iopvi
    o7vioYbioIDioIAK4qCA4qCA4qKA4qOg4qOk4qOk4qOk4qO24qO24qO24qO24qO24qG24qC24qCW
    4qCS4qKA4qOk4qO+4qO/4qO/4qO/4qGf4qKA4qO+4qO/4qG/4qCD4qCA4qCACuKggOKggOKgmOKg
    v+Kjv+Kjv+Kjv+Kjt+KjtuKjtuKjtuKjtuKjtuKjtuKjtuKjv+Kjv+Kjv+Kjv+Khv+Kgv+Kgi+Kg
    gOKggOKggOKggOKggOKggOKggOKggArioIDioIDioIDioIDioIDioIDioInioInioInioInioIni
    oInioInioInioInioInioInioIHioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIAK
    """
    print(base64.b64decode(text_banner).decode())


def hexdump(src, length=16, show=True):
    """ 
    Prints hexdump of src with length chars width

    Parameters:
    src     (str or bytes): Source used to print hexdump to console
    length  (int): Specify length of hexdump 
    show    (bool): If True, then prints hexdump, else doesn't print hexdump but returns the hexdump

    Returns:
    If show == False returns
      list: Every line of the hexdump contained in a list
    """

    if isinstance(src, bytes):
        src = src.decode(errors="ignore")
    
    results = list()
    for i in range(0, len(src), length):
        # Saving chunk of data in word
        word = str(src[i:i+length])

        # Replacing non-printable characters with '.' using HEX_FILTER
        printable = word.translate(HEX_FILTER)

        # Converting each character into its hexadecimal represntation and separating with a space
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3

        # Appending a line of hexdump into results
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')

    if show:
        for line in results:
            print(line)
    else:
        return results


def receive_from(connection):
    """
    Receives data from connection to save it in buffer, then returns buffer

    Parameters:
    connection  (socket):

    Returns:
    response of the socket communication
    """

    buffer = b""
    connection.settimeout(1)  # Change if neccesary
    try:   
        while True:  # Reading data from response until theres no more data to read
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        # add exception handler later
        pass

    return buffer


def request_handler(buffer):
    """
    Modify request buffer before sending it

    Parameters:
    buffer  (str or bytes): buffer to modify 

    Returns:
    this function returns the modified buffer
    """

    # perform packet modifications
    #buffer = buffer.decode().replace("admin", "pene").encode()
    return buffer


def response_handler(buffer):
    """
    Modify response buffer before sending it

    Parameters:
    buffer  (str or bytes): buffer to modify 

    Returns:
    this function returns the modified buffer
    """
    # perform packet modifications
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    """
    This function handles the communication between client_socket and remote_socket.

    Parameters:
    client_socket (socket.socket)
    remote_host   (str): specify remote host address to create remote_socket
    remote_port   (int): specify remote host port to create remote_socket
    receive_first (bool): if True, then it reads before sending anything, else send first

    Returns:
    None
    """

    # creating remote socket to handle remote connection
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # receive first before sending data if specified
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    # reading remote host response to send to local host 
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost."% len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        # reading local host response to send to remote host
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            # if local_buffer stores received info from client_socket then proceeds to 
            # hexdump local_buffer and sends local_buffer to remote host                         
            print("[==>]Received %d bytes from localhost." % len(local_buffer))
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        # reading remote host response to send to local host 
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            # if remote_buffer stores received info from remote_socket then proceeds to
            # hexdump remote_buffer and sends remote_buffer to local host
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        # closing connections due to no response 
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    """
    Start a listener that binds to the socket (local_host, local_port) and waits for incoming connections.
    When a connection is made, it calls proxy_handler to handle communication between the client socket and remote host.

    Parameters:
    local_host    (str):  IP address or hostname to bind the client socket. E.g., '127.0.0.1'.
    local_port    (int):  Port number to bind the client socket. Should be in the range 1-65535.
    remote_host   (str):  IP address or hostname of the remote host to forward to.
    remote_port   (int):  Port number of the remote host. Should be in the range 1-65535.
    receive_first (bool): Determines if the remote host should be read from before sending data.

    Returns:
    None

    Raises:
    Exception: If there is a problem binding to the local host and port.

    Note:
    This function creates a new thread for each connection using the proxy_handler function, 
    allowing for handling multiple connections concurrently.
    """

    # creating server socket and binding to (local_host, local_port)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print("Problem on bind: %r " % e)
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    # start listening on server socket
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        print("> connection from %s:%d" % (addr[0], addr[1]))
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
        )
        proxy_thread.start()


def show_error(msg, location, suggestion=""):
    """
    Show a error message with location and a suggestion to avoid the error next time

    Parameters:
    msg        (str): Error message
    location   (str): Location where the error happened
    suggestion (str): A suggestion to avoid commiting the error next time

    Returns:
    None
    """
    print(f"\n\n[X] {msg}")
    print(f"[X] {location}")
    print(f"[X] {suggestion}")


def main():
    show_banner()
    if len(sys.argv[1:]) != 5:
        usage_text =  "Usage: ./proxy.py [localhost] [localport] "
        usage_text += "[remotehost] [remoteport] [receive_first] "
        usage_text += "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True "
        print(usage_text)
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port,
                remote_host, remote_port,
                receive_first
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        show_error(
            "User KeyboardInterrupt",
            f"Function::{currentframe().f_code.co_name}",
        )
        exit(0)


# TODO:
# - El Proxy es demasiado lento recibiendo y enviando informacion
# - Implementar argparse para los argumentos CLI