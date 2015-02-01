import socket
import ssl


def get(host):
    # TODO: need convertion
    return ssl.get_server_certificate(host)


def test(host):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_REQUIRED
    #context.check_hostname = True
    context.set_ciphers("ALL")
    #context.load_default_certs()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        ssl_sock = context.wrap_socket(s)
        try:
            ssl_sock.connect(host)
            return ssl_sock.getpeercert()
        except ssl.SSLError:
            pass
        except ConnectionResetError:
            pass
    return None
