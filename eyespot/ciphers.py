#!/usr/bin/env python3

import re
import socket
import ssl
import subprocess
import sys

_cipher_cache = dict()

def get(subset="ALL:COMPLEMENTOFALL"):
    """Ask OpenSSL a list of ciphers

    Keyword argument:
    subset -- an openssl cipher list format string
    """

    if subset in _cipher_cache:
        return _cipher_cache[subset]

    ciphers = []
    with subprocess.Popen(["openssl", "ciphers", subset],
                          stdout=subprocess.PIPE) as raw_ciphers:
        ciphers = re.findall(r"[^:]+",
                             raw_ciphers.stdout.read().strip().decode())

    _cipher_cache[subset] = ciphers
    return ciphers


def test(host, cipher):
    """Test a given host against given cipher

    Arguments:
    host -- tuple (hostname, port) to test
    cipher -- cipher to test
    """
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.set_ciphers(cipher)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        ssl_sock = context.wrap_socket(s)
        try:
            ssl_sock.connect(host)
            return True
        except ssl.SSLError:
            pass
        except ConnectionResetError:
            pass
    return False


def weakness_level(cipher):
    wl = [
        "aNULL:eNULL",
        "EXPORT",
        "LOW",
        "MEDIUM",
        "HIGH"
    ]
    for i in range(len(wl)):
        if cipher in get(wl[i]):
            return i + 1
    return 0
