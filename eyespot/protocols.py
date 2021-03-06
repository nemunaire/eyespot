# Eyespot is a security testsuite for exposed services
# Copyright (C) 2015  nemunaire
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket
import ssl


def get():
    """Retrive a list of supported protocols by this Python version"""

    protos = []
    for p in ["PROTOCOL_SSLv2",
              "PROTOCOL_SSLv3",
              "PROTOCOL_TLSv1",
              "PROTOCOL_TLSv1_1",
              "PROTOCOL_TLSv1_2"]:
        if hasattr(ssl, p):
            protos.append(getattr(ssl, p))

    return protos


def test(host, protocol):
    """Test if a service's host against the given protocol

    Arguments:
    host -- tuple (hostname, port) to test
    protocol -- protocol to test
    """

    context = ssl.SSLContext(protocol)
    context.set_ciphers("ALL")

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
