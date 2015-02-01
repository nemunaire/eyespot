import sys

from eyespot import certs
from eyespot import ciphers
from eyespot import protocols

host = ('free.fr', 443)

for protocol in protocols.get():
    if protocols.test(host, protocol):
        print(protocol)

for cipher in ciphers.get():
    if ciphers.test(host, cipher):
        print(cipher)

print(certs.get(host))
