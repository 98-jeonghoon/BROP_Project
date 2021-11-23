#! /usr/bin/python3

from pwn import *
from subprocess import *
import sys

WELL_KNOWN_PORT_BOUNDARY = 1023

ports = []

# process argument
argc = len(sys.argv)
if argc < 3:
    print('-s: server address')
    print('e.g: ./tool.py -s \'localhost\'')
    exit(1)

SERVER = sys.argv[2]

# execute "sudo namp -sS localhost" and get the result
p = Popen(["sudo", "nmap", "-sS", "localhost"], stdout=PIPE)
r = p.stdout.read()

# parsing nmap outpiut

start = r.decode().find('STATE SERVICE\n') + len('STATE_SERVICE')
r = r[start:]

while True:
    i1 = r.decode().find('\n')
    i2 = r.decode().find('/tcp')

    if i1 == -1 or i2 == -1:
        break
    port = int(r[i1+len('\n'):i2])
    if port > WELL_KNOWN_PORT_BOUNDARY:
        ports.append(port)

    r = r[i2 + len('/tcp'):]

print(ports)

# when need other routine espicially, pre_step function will process before go in routine
def pre_step(s):
    pass

def find_overflow(port):
    for i in range(1, 0x1000):
        s = connect(SERVER, port, level='error') # connect to server
        try:
            pre_step(s)
            # send 'a' repeatedly increasing 1 to find overflow point
            s.sendline('a'*i)
            d = s.recvuntil('\n', timeout=1)
            d = s.recv(timeout=0.5)
            # if we got a EOFError, that's a overflow point, print and close the connection
        except EOFError:
            log.info('overflow length: {}'.format(i-1))
            s.close()
            return i-1
        s.close()
    return 0

# find overflow in ports that found with nmap
for port in ports:
   s = connect(SERVER, port)
   data = s.recv()
   if data:
       s.close()
       over_len = find_overflow(port)
       if over_len:
           log.info('port {} is vulnerable for overflow ( especially brop attack )'.format(port))
   s.close()
